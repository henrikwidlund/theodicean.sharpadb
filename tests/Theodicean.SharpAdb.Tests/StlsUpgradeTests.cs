using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class StlsUpgradeTests
{
    [Test]
    public async Task ConnectNegotiatesStlsAndContinuesEncrypted()
    {
        // Real-loopback TCP because SslStream needs a bidirectional stream that supports proper
        // half-close + flushing semantics. The in-memory pair used by other tests doesn't.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await listener.AcceptSocketAsync();
            await using var rawStream = new NetworkStream(serverSocket, ownsSocket: true);
            var deviceTransport = new StreamAdbTransport(rawStream, ownsStream: false);

            // Expect CNXN.
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            // Send STLS.
            await deviceTransport.WritePacketAsync(new AdbHeader(AdbCommand.Stls, 1, 0, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Expect STLS reply.
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Stls);

            // Server-side TLS handshake.
            using var serverKey = AdbAuthKey.Generate("device@host");
            using var serverCert = serverKey.CreateSelfSignedCertificate("CN=adbd");

            var ssl = new SslStream(rawStream, leaveInnerStreamOpen: false);

            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCert,
                ClientCertificateRequired = true,
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12
            });

            await using var encryptedTransport = new StreamAdbTransport(ssl, ownsStream: true);

            // Send CNXN inside TLS.
            var banner = "device::ro.product.name=tlsdev\0"u8.ToArray();
            await encryptedTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0),
                banner);

            // Hold open until client closes.
            try
            {
                await encryptedTransport.ReadPacketAsync();
            }
            catch
            {
                // Ignore
            }
        });

        using var clientKey = AdbAuthKey.Generate("client@host");
        var conn = await AdbConnection.ConnectTcpAsync("127.0.0.1", port, [clientKey]);
        await Assert.That(conn.DeviceInfo.Product).IsEqualTo("tlsdev");
        await conn.DisposeAsync();

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Test]
    public async Task UpgradeToTlsRejectsPendingBytesAfterStls()
    {
        // Regression: STLS must be the last ADB frame before TLS ClientHello. A misbehaving peer
        // that queues extra bytes after STLS would otherwise have those bytes fed into SslStream
        // as bogus TLS records, surfacing as opaque handshake failures. UpgradeToTlsAsync must
        // fast-fail with InvalidDataException *before* starting the TLS handshake.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var serverDone = new CancellationTokenSource();
        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await listener.AcceptSocketAsync(serverDone.Token);
            await using var rawStream = new NetworkStream(serverSocket, ownsSocket: true);
            var deviceTransport = new StreamAdbTransport(rawStream, ownsStream: false);

            using (var pkt = await deviceTransport.ReadPacketAsync(serverDone.Token))
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            // STLS frame + 4 KiB of garbage immediately afterwards. The kernel will deliver both
            // chunks well before the client gets to UpgradeToTlsAsync, so Socket.Available is
            // guaranteed to report the garbage as pending.
            var stlsHeader = new byte[AdbProtocolConstants.HeaderSize];
            new AdbHeader(AdbCommand.Stls, 1, 0, 0, 0).WriteTo(stlsHeader);
            await rawStream.WriteAsync(stlsHeader, serverDone.Token);
            await rawStream.WriteAsync(new byte[4096], serverDone.Token);
            await rawStream.FlushAsync(serverDone.Token);

            // Hold the connection open until the test signals completion so we don't race the
            // client's read of Socket.Available against the server closing the connection.
            try
            {
                await Task.Delay(Timeout.Infinite, serverDone.Token);
            }
            catch (OperationCanceledException)
            {
                // Expected: test body completed and signaled serverDone.
            }
        }, serverDone.Token);

        using var clientKey = AdbAuthKey.Generate("client@host");
        try
        {
            await Assert.That(async () => await AdbConnection.ConnectTcpAsync("127.0.0.1", port, [clientKey]))
                .ThrowsExactly<InvalidDataException>();
        }
        finally
        {
            await serverDone.CancelAsync();
            // Let timeouts and any server-side assertion failures surface — only the expected
            // post-cancellation completion goes through cleanly here.
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5), serverDone.Token);
        }
    }

    [Test]
    public async Task GeneratedCertificateContainsPublicKey()
    {
        using var key = AdbAuthKey.Generate();
        using var cert = key.CreateSelfSignedCertificate("CN=test");
        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.GetRSAPublicKey()).IsNotNull();
        await Assert.That(cert.GetRSAPublicKey()!.KeySize).IsEqualTo(AdbAuthKey.KeySizeBits);
    }
}
