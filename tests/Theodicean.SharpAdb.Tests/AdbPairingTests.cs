using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Pairing;

namespace Theodicean.SharpAdb.Tests;

public class AdbPairingTests
{
    private const string PairingCode = "123456";

    [Test]
    [Arguments("")]
    [Arguments("12345")]
    [Arguments("1234567")]
    [Arguments("12345a")]
    [Arguments("1234 6")]
    [Arguments(" 123456")]
    public async Task PairAsyncRejectsInvalidPairingCode(string invalidCode)
    {
        using var key = AdbAuthKey.Generate();
        // ReSharper disable once AccessToDisposedClosure
        await Assert.That(async () => await AdbPairing.PairAsync("127.0.0.1", 12345, invalidCode, key))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task PairAsyncRejectsKeyWithOversizedUserHost()
    {
        // PeerInfo has a fixed 8191-byte data budget; a userHost this long pushes the encoded
        // public key line past it. Validation happens before any socket connect, so an
        // unreachable host:port is fine here — it should never get that far.
        var hugeUserHost = new string('a', 9000);
        using var key = AdbAuthKey.Generate(hugeUserHost);

        // ReSharper disable once AccessToDisposedClosure
        await Assert.That(async () => await AdbPairing.PairAsync("127.0.0.1", 1, PairingCode, key))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task PairAsyncCancellationUnblocksAStuckHandshake()
    {
        // BC-TLS's Connect() is a blocking call with no async/cancelable variant, so this proves
        // the fix that actually makes cancellationToken do anything: it registers a callback that
        // disposes the socket, which is the only thing that can unstick a blocked synchronous
        // read. Without that fix, this test would hang until the WaitAsync timeout below expires
        // and throws TimeoutException instead of OperationCanceledException — a regression here
        // fails loudly rather than hanging the suite.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        // Accept the connection but never speak TLS back — simulates a hung peer.
        var acceptTask = listener.AcceptSocketAsync();

        using var key = AdbAuthKey.Generate();
        using var cts = new CancellationTokenSource();
        var pairTask = AdbPairing.PairAsync("127.0.0.1", port, PairingCode, key, cts.Token);

        cts.CancelAfter(TimeSpan.FromMilliseconds(200));

        // ReSharper disable once AccessToDisposedClosure
        await Assert.That(async () => await pairTask.WaitAsync(TimeSpan.FromSeconds(5), cts.Token))
            .Throws<OperationCanceledException>();

        using var acceptedSocket = await acceptTask;
    }

    [Test]
    public async Task PairAsyncCompletesFullHandshakeAgainstFakeDevice()
    {
        // End-to-end loopback exercise of the whole pairing stack (TLS 1.3 mutual auth via
        // BouncyCastle, RFC 5705 exporter, SPAKE2, AES-128-GCM PeerInfo exchange) against a
        // hand-rolled stand-in for adbd's pairing service, since there's no real device available
        // here. This can't verify bit-compatibility with BoringSSL's exporter output, but it does
        // verify the BC-TLS wiring actually works and the full protocol round-trips correctly.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var deviceKey = AdbAuthKey.Generate("device@host");
        using var deviceCertificate = deviceKey.CreateSelfSignedCertificate("CN=fakedevice");
        var deviceCertificateDer = deviceCertificate.Export(X509ContentType.Cert);
        var devicePrivateKey = AdbPairingTlsClient.ToBouncyCastleKey(deviceKey.Rsa.ExportParameters(includePrivateParameters: true));

        var serverTask = Task.Run(async () =>
        {
            // ReSharper disable AccessToDisposedClosure
            using var serverSocket = await listener.AcceptSocketAsync();
            await using var rawStream = new NetworkStream(serverSocket, ownsSocket: true);

            var server = new FakePairingTlsServer(devicePrivateKey, deviceCertificateDer);
            var protocol = new Org.BouncyCastle.Tls.TlsServerProtocol(rawStream);
            await Task.Run(() => protocol.Accept(server));

            var exportedKeyMaterial = server.ExportedKeyingMaterial;
            var password = new byte[6 + exportedKeyMaterial.Length];
            "123456"u8.ToArray().CopyTo(password, 0);
            exportedKeyMaterial.CopyTo(password, 6);

            var spake2 = new Spake2Handshake(Spake2Role.Server, password);
            var tlsStream = protocol.Stream;

            var (clientSpakeType, clientSpakeMsg) = await AdbPairing.ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, CancellationToken.None);
            await Assert.That(clientSpakeType).IsEqualTo(PairingPacketType.Spake2Msg);

            var keyMaterial = spake2.ProcessPeerMessage(clientSpakeMsg);
            await Assert.That(keyMaterial).IsNotNull();
            var cipher = new PairingCipher(keyMaterial!);

            await AdbPairing.WritePacketAsync(tlsStream, PairingPacketType.Spake2Msg, spake2.Message, CancellationToken.None);

            var (clientPeerInfoType, encryptedClientPeerInfo) = await AdbPairing.ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, CancellationToken.None);
            await Assert.That(clientPeerInfoType).IsEqualTo(PairingPacketType.PeerInfo);

            var decryptedClientPeerInfo = cipher.Decrypt(encryptedClientPeerInfo);
            await Assert.That(decryptedClientPeerInfo).IsNotNull();
            var (clientPeerInfoKind, clientPeerInfoData) = PeerInfo.Decode(decryptedClientPeerInfo!);
            await Assert.That(clientPeerInfoKind).IsEqualTo(PeerInfoType.AdbRsaPublicKey);

            var devicePeerInfo = PeerInfo.Encode(PeerInfoType.AdbRsaPublicKey, deviceKey.EncodeAndroidPublicKey());
            await AdbPairing.WritePacketAsync(tlsStream, PairingPacketType.PeerInfo, cipher.Encrypt(devicePeerInfo), CancellationToken.None);

            return clientPeerInfoData;
            // ReSharper restore AccessToDisposedClosure
        });

        using var hostKey = AdbAuthKey.Generate("host@client");
        var pairTask = AdbPairing.PairAsync("127.0.0.1", port, PairingCode, hostKey);

        await Task.WhenAll(pairTask, serverTask).WaitAsync(TimeSpan.FromSeconds(5));

        var result = await pairTask;
        await Assert.That(result.PeerInfoType).IsEqualTo(PeerInfoType.AdbRsaPublicKey);

        var clientSideDecodedPeerInfo = await serverTask;
        // Trailing NUL terminator is trimmed by PeerInfo.Decode along with padding; see PeerInfoRoundTripsAndTrimsPadding.
        await Assert.That(clientSideDecodedPeerInfo).IsEquivalentTo(hostKey.EncodeAndroidPublicKey()[..^1]);
    }

    [Test]
    public async Task PairAsyncThrowsOnPairingCodeMismatch()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var deviceKey = AdbAuthKey.Generate("device@host");
        using var deviceCertificate = deviceKey.CreateSelfSignedCertificate("CN=fakedevice");
        var deviceCertificateDer = deviceCertificate.Export(X509ContentType.Cert);
        var devicePrivateKey = AdbPairingTlsClient.ToBouncyCastleKey(deviceKey.Rsa.ExportParameters(includePrivateParameters: true));

        var serverTask = Task.Run(async () =>
        {
            // ReSharper disable AccessToDisposedClosure
            using var serverSocket = await listener.AcceptSocketAsync();
            await using var rawStream = new NetworkStream(serverSocket, ownsSocket: true);

            var server = new FakePairingTlsServer(devicePrivateKey, deviceCertificateDer);
            var protocol = new Org.BouncyCastle.Tls.TlsServerProtocol(rawStream);
            await Task.Run(() => protocol.Accept(server));

            var exportedKeyMaterial = server.ExportedKeyingMaterial;
            // Deliberately use a different code than the client, so the derived SPAKE2 password
            // differs and PeerInfo decryption fails on both sides.
            var password = new byte[6 + exportedKeyMaterial.Length];
            "654321"u8.ToArray().CopyTo(password, 0);
            exportedKeyMaterial.CopyTo(password, 6);

            var spake2 = new Spake2Handshake(Spake2Role.Server, password);
            var tlsStream = protocol.Stream;

            var (_, clientSpakeMsg) = await AdbPairing.ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, CancellationToken.None);
            var keyMaterial = spake2.ProcessPeerMessage(clientSpakeMsg)!;
            var cipher = new PairingCipher(keyMaterial);
            await AdbPairing.WritePacketAsync(tlsStream, PairingPacketType.Spake2Msg, spake2.Message, CancellationToken.None);

            var (_, encryptedClientPeerInfo) = await AdbPairing.ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, CancellationToken.None);
            // Never actually decryptable by the client with a mismatched cipher — attempt anyway
            // so the server side doesn't hang; ignore the (failed) result.
            cipher.Decrypt(encryptedClientPeerInfo);

            var devicePeerInfo = PeerInfo.Encode(PeerInfoType.AdbRsaPublicKey, deviceKey.EncodeAndroidPublicKey());
            var encrypted = cipher.Encrypt(devicePeerInfo);
            await AdbPairing.WritePacketAsync(tlsStream, PairingPacketType.PeerInfo, encrypted, CancellationToken.None);
            // ReSharper restore AccessToDisposedClosure
        });

        using var hostKey = AdbAuthKey.Generate("host@client");
        // ReSharper disable once AccessToDisposedClosure
        await Assert.That(async () => await AdbPairing.PairAsync("127.0.0.1", port, PairingCode, hostKey))
            .Throws<AdbPairingException>();

        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
    }
}
