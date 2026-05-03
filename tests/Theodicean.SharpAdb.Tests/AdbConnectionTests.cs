using System.Security.Cryptography;
using System.Text;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Services;
using Theodicean.SharpAdb.Transport;

using Xunit;

namespace Theodicean.SharpAdb.Tests;

public class AdbConnectionTests
{
    [Fact]
    public async Task HandshakeWithoutAuthSucceeds()
    {
        var (clientStream, deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        // Fake device side: receive CNXN, reply CNXN.
        var deviceTask = Task.Run(async () =>
        {
            using var pkt = await deviceTransport.ReadPacketAsync();
            Assert.Equal(AdbCommand.Cnxn, pkt.Header.Command);

            var banner = "device::ro.product.name=test;ro.product.model=Pixel\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0),
                banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        Assert.Equal("device", conn.DeviceInfo.SystemType);
        Assert.Equal("test", conn.DeviceInfo.Product);
        Assert.Equal("Pixel", conn.DeviceInfo.Model);
    }

    [Fact]
    public async Task HandshakeWithAuthChallengeAndSignature()
    {
        var (clientStream, deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);
        using var key = AdbAuthKey.Generate();

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                Assert.Equal(AdbCommand.Cnxn, pkt.Header.Command);

            var token = RandomNumberGenerator.GetBytes(AdbProtocolConstants.AuthTokenSize);
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.Token, 0, (uint)token.Length, 0), token);

            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                Assert.Equal(AdbCommand.Auth, pkt.Header.Command);
                Assert.Equal((uint)AdbAuthType.Signature, pkt.Header.Arg0);

                using var pub = RSA.Create();
                pub.ImportFromPem(key.ExportPrivateKeyPem());
                Assert.True(pub.VerifyHash(token, pkt.PayloadSpan.ToArray(),
                    HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
            }

            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0),
                banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [key], new AdbConnectOptions());
        await deviceTask;
    }

    [Fact]
    public async Task OpenStreamRoundTripsData()
    {
        var (clientStream, deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                Assert.Equal(AdbCommand.Cnxn, pkt.Header.Command);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0), banner);

            // Expect OPEN.
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                Assert.Equal(AdbCommand.Open, pkt.Header.Command);
                Assert.Equal("shell:echo hi\0", Encoding.UTF8.GetString(pkt.PayloadSpan));
                clientLocalId = pkt.Header.Arg0;
            }

            const uint deviceLocalId = 9999;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            var payload = "hi\n"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)payload.Length, 0), payload);

            // Expect OKAY ack.
            using (var ack = await deviceTransport.ReadPacketAsync())
            {
                Assert.Equal(AdbCommand.Okay, ack.Header.Command);
                Assert.Equal(clientLocalId, ack.Header.Arg0);
                Assert.Equal(deviceLocalId, ack.Header.Arg1);
            }

            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Clse, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        var output = await conn.ExecuteAsync("echo hi");
        await deviceTask;
        Assert.Equal("hi\n", output);
    }

    [Fact]
    public async Task ReadLoopFaultPropagatesToOpenStreams()
    {
        var (clientStream, deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        // Bring connection up.
        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                Assert.Equal(AdbCommand.Cnxn, pkt.Header.Command);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0), banner);

            // Accept the OPEN, then send a malformed packet to fault the read loop.
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
                clientLocalId = pkt.Header.Arg0;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, 1234, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Send a packet whose DataLength exceeds MaxPayload — transport should throw InvalidDataException.
            var hdr = new byte[AdbProtocolConstants.HeaderSize];
            new AdbHeader(AdbCommand.Wrte, 1234, clientLocalId, AdbProtocolConstants.MaxPayload + 1, 0).WriteTo(hdr);
            await deviceStream.WriteAsync(hdr);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var stream = await conn.OpenAsync("shell:cat");
        await deviceTask;

        // Pending read on the stream should observe the fault (or 0/EOF) once the loop dies.
        var buf = new byte[1024];
        var ex = await Record.ExceptionAsync(async () =>
        {
            var read = await stream.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(2));
            // If we got here, a graceful close happened — accept 0 too.
            Assert.Equal(0, read);
        });

        // Either a fault propagated (exception from pipe) or graceful EOF (0 bytes). Both acceptable.
        Assert.True(ex is null or InvalidDataException or IOException, $"unexpected: {ex}");

        // Subsequent OpenAsync must surface the recorded fault.
        Assert.NotNull(conn.FaultException);
        await Assert.ThrowsAsync<IOException>(async () => await conn.OpenAsync("shell:noop"));
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }
}
