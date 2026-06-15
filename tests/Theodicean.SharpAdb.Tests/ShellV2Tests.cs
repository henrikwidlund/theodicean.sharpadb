using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Services;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class ShellV2Tests
{
    [Test]
    public async Task ShellV2ProtocolHeaderRoundTrip()
    {
        Span<byte> buf = stackalloc byte[ShellV2Protocol.HeaderSize];
        ShellV2Protocol.WriteHeader(buf, ShellPacketId.Stdout, 0x12345678);
        (ShellPacketId id, uint length) = ShellV2Protocol.ReadHeader(buf);
        await Assert.That(id).IsEqualTo(ShellPacketId.Stdout);
        await Assert.That(length).IsEqualTo(0x12345678u);
    }

    [Test]
    public async Task ExecuteV2RoutesStdoutStderrAndExitCode()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            // Handshake with shell_v2 feature advertised.
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var banner = "device::features=shell_v2\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            // Expect OPEN shell,v2,raw:echo hi
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                var service = Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0');
                await Assert.That(service).IsEqualTo("shell,v2,raw:echo hi");
                clientLocalId = pkt.Header.Arg0;
            }

            const uint deviceLocalId = 42;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Single WRTE carrying stdout + stderr + exit packets back-to-back inside one frame.
            var stdoutBytes = "hi\n"u8;
            var stderrBytes = "err\n"u8;
            var payload = new byte[
                ShellV2Protocol.HeaderSize + stdoutBytes.Length +
                ShellV2Protocol.HeaderSize + stderrBytes.Length +
                ShellV2Protocol.HeaderSize + 1];
            var span = payload.AsSpan();
            ShellV2Protocol.WriteHeader(span, ShellPacketId.Stdout, (uint)stdoutBytes.Length);
            stdoutBytes.CopyTo(span[ShellV2Protocol.HeaderSize..]);
            span = span[(ShellV2Protocol.HeaderSize + stdoutBytes.Length)..];
            ShellV2Protocol.WriteHeader(span, ShellPacketId.Stderr, (uint)stderrBytes.Length);
            stderrBytes.CopyTo(span[ShellV2Protocol.HeaderSize..]);
            span = span[(ShellV2Protocol.HeaderSize + stderrBytes.Length)..];
            ShellV2Protocol.WriteHeader(span, ShellPacketId.Exit, 1);
            span[ShellV2Protocol.HeaderSize] = 7; // exit code

            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)payload.Length, 0), payload);

            // Read OKAY ack.
            using (var ack = await deviceTransport.ReadPacketAsync())
                await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);

            // CLSE the stream so the client side can wind down.
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Clse, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        var result = await conn.ExecuteAsync("echo hi");
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(5));

        await Assert.That(result.Stdout).IsEqualTo("hi\n");
        await Assert.That(result.Stderr).IsEqualTo("err\n");
        await Assert.That(result.ExitCode).IsEqualTo(7);
    }

    [Test]
    public async Task ExecuteV2ThrowsWhenDeviceLacksShellV2Feature()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            // Note: no shell_v2 in features.
            var banner = "device::features=cmd\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        await Assert.That(async () => await conn.ExecuteAsync("ls"))
            .ThrowsExactly<NotSupportedException>();
    }

    [Test]
    public async Task ShellSessionExitTaskFaultsIfStreamClosesWithoutExitPacket()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var banner = "device::features=shell_v2\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
                clientLocalId = pkt.Header.Arg0;

            const uint deviceLocalId = 99;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Close immediately — no stdout, no exit code.
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Clse, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var session = await conn.OpenShellAsync("noop");
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(5));

        await Assert.That(async () => await session.ExitCodeTask.WaitAsync(TimeSpan.FromSeconds(2)))
            .ThrowsExactly<IOException>();
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }
}
