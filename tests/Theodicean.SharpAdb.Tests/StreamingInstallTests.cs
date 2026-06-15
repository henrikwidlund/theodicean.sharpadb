using System.Text;

using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Services;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class StreamingInstallTests
{
    [Test]
    public async Task InstallAsyncStreamsApkThroughShellV2()
    {
        // Verifies the service string is `cmd package install -S <size> -` and that the APK
        // bytes arrive on stdin as shell_v2 Stdin packets, in order.
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var apkBytes = Enumerable.Range(0, 200_000).Select(static i => (byte)i).ToArray();

        var observedService = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var observedStdin = new MemoryStream();

        var deviceTask = Task.Run(async () =>
        {
            try
            {
                using (var pkt = await deviceTransport.ReadPacketAsync())
                    await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

                var banner = "device::features=shell_v2\0"u8.ToArray();
                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                        (uint)banner.Length, 0), banner);

                // Expect OPEN with the streaming-install service string.
                uint clientLocalId;
                using (var pkt = await deviceTransport.ReadPacketAsync())
                {
                    await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                    observedService.SetResult(Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0'));
                    clientLocalId = pkt.Header.Arg0;
                }

                const uint deviceLocalId = 5555;
                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

                // Receive WRTEs until we see a CloseStdin packet, accumulating stdin payload.
                var sawCloseStdin = false;
                while (!sawCloseStdin)
                {
                    using var pkt = await deviceTransport.ReadPacketAsync();
                    if (pkt.Header.Command != AdbCommand.Wrte)
                        continue;

                    // Each WRTE payload is one or more shell_v2 frames. Parse them and route
                    // Stdin bytes into observedStdin.
                    var span = pkt.PayloadSpan;
                    while (!span.IsEmpty)
                    {
                        var id = (ShellPacketId)span[0];
                        var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(span[1..]);
                        span = span[5..];
                        if (id == ShellPacketId.Stdin)
                            observedStdin.Write(span[..length]);
                        else if (id == ShellPacketId.CloseStdin)
                            sawCloseStdin = true;
                        span = span[length..];
                    }

                    // Acknowledge the WRTE so the client can keep streaming.
                    await deviceTransport.WritePacketAsync(
                        new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
                }

                // Send shell_v2 Stdout "Success" + EXIT 0.
                var successBytes = "Success\n"u8.ToArray();
                var replyPayload = new byte[
                    ShellV2Protocol.HeaderSize + successBytes.Length +
                    ShellV2Protocol.HeaderSize + 1];
                ShellV2Protocol.WriteHeader(replyPayload, ShellPacketId.Stdout, (uint)successBytes.Length);
                successBytes.CopyTo(replyPayload, ShellV2Protocol.HeaderSize);
                var exitOffset = ShellV2Protocol.HeaderSize + successBytes.Length;
                ShellV2Protocol.WriteHeader(replyPayload.AsSpan(exitOffset), ShellPacketId.Exit, 1);
                replyPayload[exitOffset + ShellV2Protocol.HeaderSize] = 0; // exit code

                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)replyPayload.Length, 0), replyPayload);

                using (var ack = await deviceTransport.ReadPacketAsync())
                    await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);

                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Clse, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
            }
            catch (Exception ex)
            {
                observedService.TrySetException(ex);
                throw;
            }
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        using var apkStream = new MemoryStream(apkBytes);
        var result = await conn.InstallAsync(apkStream);
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        // OpenShellAsync wraps the command with shell,v2,raw: prefix.
        await Assert.That(await observedService.Task).IsEqualTo($"shell,v2,raw:cmd package install -r -S {apkBytes.Length} -");
        await Assert.That(observedStdin.ToArray()).IsEquivalentTo(apkBytes);
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.FailureReason).IsNull();
        await Assert.That(result.Raw.ExitCode).IsEqualTo(0);
    }

    [Test]
    public async Task InstallAsyncRejectsStreamWithNoBytesRemaining()
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
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        // Position seeked to (or past) end → 0 (or negative) bytes remaining. Without the
        // guard this would advertise a non-positive -S size to cmd package install.
        using var empty = new MemoryStream(new byte[10]);
        empty.Seek(0, SeekOrigin.End);
        await Assert.That(async () => await conn.InstallAsync(empty))
            .ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task InstallAsyncRejectsWriteOnlyStream()
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
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        // Seekable but write-only — would later blow up inside ReadAsync with a less helpful
        // error if we hadn't guarded it up front.
        await using var writeOnly = new WriteOnlySeekableStream();
        await Assert.That(async () => await conn.InstallAsync(writeOnly))
            .ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task InstallAsyncRejectsNonSeekableStream()
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
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        // Pretend to have a non-seekable stream.
        await using var notSeekable = new NonSeekableStream();
        await Assert.That(async () => await conn.InstallAsync(notSeekable))
            .ThrowsExactly<ArgumentException>();
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }

    private sealed class NonSeekableStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class WriteOnlySeekableStream : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => true;
        public override bool CanWrite => true;
        public override long Length => 0;
        public override long Position { get; set; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => 0;
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
    }
}
