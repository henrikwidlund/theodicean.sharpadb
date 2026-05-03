using SharpAdb.Protocol;
using SharpAdb.Transport;

using Xunit;

namespace SharpAdb.Tests;

public class StreamAdbTransportTests
{
    [Fact]
    public async Task RoundTripsHeaderOnlyPacket()
    {
        var (a, b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);

        var header = new AdbHeader(AdbCommand.Okay, 1, 2, 0, 0);
        await sender.WritePacketAsync(header, ReadOnlyMemory<byte>.Empty);

        using var received = await receiver.ReadPacketAsync();
        Assert.Equal(AdbCommand.Okay, received.Header.Command);
        Assert.Equal(1u, received.Header.Arg0);
        Assert.Equal(2u, received.Header.Arg1);
        Assert.True(received.PayloadSpan.IsEmpty);
    }

    [Fact]
    public async Task RoundTripsPacketWithPayload()
    {
        var (a, b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);

        byte[] payload = [.. Enumerable.Range(0, 5000).Select(static i => (byte)(i & 0xFF))];
        var header = new AdbHeader(AdbCommand.Wrte, 11, 22, (uint)payload.Length,
            AdbHeader.ComputeChecksum(payload));
        await sender.WritePacketAsync(header, payload);

        using var received = await receiver.ReadPacketAsync();
        Assert.Equal(AdbCommand.Wrte, received.Header.Command);
        Assert.Equal(11u, received.Header.Arg0);
        Assert.Equal(22u, received.Header.Arg1);
        Assert.Equal(payload.Length, received.PayloadSpan.Length);
        Assert.True(payload.AsSpan().SequenceEqual(received.PayloadSpan));
    }

    [Fact]
    public async Task ChecksumMismatchThrowsWhenVerifyEnabled()
    {
        var (a, b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b, verifyChecksum: true);

        byte[] payload = [1, 2, 3, 4];
        // Wrong checksum.
        var header = new AdbHeader(AdbCommand.Wrte, 0, 0, 4, 0xDEADBEEF);
        await sender.WritePacketAsync(header, payload);

        await Assert.ThrowsAsync<InvalidDataException>(async () => await receiver.ReadPacketAsync());
    }

    [Fact]
    public async Task ReadEofThrows()
    {
        var (a, b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);
        // ReSharper disable once DisposeOnUsingVariable
        await sender.DisposeAsync();

        await Assert.ThrowsAsync<EndOfStreamException>(async () => await receiver.ReadPacketAsync());
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }
}

internal sealed class DuplexStream(Stream readSide, Stream writeSide) : Stream
{
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => writeSide.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => writeSide.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => readSide.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        readSide.ReadAsync(buffer, cancellationToken);
    public override void Write(byte[] buffer, int offset, int count) => writeSide.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        writeSide.WriteAsync(buffer, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            writeSide.Dispose();
            readSide.Dispose();
        }
        base.Dispose(disposing);
    }
}

internal sealed class BlockingMemoryStream : Stream
{
    private readonly Lock _gate = new();
    private readonly Queue<byte[]> _chunks = new();
    private int _offset;
    private bool _writerClosed;

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            lock (_gate)
            {
                if (_chunks.Count > 0)
                {
                    var head = _chunks.Peek();
                    var remaining = head.Length - _offset;
                    var toCopy = Math.Min(remaining, buffer.Length);
                    head.AsSpan(_offset, toCopy).CopyTo(buffer.Span);
                    _offset += toCopy;
                    if (_offset == head.Length)
                    {
                        _chunks.Dequeue();
                        _offset = 0;
                    }
                    return toCopy;
                }
                if (_writerClosed) return 0;
            }
            await Task.Delay(2, cancellationToken).ConfigureAwait(false);
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        lock (_gate)
            _chunks.Enqueue(buffer.AsSpan(offset, count).ToArray());
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        lock (_gate)
            _chunks.Enqueue(buffer.ToArray());
        return ValueTask.CompletedTask;
    }

    protected override void Dispose(bool disposing)
    {
        lock (_gate)
            _writerClosed = true;
        base.Dispose(disposing);
    }
}