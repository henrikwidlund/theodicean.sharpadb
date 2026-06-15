using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class StreamAdbTransportTests
{
    [Test]
    public async Task RoundTripsHeaderOnlyPacket()
    {
        (Stream a, Stream b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);

        var header = new AdbHeader(AdbCommand.Okay, 1, 2, 0, 0);
        await sender.WritePacketAsync(header, ReadOnlyMemory<byte>.Empty);

        using var received = await receiver.ReadPacketAsync();
        await Assert.That(received.Header.Command).IsEqualTo(AdbCommand.Okay);
        await Assert.That(received.Header.Arg0).IsEqualTo(1u);
        await Assert.That(received.Header.Arg1).IsEqualTo(2u);
        await Assert.That(received.PayloadSpan.IsEmpty).IsTrue();
    }

    [Test]
    public async Task RoundTripsPacketWithPayload()
    {
        (Stream a, Stream b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);

        byte[] payload = [.. Enumerable.Range(0, 5000).Select(static i => (byte)(i & 0xFF))];
        var header = new AdbHeader(AdbCommand.Wrte, 11, 22, (uint)payload.Length,
            AdbHeader.ComputeChecksum(payload));
        await sender.WritePacketAsync(header, payload);

        using var received = await receiver.ReadPacketAsync();
        await Assert.That(received.Header.Command).IsEqualTo(AdbCommand.Wrte);
        await Assert.That(received.Header.Arg0).IsEqualTo(11u);
        await Assert.That(received.Header.Arg1).IsEqualTo(22u);
        await Assert.That(received.PayloadSpan.Length).IsEqualTo(payload.Length);
        await Assert.That(payload.AsSpan().SequenceEqual(received.PayloadSpan)).IsTrue();
    }

    [Test]
    public async Task ChecksumMismatchThrowsWhenVerifyEnabled()
    {
        (Stream a, Stream b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b, verifyChecksum: true);

        byte[] payload = [1, 2, 3, 4];
        // Wrong checksum.
        var header = new AdbHeader(AdbCommand.Wrte, 0, 0, 4, 0xDEADBEEF);
        await sender.WritePacketAsync(header, payload);

        await Assert.That(async () => await receiver.ReadPacketAsync()).ThrowsExactly<InvalidDataException>();
    }

    [Test]
    public async Task ReadEofThrows()
    {
        (Stream a, Stream b) = CreateDuplexPair();
        await using var sender = new StreamAdbTransport(a);
        await using var receiver = new StreamAdbTransport(b);
        // ReSharper disable once DisposeOnUsingVariable
        await sender.DisposeAsync();

        await Assert.That(async () => await receiver.ReadPacketAsync()).ThrowsExactly<EndOfStreamException>();
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
            await Task.Delay(2, cancellationToken);
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
