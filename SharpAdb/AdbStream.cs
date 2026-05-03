using System.Buffers;
using System.IO.Pipelines;
using SharpAdb.Protocol;

namespace SharpAdb;

/// <summary>
/// Multiplexed bidirectional byte stream over an <see cref="AdbConnection"/>. Created by
/// <see cref="AdbConnection.OpenAsync"/>. ADB requires every WRTE be ACKed by the peer before
/// the next WRTE may be sent — this class enforces that with an internal ack semaphore.
/// </summary>
public sealed class AdbStream : Stream
{
    private readonly AdbConnection _connection;
    public uint LocalId { get; }
    public uint RemoteId { get; private set; }

    private readonly Pipe _inboundPipe = new(new PipeOptions(useSynchronizationContext: false));
    private readonly SemaphoreSlim _writeAck = new(0, 1);
    private readonly TaskCompletionSource<bool> _opened = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _closed;
    private Exception? _fault;

    internal AdbStream(AdbConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
    }

    internal Task<bool> OpenedTask => _opened.Task;

    internal void OnOpened(uint remoteId)
    {
        RemoteId = remoteId;
        _opened.TrySetResult(true);
        _writeAck.Release(); // ready for first write
    }

    internal void OnOpenRejected()
    {
        _opened.TrySetResult(false);
        _inboundPipe.Writer.Complete();
        Interlocked.Exchange(ref _closed, 1);
    }

    internal async ValueTask OnDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closed) != 0) return;
        await _inboundPipe.Writer.WriteAsync(data, cancellationToken).ConfigureAwait(false);
    }

    internal void OnAck()
    {
        if (_writeAck.CurrentCount == 0)
            _writeAck.Release();
    }

    internal void OnClosed()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _inboundPipe.Writer.Complete();
        _opened.TrySetResult(false);
        if (_writeAck.CurrentCount == 0) _writeAck.Release();
    }

    internal void OnFaulted(Exception fault)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        Volatile.Write(ref _fault, fault);
        _inboundPipe.Writer.Complete(fault);
        _opened.TrySetException(fault);
        if (_writeAck.CurrentCount == 0) _writeAck.Release();
    }

    private IOException StreamClosedException() =>
        Volatile.Read(ref _fault) is { } f
            ? new IOException($"ADB stream faulted: {f.Message}", f)
            : new IOException("ADB stream closed");

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _inboundPipe.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        var seq = result.Buffer;
        if (seq.IsEmpty)
        {
            _inboundPipe.Reader.AdvanceTo(seq.End);
            return 0;
        }

        var toCopy = (int)Math.Min(seq.Length, buffer.Length);
        seq.Slice(0, toCopy).CopyTo(buffer.Span);
        _inboundPipe.Reader.AdvanceTo(seq.GetPosition(toCopy));
        return toCopy;
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var remaining = buffer;
        var max = (int)_connection.MaxPayload;
        while (!remaining.IsEmpty)
        {
            if (Volatile.Read(ref _closed) != 0)
                throw StreamClosedException();

            var chunk = Math.Min(remaining.Length, max);
            var slice = remaining[..chunk];

            await _writeAck.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (Volatile.Read(ref _closed) != 0)
                throw StreamClosedException();

            var checksum = _connection.WriteChecksum ? AdbHeader.ComputeChecksum(slice.Span) : 0u;
            var header = new AdbHeader(AdbCommand.Wrte, LocalId, RemoteId, (uint)slice.Length, checksum);
            await _connection.SendAsync(header, slice, cancellationToken).ConfigureAwait(false);

            remaining = remaining[chunk..];
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _closed, 1) == 0)
        {
            _ = _connection.CloseStreamAsync(this);
            _inboundPipe.Writer.Complete();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 0)
        {
            await _connection.CloseStreamAsync(this).ConfigureAwait(false);
            await _inboundPipe.Writer.CompleteAsync().ConfigureAwait(false);
        }
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
