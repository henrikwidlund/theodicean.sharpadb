using System.Buffers;
using System.IO.Pipelines;

using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb;

/// <summary>
/// Multiplexed bidirectional byte stream over an <see cref="AdbConnection"/>. Created by
/// <see cref="AdbConnection.OpenAsync"/>. ADB requires every WRTE be ACKed by the peer before
/// the next WRTE may be sent — this class enforces that with an internal ack semaphore.
/// </summary>
public sealed class AdbStream : Stream
{
    private readonly AdbConnection _connection;

    /// <summary>
    /// The local identifier we assigned to this stream when sending OPEN.
    /// </summary>
    public uint LocalId { get; }

    /// <summary>
    /// The peer-assigned identifier returned in the OKAY response. Zero until the stream is opened.
    /// </summary>
    public uint RemoteId { get; private set; }

    private readonly Pipe _inboundPipe = new(new PipeOptions(useSynchronizationContext: false));
    private readonly SemaphoreSlim _writeAck = new(0, 1);
    private readonly TaskCompletionSource<bool> _opened = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _closed;
    private int _resourcesDisposed;
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

    internal async ValueTask OnDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closed) != 0) return;
        await _inboundPipe.Writer.WriteAsync(data, cancellationToken);
    }

    internal void OnAck() => TryReleaseWriteAck();

    internal void OnClosed()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _connection.Logger.StreamClosed(LocalId, RemoteId);
        _inboundPipe.Writer.Complete();
        _opened.TrySetResult(false);
        TryReleaseWriteAck();
    }

    internal void OnFaulted(Exception fault)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _connection.Logger.StreamFaulted(LocalId, RemoteId, fault);
        Volatile.Write(ref _fault, fault);
        _inboundPipe.Writer.Complete(fault);
        _opened.TrySetException(fault);
        TryReleaseWriteAck();
    }

    private void TryReleaseWriteAck()
    {
        try
        {
            _writeAck.Release();
        }
        catch (SemaphoreFullException)
        {
            // Ignore
        }
    }

    private IOException StreamClosedException() =>
        Volatile.Read(ref _fault) is { } f
            ? new IOException($"ADB stream faulted: {f.Message}", f)
            : new IOException("ADB stream closed");

    /// <inheritdoc/>
    public override bool CanRead => true;

    /// <inheritdoc/>
    public override bool CanWrite => true;

    /// <inheritdoc/>
    public override bool CanSeek => false;

    /// <inheritdoc/>
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc/>
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    /// <inheritdoc/>
    public override void Flush() { }

    /// <inheritdoc/>
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc/>
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>
    /// Synchronous wrapper around <see cref="ReadAsync(Memory{byte}, CancellationToken)"/>.
    /// </summary>
    /// <remarks>
    /// Implemented as sync-over-async. The inbound pipe is constructed with
    /// <c>useSynchronizationContext: false</c> so this does not deadlock on a captured
    /// synchronization context, but it does block a thread-pool thread for the duration of
    /// the read. Prefer the async overload from any async or hot-path code.
    /// </remarks>
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// Reads up to <paramref name="buffer"/>.Length bytes from the device-side service. Returns 0 on graceful close.
    /// </summary>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _inboundPipe.Reader.ReadAsync(cancellationToken);
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

    /// <summary>
    /// Synchronous wrapper around <see cref="WriteAsync(ReadOnlyMemory{byte}, CancellationToken)"/>.
    /// </summary>
    /// <remarks>
    /// Implemented as sync-over-async. Waits for the per-packet WRTE/OKAY ack required by the
    /// ADB protocol, blocking the calling thread for the full round trip. Prefer the async
    /// overload from any async or hot-path code.
    /// </remarks>
    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// Writes the buffer to the device-side service, splitting into <see cref="AdbConnection.MaxPayload"/>-sized
    /// WRTE packets and waiting for the per-packet OKAY ack required by the protocol.
    /// </summary>
    /// <exception cref="IOException">Stream was closed (graceful) or faulted (e.g. transport error).</exception>
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

            await _writeAck.WaitAsync(cancellationToken);
            if (Volatile.Read(ref _closed) != 0)
                throw StreamClosedException();

            var checksum = _connection.WriteChecksum ? AdbHeader.ComputeChecksum(slice.Span) : 0u;
            var header = new AdbHeader(AdbCommand.Wrte, LocalId, RemoteId, (uint)slice.Length, checksum);
            await _connection.SendAsync(header, slice, cancellationToken);

            remaining = remaining[chunk..];
        }
    }

    /// <summary>
    /// Synchronous dispose; fires CLSE in the background. Prefer <see cref="DisposeAsync"/> for deterministic cleanup.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (Interlocked.Exchange(ref _closed, 1) == 0)
            {
                _ = _connection.CloseStreamAsync(this);
                _inboundPipe.Writer.Complete();
            }
            DisposeResources();
        }
        base.Dispose(disposing);
    }

    /// <summary>
    /// Sends CLSE to the device and completes the inbound pipe.
    /// </summary>
    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 0)
        {
            await _connection.CloseStreamAsync(this);
            await _inboundPipe.Writer.CompleteAsync();
        }
        DisposeResources();
        await base.DisposeAsync();
    }

    private void DisposeResources()
    {
        // OnClosed/OnFaulted may have flipped _closed without ever owning the SemaphoreSlim;
        // _resourcesDisposed guarantees we only dispose once even if both Dispose paths run.
        if (Interlocked.Exchange(ref _resourcesDisposed, 1) == 0)
            _writeAck.Dispose();
    }
}
