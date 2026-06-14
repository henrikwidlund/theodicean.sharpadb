using System.Buffers;
using System.IO.Pipelines;
using System.Threading.Channels;

using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb;

/// <summary>
/// Multiplexed bidirectional byte stream over an <see cref="AdbConnection"/>. Created by
/// <see cref="AdbConnection.OpenAsync"/>. ADB requires every WRTE be ACKed by the peer before
/// the next WRTE may be sent — this class enforces that with an internal ack semaphore.
/// </summary>
/// <remarks>
/// Inbound WRTE packets are handed off to a per-stream drain task and acknowledged only after
/// the bytes have been placed in this stream's read buffer. That preserves per-stream
/// backpressure (a slow consumer throttles the device for *its* stream) without ever blocking
/// the connection-wide demuxer, so a slow reader on one stream cannot deadlock writers on any
/// other stream.
/// </remarks>
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
    private readonly Channel<InboundChunk> _inboundChannel = Channel.CreateBounded<InboundChunk>(
        new BoundedChannelOptions(1) { SingleReader = true, SingleWriter = true });
    private readonly SemaphoreSlim _writeAck = new(0, 1);
    private readonly TaskCompletionSource<bool> _opened = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _drainCts = new();
    private readonly Task _drainTask;
    private int _closed;
    private int _resourcesDisposed;
    private Exception? _fault;

    internal AdbStream(AdbConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
        _drainTask = Task.Run(DrainLoopAsync, _drainCts.Token);
    }

    internal Task<bool> OpenedTask => _opened.Task;

    internal void OnOpened(uint remoteId)
    {
        RemoteId = remoteId;
        _opened.TrySetResult(true);
        // Ready for first write. Routed through TryReleaseWriteAck so that a racing user-side
        // Dispose() that already tore down the SemaphoreSlim doesn't fault the read loop.
        TryReleaseWriteAck();
    }

    /// <summary>
    /// Hands off an inbound WRTE payload to this stream's drain task. Takes ownership of
    /// <paramref name="buffer"/> (must be a pooled buffer of at least <paramref name="length"/>
    /// bytes); the drain task returns it to the pool once the bytes have been copied into the
    /// reader's pipe. The demuxer never blocks here — if the channel rejects the chunk (channel
    /// capacity 1, meaning the device sent a second WRTE before we acknowledged the first) the
    /// stream is faulted but the connection-wide read loop keeps running for other streams.
    /// </summary>
    internal void EnqueueInboundWrite(byte[] buffer, int length)
    {
        if (Volatile.Read(ref _closed) != 0)
        {
            ArrayPool<byte>.Shared.Return(buffer);
            return;
        }

        if (!_inboundChannel.Writer.TryWrite(new InboundChunk(buffer, length)))
        {
            ArrayPool<byte>.Shared.Return(buffer);
            OnFaulted(new IOException(
                $"ADB device sent a WRTE on stream {LocalId} before acknowledging the previous one"));
        }
    }

    internal void OnAck() => TryReleaseWriteAck();

    internal void OnClosed()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _connection.Logger.StreamClosed(LocalId, RemoteId);
        _inboundChannel.Writer.TryComplete();
        // Wake the drain task if it is parked inside Pipe.Writer.WriteAsync waiting for a
        // consumer that will never read — otherwise DisposeAsync's await on the drain task
        // would hang forever.
        _drainCts.Cancel();
        _opened.TrySetResult(false);
        TryReleaseWriteAck();
    }

    internal void OnFaulted(Exception fault)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _connection.Logger.StreamFaulted(LocalId, RemoteId, fault);
        Volatile.Write(ref _fault, fault);
        _inboundChannel.Writer.TryComplete(fault);
        _inboundPipe.Writer.Complete(fault);
        _drainCts.Cancel();
        _opened.TrySetException(fault);
        TryReleaseWriteAck();
    }

    private async Task DrainLoopAsync()
    {
        var token = _drainCts.Token;
        try
        {
            await foreach ((byte[] buffer, int length) in _inboundChannel.Reader.ReadAllAsync(token))
            {
                try
                {
                    if (Volatile.Read(ref _closed) != 0)
                        return;

                    await _inboundPipe.Writer.WriteAsync(buffer.AsMemory(0, length), token);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }

                if (Volatile.Read(ref _closed) != 0)
                    return;

                // OKAY-on-consume: only acknowledge after the consumer's pipe has the bytes,
                // so a slow reader naturally throttles the device for this stream alone.
                try
                {
                    await _connection.SendOkayAsync(this);
                }
                catch (Exception ex)
                {
                    if (Volatile.Read(ref _closed) == 0)
                        OnFaulted(ex);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Stream closed/faulted while we were blocked on Pipe.WriteAsync or the channel.
        }
        catch (Exception ex)
        {
            if (Volatile.Read(ref _closed) == 0)
                OnFaulted(ex);
        }
        finally
        {
            // Complete() is idempotent: if OnFaulted already completed the writer with a fault
            // exception this call is a no-op.
            _inboundPipe.Writer.Complete();
        }
    }

    private void TryReleaseWriteAck()
    {
        try
        {
            _writeAck.Release();
        }
        catch (SemaphoreFullException)
        {
            // Already signaled — fine, the next WriteAsync will pass through immediately.
        }
        catch (ObjectDisposedException)
        {
            // The user-side Dispose path may have torn down the SemaphoreSlim while a packet
            // for this stream was still in flight on the read loop. Swallowing here keeps the
            // demuxer alive for every other stream; the disposing stream will not write again.
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
            try
            {
                if (Volatile.Read(ref _closed) != 0)
                    throw StreamClosedException();

                var checksum = _connection.WriteChecksum ? AdbHeader.ComputeChecksum(slice.Span) : 0u;
                var header = new AdbHeader(AdbCommand.Wrte, LocalId, RemoteId, (uint)slice.Length, checksum);
                await _connection.SendAsync(header, slice, cancellationToken);
            }
            catch
            {
                // Restore the slot we consumed. If the WRTE actually went out, the eventual OKAY
                // will land on a full semaphore and TryReleaseWriteAck swallows the resulting
                // SemaphoreFullException. If the WRTE never went out, this lets the next
                // legitimate write (or close) proceed instead of hanging forever on WaitAsync.
                TryReleaseWriteAck();
                throw;
            }

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
                _inboundChannel.Writer.TryComplete();
                _drainCts.Cancel();
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
            _inboundChannel.Writer.TryComplete();
            // Cancel any in-flight Pipe.WriteAsync inside the drain task so awaiting it below
            // can't block on a consumer that will never read.
            await _drainCts.CancelAsync();
            try
            {
                await _drainTask;
            }
            catch
            {
                // Drain task surfaces faults via OnFaulted; don't double-throw from dispose.
            }
        }
        DisposeResources();
        await base.DisposeAsync();
    }

    private void DisposeResources()
    {
        // OnClosed/OnFaulted may have flipped _closed without ever owning the SemaphoreSlim;
        // _resourcesDisposed guarantees we only dispose once even if both Dispose paths run.
        if (Interlocked.Exchange(ref _resourcesDisposed, 1) == 0)
        {
            _writeAck.Dispose();
            _drainCts.Dispose();
        }
    }

    private readonly record struct InboundChunk(byte[] Buffer, int Length);
}
