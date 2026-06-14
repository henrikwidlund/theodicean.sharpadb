using System.Buffers;
using System.Globalization;
using System.IO.Pipelines;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// A live shell_v2 session over a single <see cref="AdbStream"/>. Exposes separate
/// <see cref="Stdout"/> / <see cref="Stderr"/> readers plus <see cref="ExitCodeTask"/> which
/// completes when the device sends the EXIT packet. Use this for interactive shells or any
/// case where you need to inspect stdout / stderr separately or read the command's exit code.
/// </summary>
public sealed class ShellSession : IAsyncDisposable
{
    private readonly AdbStream _stream;
    private readonly Pipe _stdout = new(new PipeOptions(useSynchronizationContext: false));
    private readonly Pipe _stderr = new(new PipeOptions(useSynchronizationContext: false));
    private readonly TaskCompletionSource<int> _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _readLoop;
    private int _disposed;

    /// <summary>
    /// Standard output stream from the remote command.
    /// </summary>
    public Stream Stdout => _stdout.Reader.AsStream();

    /// <summary>
    /// Standard error stream from the remote command.
    /// </summary>
    public Stream Stderr => _stderr.Reader.AsStream();

    /// <summary>
    /// Completes with the exit code from the device's shell_v2 EXIT packet. Faults with
    /// <see cref="IOException"/> if the stream closes before an EXIT is received.
    /// </summary>
    public Task<int> ExitCodeTask => _exit.Task;

    internal ShellSession(AdbStream stream)
    {
        _stream = stream;
        _readLoop = Task.Run(ReadLoopAsync);
    }

    /// <summary>
    /// Sends bytes to the remote command's stdin.
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public async ValueTask WriteStdinAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (data.IsEmpty) return;
        var buf = ArrayPool<byte>.Shared.Rent(ShellV2Protocol.HeaderSize + data.Length);
        try
        {
            ShellV2Protocol.WriteHeader(buf, ShellPacketId.Stdin, (uint)data.Length);
            data.Span.CopyTo(buf.AsSpan(ShellV2Protocol.HeaderSize));
            await _stream.WriteAsync(buf.AsMemory(0, ShellV2Protocol.HeaderSize + data.Length), cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>
    /// Signals end-of-input to the remote command (equivalent to closing stdin).
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public async ValueTask CloseStdinAsync(CancellationToken cancellationToken = default)
    {
        var buf = new byte[ShellV2Protocol.HeaderSize];
        ShellV2Protocol.WriteHeader(buf, ShellPacketId.CloseStdin, 0);
        await _stream.WriteAsync(buf, cancellationToken);
    }

    private async Task ReadLoopAsync()
    {
        var headerBuf = new byte[ShellV2Protocol.HeaderSize];
        Exception? fault = null;
        try
        {
            var done = false;
            while (!done)
            {
                var read = await ReadExactOrEofAsync(headerBuf);
                if (read == 0)
                {
                    // Remote closed the stream without sending EXIT — surface that to callers.
                    _exit.TrySetException(new IOException(
                        "shell_v2 stream closed without an EXIT packet"));
                    break;
                }
                if (read < ShellV2Protocol.HeaderSize)
                {
                    // Stream ended in the middle of a header. Parsing the partial buffer would
                    // produce a garbage length that subsequent ReadExactly would hang on.
                    _exit.TrySetException(new IOException(
                        string.Create(CultureInfo.InvariantCulture, $"shell_v2 stream closed mid-header (read {read} of {ShellV2Protocol.HeaderSize} bytes)")));
                    break;
                }

                (ShellPacketId id, uint length) = ShellV2Protocol.ReadHeader(headerBuf);

                // Reject frame lengths that would overflow when cast to int (used by
                // ReadExactlyAsync / ArrayPool.Rent below). Real shell_v2 payloads are tiny
                // by protocol convention; anything past int.MaxValue is malformed.
                if (length > int.MaxValue)
                    throw new IOException(
                        $"shell_v2 frame length {length} exceeds the supported maximum ({int.MaxValue})");

                switch (id)
                {
                    case ShellPacketId.Stdout:
                        await CopyPayloadToPipeAsync(_stdout.Writer, (int)length);
                        break;
                    case ShellPacketId.Stderr:
                        await CopyPayloadToPipeAsync(_stderr.Writer, (int)length);
                        break;
                    case ShellPacketId.Exit:
                        {
                            // EXIT payload is a single byte exit code per the shell protocol.
                            // Don't let a misbehaving / hostile peer steer a single big Rent
                            // via the device-controlled length — read the byte we need into a
                            // 1-byte buffer and discard any extras through the chunked
                            // DiscardAsync helper.
                            if (length == 0)
                            {
                                _exit.TrySetException(new IOException("shell_v2 EXIT packet had zero-length payload"));
                            }
                            else
                            {
                                var exitBuf = ArrayPool<byte>.Shared.Rent(1);
                                try
                                {
                                    await _stream.ReadExactlyAsync(exitBuf.AsMemory(0, 1));
                                    if (length > 1)
                                        await DiscardAsync((int)(length - 1));
                                    _exit.TrySetResult(exitBuf[0]);
                                }
                                finally
                                {
                                    ArrayPool<byte>.Shared.Return(exitBuf);
                                }
                            }
                            done = true;
                            break;
                        }
                    default:
                        // Unknown/unexpected packet from the device (stdin/CloseStdin/WindowSize
                        // are client→device only). Drain the payload so we don't desync framing.
                        await DiscardAsync((int)length);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            fault = ex;
            _exit.TrySetException(ex);
        }
        finally
        {
            // Always complete both pipe writers on exit so any pending Stdout/Stderr reader
            // (e.g. a CopyToAsync inside ExecuteV2Async) gets unblocked. A fault on the read
            // loop propagates to readers via Complete(fault); the success path completes with
            // a graceful EOF.
            await _stdout.Writer.CompleteAsync(fault);
            await _stderr.Writer.CompleteAsync(fault);
        }
    }

    private async ValueTask<int> ReadExactOrEofAsync(Memory<byte> destination)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var n = await _stream.ReadAsync(destination[total..]);
            if (n == 0)
                return total; // EOF (returns 0 if no bytes received at all)
            total += n;
        }
        return total;
    }

    // Maximum buffer we will rent in one shot when streaming a shell_v2 frame's payload.
    // The wire-level `length` field is device-controlled (32-bit), so a malformed or hostile
    // peer could request a huge allocation if we passed it straight to ArrayPool.Rent. Reading
    // in bounded chunks preserves framing correctness without giving the peer that lever.
    private const int PayloadChunkSize = 64 * 1024;

    private async ValueTask CopyPayloadToPipeAsync(PipeWriter writer, int length)
    {
        if (length == 0) return;
        var remaining = length;
        while (remaining > 0)
        {
            var chunk = Math.Min(remaining, PayloadChunkSize);
            var buf = ArrayPool<byte>.Shared.Rent(chunk);
            try
            {
                await _stream.ReadExactlyAsync(buf.AsMemory(0, chunk));
                await writer.WriteAsync(buf.AsMemory(0, chunk));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
            remaining -= chunk;
        }
    }

    private async ValueTask DiscardAsync(int length)
    {
        if (length == 0) return;
        var remaining = length;
        var buf = ArrayPool<byte>.Shared.Rent(Math.Min(remaining, PayloadChunkSize));
        try
        {
            while (remaining > 0)
            {
                var chunk = Math.Min(remaining, buf.Length);
                await _stream.ReadExactlyAsync(buf.AsMemory(0, chunk));
                remaining -= chunk;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>
    /// Closes the underlying ADB stream and tears down the shell_v2 demuxer.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await _stream.DisposeAsync();
        try
        {
            await _readLoop;
        }
        catch
        {
            // Read loop surfaces faults via ExitCodeTask / pipe completion — don't double-throw.
        }
        _exit.TrySetException(new IOException("shell_v2 session disposed before EXIT packet"));
    }
}
