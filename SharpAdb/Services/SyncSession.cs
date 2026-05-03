using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace SharpAdb.Services;

/// <summary>
/// Wraps an open "sync:" stream to expose file-transfer operations (STAT/LIST/RECV/SEND).
/// One instance services many operations sequentially. Dispose to send QUIT and close the stream.
/// </summary>
public sealed class SyncSession : IAsyncDisposable
{
    private readonly AdbStream _stream;
    private readonly byte[] _frameBuf = new byte[SyncProtocol.FrameHeaderSize];
    private int _disposed;

    private SyncSession(AdbStream stream) => _stream = stream;

    /// <summary>
    /// Opens a new sync session over the given <paramref name="connection"/>.
    /// </summary>
    public static async Task<SyncSession> OpenAsync(AdbConnection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var stream = await connection.OpenAsync("sync:", cancellationToken).ConfigureAwait(false);
        return new SyncSession(stream);
    }

    /// <summary>
    /// Returns metadata for a remote path. Returns a zero-mode <see cref="AdbFileStat"/> if the file does not exist.
    /// </summary>
    public async Task<AdbFileStat> StatAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        await SendCommandAsync(SyncProtocol.Stat, remotePath, cancellationToken).ConfigureAwait(false);

        Span<byte> hdr = stackalloc byte[16];
        await ReadExactAsync(_frameBuf.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
        var tag = BinaryPrimitives.ReadUInt32LittleEndian(_frameBuf);
        if (tag != SyncProtocol.Stat)
            throw new IOException($"Expected STAT, got 0x{tag:X8}");

        var tmp = ArrayPool<byte>.Shared.Rent(12);
        try
        {
            await ReadExactAsync(tmp.AsMemory(0, 12), cancellationToken).ConfigureAwait(false);
            var mode = BinaryPrimitives.ReadUInt32LittleEndian(tmp);
            var size = BinaryPrimitives.ReadUInt32LittleEndian(tmp.AsSpan(4));
            var mTime = BinaryPrimitives.ReadUInt32LittleEndian(tmp.AsSpan(8));
            return new AdbFileStat(mode, size, DateTimeOffset.FromUnixTimeSeconds(mTime));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(tmp);
        }
    }

    /// <summary>
    /// Enumerates the entries of a remote directory.
    /// </summary>
    public async IAsyncEnumerable<AdbDirectoryEntry> ListAsync(string remotePath,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await SendCommandAsync(SyncProtocol.List, remotePath, cancellationToken).ConfigureAwait(false);

        var entryHdr = ArrayPool<byte>.Shared.Rent(16);
        try
        {
            while (true)
            {
                await ReadExactAsync(_frameBuf.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
                var tag = BinaryPrimitives.ReadUInt32LittleEndian(_frameBuf);
                if (tag == SyncProtocol.Done)
                {
                    // 16 bytes follow but are zero in the LIST terminator.
                    await ReadExactAsync(entryHdr.AsMemory(0, 16), cancellationToken).ConfigureAwait(false);
                    yield break;
                }

                if (tag != SyncProtocol.Dent)
                    throw new IOException($"Unexpected sync tag during LIST: 0x{tag:X8}");

                await ReadExactAsync(entryHdr.AsMemory(0, 16), cancellationToken).ConfigureAwait(false);
                var mode = BinaryPrimitives.ReadUInt32LittleEndian(entryHdr);
                var size = BinaryPrimitives.ReadUInt32LittleEndian(entryHdr.AsSpan(4));
                var mTime = BinaryPrimitives.ReadUInt32LittleEndian(entryHdr.AsSpan(8));
                var nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(entryHdr.AsSpan(12));

                var nameBuf = ArrayPool<byte>.Shared.Rent(nameLen);
                string name;
                try
                {
                    await ReadExactAsync(nameBuf.AsMemory(0, nameLen), cancellationToken).ConfigureAwait(false);
                    name = Encoding.UTF8.GetString(nameBuf, 0, nameLen);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(nameBuf);
                }

                yield return new AdbDirectoryEntry(name, mode, size, DateTimeOffset.FromUnixTimeSeconds(mTime));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(entryHdr);
        }
    }

    /// <summary>
    /// Pulls <paramref name="remotePath"/> from the device, writing its bytes to <paramref name="destination"/>.
    /// </summary>
    public async Task PullAsync(string remotePath, Stream destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        await SendCommandAsync(SyncProtocol.Recv, remotePath, cancellationToken).ConfigureAwait(false);

        var buf = ArrayPool<byte>.Shared.Rent(SyncProtocol.MaxDataChunk);
        try
        {
            while (true)
            {
                await ReadExactAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken).ConfigureAwait(false);
                var (tag, length) = SyncProtocol.ReadFrameHeader(_frameBuf);
                if (tag == SyncProtocol.Done)
                    return;

                if (tag == SyncProtocol.Fail)
                {
                    var msg = await ReadFailMessageAsync(length, cancellationToken).ConfigureAwait(false);
                    throw new IOException($"adbd refused PULL of '{remotePath}': {msg}");
                }

                if (tag != SyncProtocol.Data)
                    throw new IOException($"Unexpected sync tag during RECV: 0x{tag:X8}");

                if (length > SyncProtocol.MaxDataChunk)
                    throw new IOException($"Sync chunk exceeds {SyncProtocol.MaxDataChunk}: {length}");

                await ReadExactAsync(buf.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false);
                await destination.WriteAsync(buf.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>
    /// Pushes a stream to <paramref name="remotePath"/>. Mode is the POSIX file mode (e.g. 0o644 = 0x1A4).
    /// </summary>
    public async Task PushAsync(Stream source, string remotePath, uint mode = 0x1A4,
        DateTimeOffset? modifiedTime = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        // SEND path is "<path>,<mode>" as ASCII decimal mode.
        var sendPath = $"{remotePath},{mode}";
        await SendCommandAsync(SyncProtocol.Send, sendPath, cancellationToken).ConfigureAwait(false);

        var buf = ArrayPool<byte>.Shared.Rent(SyncProtocol.MaxDataChunk + SyncProtocol.FrameHeaderSize);
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buf.AsMemory(SyncProtocol.FrameHeaderSize, SyncProtocol.MaxDataChunk),
                    cancellationToken).ConfigureAwait(false);

                if (read == 0)
                    break;

                SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Data, (uint)read);
                await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize + read), cancellationToken).ConfigureAwait(false);
            }

            var mTime = (uint)(modifiedTime ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Done, mTime);
            await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken).ConfigureAwait(false);

            // Expect OKAY or FAIL.
            await ReadExactAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken).ConfigureAwait(false);
            var (tag, length) = SyncProtocol.ReadFrameHeader(_frameBuf);
            if (tag == SyncProtocol.Okay)
                return;

            if (tag == SyncProtocol.Fail)
            {
                var msg = await ReadFailMessageAsync(length, cancellationToken).ConfigureAwait(false);
                throw new IOException($"adbd refused PUSH to '{remotePath}': {msg}");
            }

            throw new IOException($"Unexpected sync tag after PUSH: 0x{tag:X8}");
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    private async Task<string> ReadFailMessageAsync(uint length, CancellationToken cancellationToken)
    {
        if (length == 0) return string.Empty;
        var buf = ArrayPool<byte>.Shared.Rent((int)length);
        try
        {
            await ReadExactAsync(buf.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(buf, 0, (int)length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private async ValueTask SendCommandAsync(uint tag, string path, CancellationToken cancellationToken)
    {
        var pathLen = Encoding.UTF8.GetByteCount(path);
        var buf = ArrayPool<byte>.Shared.Rent(SyncProtocol.FrameHeaderSize + pathLen);
        try
        {
            SyncProtocol.WriteFrameHeader(buf, tag, (uint)pathLen);
            Encoding.UTF8.GetBytes(path, buf.AsSpan(SyncProtocol.FrameHeaderSize));
            await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize + pathLen), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private async ValueTask ReadExactAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var read = await _stream.ReadAsync(destination[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException("ADB sync stream ended early");

            total += read;
        }
    }

    /// <summary>
    /// Sends QUIT and closes the underlying stream.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        try
        {
            SyncProtocol.WriteFrameHeader(_frameBuf, SyncProtocol.Quit, 0);
            await _stream.WriteAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize)).ConfigureAwait(false);
        }
        catch
        {
            // Don't throw in dispose
        }
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}
