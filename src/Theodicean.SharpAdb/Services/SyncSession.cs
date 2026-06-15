using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Wraps an open "sync:" stream to expose file-transfer operations over the sendrecv_v2
/// sub-protocol. One instance services many operations sequentially. Dispose to send QUIT
/// and close the stream.
/// </summary>
public sealed class SyncSession : IAsyncDisposable
{
    private readonly AdbStream _stream;
    private readonly byte[] _frameBuf = new byte[SyncProtocol.FrameHeaderSize];
    private int _disposed;

    private SyncSession(AdbStream stream) => _stream = stream;

    /// <summary>
    /// Opens a new sync session over the given <paramref name="connection"/>. Requires the
    /// device to advertise the <c>sendrecv_v2</c> feature (Android 9+).
    /// </summary>
    /// <exception cref="NotSupportedException">The connected device does not advertise <c>sendrecv_v2</c>.</exception>
    public static async Task<SyncSession> OpenAsync(AdbConnection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);

        if (!connection.DeviceInfo.Features.Contains(SyncProtocol.FeatureFlag))
            throw new NotSupportedException(
                $"Device does not support the '{SyncProtocol.FeatureFlag}' sync sub-protocol (requires Android 9+).");

        var stream = await connection.OpenAsync("sync:", cancellationToken);
        return new SyncSession(stream);
    }

    /// <summary>
    /// Returns metadata for a remote path using <c>LST2</c> (lstat semantics — symlinks are
    /// reported as symlinks rather than dereferenced). Returns a zero-mode
    /// <see cref="AdbFileStat"/> if the file does not exist.
    /// </summary>
    public async Task<AdbFileStat> StatAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        await SendCommandAsync(SyncProtocol.LStatV2, remotePath, cancellationToken);

        // LST2 reply: tag(4) + 68-byte fixed payload.
        const int replySize = 4 + SyncProtocol.StatV2PayloadSize;
        var tmp = ArrayPool<byte>.Shared.Rent(replySize);
        try
        {
            await ReadExactAsync(tmp.AsMemory(0, replySize), cancellationToken);
            var tag = BinaryPrimitives.ReadUInt32LittleEndian(tmp);
            return tag != SyncProtocol.LStatV2
                ? throw new IOException($"Expected LST2, got 0x{tag:X8}")
                : ParseStatV2(tmp.AsSpan(4, SyncProtocol.StatV2PayloadSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(tmp);
        }
    }

    /// <summary>
    /// Enumerates the entries of a remote directory using <c>LIS2</c>. The caller must drain
    /// the enumeration (or cancel before <see cref="StatAsync"/>/<see cref="PullAsync"/>/<see cref="PushAsync"/>
    /// runs); abandoning iteration mid-stream leaves unread DNT2/DONE frames on the wire that
    /// the next operation on this session would misinterpret.
    /// </summary>
    public async IAsyncEnumerable<AdbDirectoryEntry> ListAsync(string remotePath,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await SendCommandAsync(SyncProtocol.ListV2, remotePath, cancellationToken);

        // Each DNT2 entry: tag(4) + 68 bytes stat + 4 bytes namelen + name. DONE terminator
        // is a full 76-byte sync_dent_v2 struct with id=DONE.
        const int dentFixedSize = SyncProtocol.StatV2PayloadSize + 4;
        var entryHdr = ArrayPool<byte>.Shared.Rent(dentFixedSize);
        try
        {
            while (true)
            {
                await ReadExactAsync(_frameBuf.AsMemory(0, 4), cancellationToken);
                var tag = BinaryPrimitives.ReadUInt32LittleEndian(_frameBuf);

                if (tag == SyncProtocol.Done)
                {
                    await ReadExactAsync(entryHdr.AsMemory(0, dentFixedSize), cancellationToken);
                    yield break;
                }

                if (tag != SyncProtocol.DentV2)
                    throw new IOException($"Unexpected sync tag during LIS2: 0x{tag:X8}");

                await ReadExactAsync(entryHdr.AsMemory(0, dentFixedSize), cancellationToken);
                var stat = ParseStatV2(entryHdr.AsSpan(0, SyncProtocol.StatV2PayloadSize));
                var nameLenU = BinaryPrimitives.ReadUInt32LittleEndian(
                    entryHdr.AsSpan(SyncProtocol.StatV2PayloadSize, 4));

                // Cast uint→int can wrap negative; the wire field is uint32 but ArrayPool
                // and Encoding.UTF8.GetString both take int counts.
                if (nameLenU > int.MaxValue)
                    throw new IOException($"DNT2 entry namelen exceeds int.MaxValue: {nameLenU}");

                var nameLen = (int)nameLenU;
                string name;
                if (nameLen == 0)
                {
                    name = string.Empty;
                }
                else
                {
                    var nameBuf = ArrayPool<byte>.Shared.Rent(nameLen);
                    try
                    {
                        await ReadExactAsync(nameBuf.AsMemory(0, nameLen), cancellationToken);
                        name = Encoding.UTF8.GetString(nameBuf, 0, nameLen);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(nameBuf);
                    }
                }

                yield return new AdbDirectoryEntry(
                    name,
                    stat.Mode,
                    stat.Size,
                    stat.ModifiedTime,
                    stat.AccessedTime,
                    stat.ChangedTime,
                    stat.Uid,
                    stat.Gid,
                    stat.Nlink,
                    stat.Inode,
                    stat.Device,
                    stat.Error);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(entryHdr);
        }
    }

    /// <summary>
    /// Pulls <paramref name="remotePath"/> from the device using <c>RCV2</c>, writing its
    /// bytes to <paramref name="destination"/>. Compression is not negotiated. Cancelling
    /// mid-transfer leaves unread DATA/DONE frames on the wire; do not reuse this session
    /// after cancellation, dispose it instead.
    /// </summary>
    public async Task PullAsync(string remotePath, Stream destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);

        await SendCommandAsync(SyncProtocol.RecvV2, remotePath, cancellationToken);
        await SendRecvV2MetadataAsync(cancellationToken);

        var buf = ArrayPool<byte>.Shared.Rent(SyncProtocol.MaxDataChunk);
        try
        {
            while (true)
            {
                await ReadExactAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken);
                var (tag, length) = SyncProtocol.ReadFrameHeader(_frameBuf);
                if (tag == SyncProtocol.Done)
                    return;

                if (tag == SyncProtocol.Fail)
                {
                    var msg = await ReadFailMessageAsync(length, cancellationToken);
                    throw new IOException($"adbd refused PULL of '{remotePath}': {msg}");
                }

                if (tag != SyncProtocol.Data)
                    throw new IOException($"Unexpected sync tag during RCV2: 0x{tag:X8}");

                if (length > SyncProtocol.MaxDataChunk)
                    throw new IOException($"Sync chunk exceeds {SyncProtocol.MaxDataChunk}: {length}");

                await ReadExactAsync(buf.AsMemory(0, (int)length), cancellationToken);
                await destination.WriteAsync(buf.AsMemory(0, (int)length), cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>
    /// Pushes a stream to <paramref name="remotePath"/> using <c>SND2</c>. Mode is the POSIX
    /// file mode (e.g. 0o644 = 0x1A4). Compression is not negotiated.
    /// </summary>
    public async Task PushAsync(Stream source, string remotePath, uint mode = 0x1A4,
        DateTimeOffset? modifiedTime = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        await SendCommandAsync(SyncProtocol.SendV2, remotePath, cancellationToken);
        await SendSendV2MetadataAsync(mode, cancellationToken);

        var buf = ArrayPool<byte>.Shared.Rent(SyncProtocol.MaxDataChunk + SyncProtocol.FrameHeaderSize);
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buf.AsMemory(SyncProtocol.FrameHeaderSize, SyncProtocol.MaxDataChunk), cancellationToken);

                if (read == 0)
                    break;

                SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Data, (uint)read);
                await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize + read), cancellationToken);
            }

            var mTime = (uint)(modifiedTime ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Done, mTime);
            await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken);

            await ReadExactAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize), cancellationToken);
            (uint tag, uint length) = SyncProtocol.ReadFrameHeader(_frameBuf);
            if (tag == SyncProtocol.Okay)
                return;

            if (tag == SyncProtocol.Fail)
            {
                var msg = await ReadFailMessageAsync(length, cancellationToken);
                throw new IOException($"adbd refused PUSH to '{remotePath}': {msg}");
            }

            throw new IOException($"Unexpected sync tag after PUSH: 0x{tag:X8}");
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    /// <summary>
    /// Parses the fixed 68-byte sync_stat_v2 payload (everything after the 4-byte tag).
    /// </summary>
    private static AdbFileStat ParseStatV2(ReadOnlySpan<byte> payload)
    {
        var error = BinaryPrimitives.ReadUInt32LittleEndian(payload);
        var dev = BinaryPrimitives.ReadUInt64LittleEndian(payload[4..]);
        var ino = BinaryPrimitives.ReadUInt64LittleEndian(payload[12..]);
        var mode = BinaryPrimitives.ReadUInt32LittleEndian(payload[20..]);
        var nlink = BinaryPrimitives.ReadUInt32LittleEndian(payload[24..]);
        var uid = BinaryPrimitives.ReadUInt32LittleEndian(payload[28..]);
        var gid = BinaryPrimitives.ReadUInt32LittleEndian(payload[32..]);
        var size = BinaryPrimitives.ReadUInt64LittleEndian(payload[36..]);
        var atime = BinaryPrimitives.ReadInt64LittleEndian(payload[44..]);
        var mtime = BinaryPrimitives.ReadInt64LittleEndian(payload[52..]);
        var ctime = BinaryPrimitives.ReadInt64LittleEndian(payload[60..]);

        return new AdbFileStat(
            mode,
            size,
            DateTimeOffset.FromUnixTimeSeconds(mtime),
            DateTimeOffset.FromUnixTimeSeconds(atime),
            DateTimeOffset.FromUnixTimeSeconds(ctime),
            uid,
            gid,
            nlink,
            ino,
            dev,
            error);
    }

    private async Task<string> ReadFailMessageAsync(uint length, CancellationToken cancellationToken)
    {
        if (length == 0) return string.Empty;
        var buf = ArrayPool<byte>.Shared.Rent((int)length);
        try
        {
            await ReadExactAsync(buf.AsMemory(0, (int)length), cancellationToken);
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
            await _stream.WriteAsync(buf.AsMemory(0, SyncProtocol.FrameHeaderSize + pathLen), cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // sync_send_v2 { uint32 id = SND2; uint32 mode; uint32 flags; } — 12 bytes.
    // Compression flag is wired as 0 (uncompressed); adbd accepts a no-compression sender.
    private async ValueTask SendSendV2MetadataAsync(uint mode, CancellationToken cancellationToken)
    {
        var buf = ArrayPool<byte>.Shared.Rent(12);
        try
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buf, SyncProtocol.SendV2);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), mode);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8), 0u);
            await _stream.WriteAsync(buf.AsMemory(0, 12), cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // sync_recv_v2 { uint32 id = RCV2; uint32 flags; } — 8 bytes.
    // Compression flag is wired as 0 (uncompressed).
    private async ValueTask SendRecvV2MetadataAsync(CancellationToken cancellationToken)
    {
        var buf = ArrayPool<byte>.Shared.Rent(8);
        try
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buf, SyncProtocol.RecvV2);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), 0u);
            await _stream.WriteAsync(buf.AsMemory(0, 8), cancellationToken);
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
            var read = await _stream.ReadAsync(destination[total..], cancellationToken);
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
            await _stream.WriteAsync(_frameBuf.AsMemory(0, SyncProtocol.FrameHeaderSize));
        }
        catch
        {
            // Don't throw in dispose
        }
        await _stream.DisposeAsync();
    }
}
