using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// 4-byte ASCII tags for the ADB sync subprotocol v2 ("sync:" service, sendrecv_v2 feature,
/// Android 9+). Carries 64-bit sizes, full POSIX stat fields, and second-resolution timestamps.
/// </summary>
internal static class SyncProtocol
{
    // CNXN feature flag required for the v2 sync sub-protocol.
    public const string FeatureFlag = "sendrecv_v2";

    // Common tags carried over from v1 (still used in v2 framing).
    public const uint Data = 0x41544144; // "DATA"
    public const uint Done = 0x454e4f44; // "DONE"
    public const uint Okay = 0x59414b4f; // "OKAY"
    public const uint Fail = 0x4c494146; // "FAIL"
    public const uint Quit = 0x54495551; // "QUIT"

    // v2 request / reply tags.
    public const uint StatV2 = 0x32415453; // "STA2" — stat (follows symlinks)
    public const uint LStatV2 = 0x3254534c; // "LST2" — lstat (does not follow symlinks)
    public const uint ListV2 = 0x3253494c; // "LIS2"
    public const uint DentV2 = 0x32544e44; // "DNT2"
    public const uint SendV2 = 0x32444e53; // "SND2"
    public const uint RecvV2 = 0x32564352; // "RCV2"

    public const int MaxDataChunk = 64 * 1024;
    public const int FrameHeaderSize = 8; // tag(4) + length(4)

    // Size of the fixed sync_stat_v2 / sync_dent_v2 metadata payload that follows the tag.
    // = error(4) + dev(8) + ino(8) + mode(4) + nlink(4) + uid(4) + gid(4) + size(8) + atime(8) + mtime(8) + ctime(8)
    public const int StatV2PayloadSize = 68;

    public static void WriteFrameHeader(Span<byte> dest, uint tag, uint length)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(dest, tag);
        BinaryPrimitives.WriteUInt32LittleEndian(dest[4..], length);
    }

    public static (uint Tag, uint Arg) ReadFrameHeader(ReadOnlySpan<byte> src)
    {
        var tag = BinaryPrimitives.ReadUInt32LittleEndian(src);
        var arg = BinaryPrimitives.ReadUInt32LittleEndian(src[4..]);
        return (tag, arg);
    }
}

/// <summary>
/// Result of a sync STAT call. <see cref="Exists"/> reports whether the path resolved on the
/// device. Backed by <c>LST2</c> on the wire (lstat semantics — symlinks are reported as
/// symlinks rather than resolved through).
/// </summary>
/// <param name="Mode">POSIX mode bits (file type in the high nibble, permissions in the low bits).</param>
/// <param name="Size">File size in bytes.</param>
/// <param name="ModifiedTime">Last-modified time (mtime).</param>
/// <param name="AccessedTime">Last-accessed time (atime).</param>
/// <param name="ChangedTime">Last status-change time (ctime).</param>
/// <param name="Uid">Owning user id.</param>
/// <param name="Gid">Owning group id.</param>
/// <param name="Nlink">Hard-link count.</param>
/// <param name="Inode">Inode number.</param>
/// <param name="Device">Device id holding the inode.</param>
/// <param name="Error">errno reported by the device (0 on success, &gt;0 if the device could not stat the path).</param>
[StructLayout(LayoutKind.Auto)]
// ReSharper disable once NotAccessedPositionalProperty.Global
public readonly record struct AdbFileStat(
    uint Mode,
    ulong Size,
    DateTimeOffset ModifiedTime,
    DateTimeOffset AccessedTime,
    DateTimeOffset ChangedTime,
    uint Uid,
    uint Gid,
    uint Nlink,
    ulong Inode,
    ulong Device,
    uint Error)
{
    /// <summary>
    /// <see langword="true"/> when the path exists (mode non-zero and errno zero).
    /// </summary>
    public bool Exists => Mode != 0 && Error == 0;

    /// <summary>
    /// <see langword="true"/> for directories (mode high nibble = 0x4000).
    /// </summary>
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;

    /// <summary>
    /// <see langword="true"/> for regular files (mode high nibble = 0x8000).
    /// </summary>
    public bool IsRegularFile => (Mode & 0xF000) == 0x8000;

    /// <summary>
    /// <see langword="true"/> for symlinks (mode high nibble = 0xA000).
    /// </summary>
    public bool IsSymlink => (Mode & 0xF000) == 0xA000;
}

/// <summary>
/// One entry yielded by a sync LIST call. Carries the same extended metadata as
/// <see cref="AdbFileStat"/>.
/// </summary>
/// <param name="Name">Entry name (filename within the listed directory).</param>
/// <param name="Mode">POSIX mode bits.</param>
/// <param name="Size">Entry size in bytes.</param>
/// <param name="ModifiedTime">Last-modified time (mtime).</param>
/// <param name="AccessedTime">Last-accessed time (atime).</param>
/// <param name="ChangedTime">Last status-change time (ctime).</param>
/// <param name="Uid">Owning user id.</param>
/// <param name="Gid">Owning group id.</param>
/// <param name="Nlink">Hard-link count.</param>
/// <param name="Inode">Inode number.</param>
/// <param name="Device">Device id.</param>
/// <param name="Error">errno reported by the device for this entry (usually 0).</param>
// ReSharper disable NotAccessedPositionalProperty.Global
public readonly record struct AdbDirectoryEntry(
    string Name,
    uint Mode,
    ulong Size,
    DateTimeOffset ModifiedTime,
    DateTimeOffset AccessedTime,
    DateTimeOffset ChangedTime,
    uint Uid,
    uint Gid,
    uint Nlink,
    ulong Inode,
    ulong Device,
    uint Error)
// ReSharper restore NotAccessedPositionalProperty.Global
{
    /// <summary>
    /// <see langword="true"/> for directories.
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;

    /// <summary>
    /// <see langword="true"/> for regular files.
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public bool IsRegularFile => (Mode & 0xF000) == 0x8000;

    /// <summary>
    /// <see langword="true"/> for symlinks.
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public bool IsSymlink => (Mode & 0xF000) == 0xA000;
}
