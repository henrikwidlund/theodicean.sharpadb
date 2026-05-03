using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// 4-byte ASCII tags for the ADB sync subprotocol (file transfer over the "sync:" service).
/// </summary>
internal static class SyncProtocol
{
    public const uint List = 0x5453494c; // "LIST"
    public const uint Recv = 0x56434552; // "RECV"
    public const uint Send = 0x444e4553; // "SEND"
    public const uint Stat = 0x54415453; // "STAT"
    public const uint Dent = 0x544e4544; // "DENT"
    public const uint Data = 0x41544144; // "DATA"
    public const uint Done = 0x454e4f44; // "DONE"
    public const uint Okay = 0x59414b4f; // "OKAY"
    public const uint Fail = 0x4c494146; // "FAIL"
    public const uint Quit = 0x54495551; // "QUIT"

    public const int MaxDataChunk = 64 * 1024;
    public const int FrameHeaderSize = 8; // tag(4) + length(4)

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
/// Result of a sync STAT call. <c>Mode == 0</c> means the path does not exist.
/// </summary>
/// <param name="Mode">POSIX mode bits (file type in the high nibble, permissions in the low bits).</param>
/// <param name="Size">File size in bytes. Capped at <see cref="uint.MaxValue"/> by the protocol.</param>
/// <param name="ModifiedTime">Last-modified time.</param>
[StructLayout(LayoutKind.Auto)]
public readonly record struct AdbFileStat(uint Mode, uint Size, DateTimeOffset ModifiedTime)
{
    /// <summary>
    /// <see langword="true"/> when the path exists (i.e. the device returned a non-zero mode).
    /// </summary>
    public bool Exists => Mode != 0;

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
/// One entry yielded by a sync LIST call.
/// </summary>
/// <param name="Name">Entry name (filename within the listed directory).</param>
/// <param name="Mode">POSIX mode bits.</param>
/// <param name="Size">Entry size in bytes.</param>
/// <param name="ModifiedTime">Last-modified time.</param>
public readonly record struct AdbDirectoryEntry(string Name, uint Mode, uint Size, DateTimeOffset ModifiedTime)
{
    /// <summary>
    /// <see langword="true"/> for directories.
    /// </summary>
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;

    /// <summary>
    /// <see langword="true"/> for regular files.
    /// </summary>
    public bool IsRegularFile => (Mode & 0xF000) == 0x8000;

    /// <summary>
    /// <see langword="true"/> for symlinks.
    /// </summary>
    public bool IsSymlink => (Mode & 0xF000) == 0xA000;
}
