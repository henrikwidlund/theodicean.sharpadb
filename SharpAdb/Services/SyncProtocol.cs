using System.Buffers.Binary;

namespace SharpAdb.Services;

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

public readonly record struct AdbFileStat(uint Mode, uint Size, DateTimeOffset ModifiedTime)
{
    public bool Exists => Mode != 0;
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;
    public bool IsRegularFile => (Mode & 0xF000) == 0x8000;
    public bool IsSymlink => (Mode & 0xF000) == 0xA000;
}

public readonly record struct AdbDirectoryEntry(string Name, uint Mode, uint Size, DateTimeOffset ModifiedTime)
{
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;
    public bool IsRegularFile => (Mode & 0xF000) == 0x8000;
    public bool IsSymlink => (Mode & 0xF000) == 0xA000;
}
