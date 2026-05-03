using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Theodicean.SharpAdb.Protocol;

/// <summary>
/// 24-byte ADB packet header. Wire layout (little-endian):
/// command (4) | arg0 (4) | arg1 (4) | data_length (4) | data_check (4) | magic (4).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = AdbProtocolConstants.HeaderSize)]
public readonly struct AdbHeader
{
    /// <summary>
    /// Wire command tag..
    /// </summary>
    public readonly AdbCommand Command;

    /// <summary>
    /// Command-specific first argument. Meaning depends on <see cref="Command"/>.
    /// </summary>
    public readonly uint Arg0;

    /// <summary>
    /// Command-specific second argument. Meaning depends on <see cref="Command"/>.
    /// </summary>
    public readonly uint Arg1;

    /// <summary>
    /// Length of the payload that follows this header, in bytes.
    /// </summary>
    public readonly uint DataLength;

    /// <summary>
    /// Legacy sum-of-bytes checksum of the payload. Modern peers send 0.
    /// </summary>
    public readonly uint DataChecksum;

    /// <summary>
    /// Bitwise-NOT of <see cref="Command"/>. Used by readers to detect frame desynchronization.
    /// </summary>
    public readonly uint Magic;

    /// <summary>
    /// Initializes a new header. <see cref="Magic"/> is computed automatically.
    /// </summary>
    public AdbHeader(in AdbCommand command, in uint arg0, in uint arg1, in uint dataLength, in uint dataChecksum)
    {
        Command = command;
        Arg0 = arg0;
        Arg1 = arg1;
        DataLength = dataLength;
        DataChecksum = dataChecksum;
        Magic = (uint)command ^ 0xFFFFFFFFu;
    }

    /// <summary>
    /// <see langword="true"/> when <see cref="Magic"/> matches the bitwise-NOT of <see cref="Command"/>.
    /// </summary>
    public bool IsMagicValid => Magic == ((uint)Command ^ 0xFFFFFFFFu);

    /// <summary>
    /// Sum-of-bytes checksum used by ADB for payload verification (legacy; protocol v2 sets it to 0).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ComputeChecksum(in ReadOnlySpan<byte> payload)
    {
        uint sum = 0;
        ref var p = ref MemoryMarshal.GetReference(payload);
        var len = (nuint)payload.Length;
        for (nuint i = 0; i < len; i++)
            sum += Unsafe.AddByteOffset(ref p, i);
        return sum;
    }

    /// <summary>
    /// Serializes this header into <paramref name="destination"/>. Buffer must be at least 24 bytes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteTo(in Span<byte> destination)
    {
        if (destination.Length < AdbProtocolConstants.HeaderSize)
            throw new ArgumentException("Buffer too small for ADB header", nameof(destination));

        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)Command);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], Arg0);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], Arg1);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], DataLength);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[16..], DataChecksum);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[20..], Magic);
    }

    /// <summary>
    /// Decodes a header from <paramref name="source"/>.
    /// </summary>
    /// <exception cref="InvalidDataException">Thrown if magic does not match.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static AdbHeader Read(in ReadOnlySpan<byte> source)
    {
        if (source.Length < AdbProtocolConstants.HeaderSize)
            throw new ArgumentException("Buffer too small for ADB header", nameof(source));

        var command = (AdbCommand)BinaryPrimitives.ReadUInt32LittleEndian(source);
        var arg0 = BinaryPrimitives.ReadUInt32LittleEndian(source[4..]);
        var arg1 = BinaryPrimitives.ReadUInt32LittleEndian(source[8..]);
        var dataLength = BinaryPrimitives.ReadUInt32LittleEndian(source[12..]);
        var dataChecksum = BinaryPrimitives.ReadUInt32LittleEndian(source[16..]);
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(source[20..]);

        var header = new AdbHeader(command, arg0, arg1, dataLength, dataChecksum);
        return header.Magic != magic
            ? throw new InvalidDataException($"Invalid ADB packet magic: expected 0x{header.Magic:X8}, got 0x{magic:X8}")
            : header;
    }
}
