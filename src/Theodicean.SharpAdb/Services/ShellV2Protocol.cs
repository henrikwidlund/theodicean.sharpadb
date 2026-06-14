using System.Buffers.Binary;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Shell v2 sub-protocol packet identifiers. ADB shell_v2 frames every chunk inside the
/// stream as a 5-byte header (<see cref="ShellV2Protocol.HeaderSize"/>) followed by a payload.
/// </summary>
internal enum ShellPacketId : byte
{
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
    Exit = 3,
    CloseStdin = 4,
}

/// <summary>
/// Wire helpers for the ADB shell_v2 sub-protocol (Android 7+). Each frame is
/// <c>id(1) + length(4, little-endian) + payload(length)</c>.
/// </summary>
internal static class ShellV2Protocol
{
    public const int HeaderSize = 5;

    /// <summary>
    /// CNXN banner feature flag indicating the device speaks shell_v2.
    /// </summary>
    public const string FeatureFlag = "shell_v2";

    public static void WriteHeader(Span<byte> dest, ShellPacketId id, uint length)
    {
        dest[0] = (byte)id;
        BinaryPrimitives.WriteUInt32LittleEndian(dest[1..], length);
    }

    public static (ShellPacketId Id, uint Length) ReadHeader(ReadOnlySpan<byte> src) =>
        ((ShellPacketId)src[0], BinaryPrimitives.ReadUInt32LittleEndian(src[1..]));
}
