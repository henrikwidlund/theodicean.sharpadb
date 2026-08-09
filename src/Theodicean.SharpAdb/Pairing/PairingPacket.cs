using System.Buffers.Binary;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>Wire type of a <c>PairingPacketHeader</c>, matching <c>adb.proto.PairingPacket.Type</c>.</summary>
internal enum PairingPacketType : byte
{
    Spake2Msg = 0,
    PeerInfo = 1
}

/// <summary>What kind of identity <see cref="PeerInfo"/> carries.</summary>
public enum PeerInfoType : byte
{
    /// <summary>An Android mincrypt-encoded RSA public key, formatted exactly like a normal ADB AUTH pubkey line.</summary>
    AdbRsaPublicKey = 0,

    /// <summary>An opaque device GUID.</summary>
    // ReSharper disable once UnusedMember.Global
    AdbDeviceGuid = 1
}

/// <summary>
/// The 6-byte header ADB's pairing protocol prefixes every message with over the TLS channel:
/// a version byte (currently always 1), a <see cref="PairingPacketType"/> byte, and a big-endian
/// (network order) payload length. This is a distinct framing from the normal ADB CNXN/OPEN
/// packet header used post-connect.
/// </summary>
internal static class PairingPacketHeader
{
    internal const int Size = 6;
    private const byte CurrentVersion = 1;

    internal static void Write(in Span<byte> destination, in PairingPacketType type, in int payloadLength)
    {
        destination[0] = CurrentVersion;
        destination[1] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(destination[2..], (uint)payloadLength);
    }

    /// <summary>Parses a header, validating the version and a caller-supplied maximum payload size.</summary>
    internal static bool TryRead(in ReadOnlySpan<byte> source, in int maxPayloadSize, out PairingPacketType type, out int payloadLength)
    {
        type = default;
        payloadLength = 0;
        if (source.Length != Size || source[0] != CurrentVersion)
            return false;

        if (source[1] > (byte)PairingPacketType.PeerInfo)
            return false;
        type = (PairingPacketType)source[1];

        var length = BinaryPrimitives.ReadUInt32BigEndian(source[2..]);
        if (length == 0 || length > (uint)maxPayloadSize)
            return false;
        payloadLength = (int)length;
        return true;
    }
}

/// <summary>
/// The fixed-size (8192-byte) peer identity payload exchanged, encrypted, once pairing's SPAKE2
/// exchange succeeds. Matches ADB's <c>PeerInfo</c> struct: a one-byte <see cref="PeerInfoType"/>
/// followed by 8191 bytes of type-specific, NUL-padded data.
/// </summary>
public static class PeerInfo
{
    /// <summary>Total encoded size of a <c>PeerInfo</c> struct, per ADB's <c>kMaxPeerInfoSize</c>.</summary>
    public const int EncodedSize = 8192;
    private const int DataSize = EncodedSize - 1;

    /// <summary>Encodes <paramref name="data"/> (at most 8191 bytes) into a full 8192-byte, zero-padded <c>PeerInfo</c> buffer.</summary>
    internal static byte[] Encode(in PeerInfoType type, in ReadOnlySpan<byte> data)
    {
        if (data.Length > DataSize)
            throw new ArgumentException($"PeerInfo data must be at most {DataSize} bytes", nameof(data));

        var buffer = new byte[EncodedSize];
        buffer[0] = (byte)type;
        data.CopyTo(buffer.AsSpan(1));
        return buffer;
    }

    /// <summary>
    /// Decodes a full 8192-byte <c>PeerInfo</c> buffer, trimming trailing zero padding from the
    /// data section (safe because every defined payload — the AUTH-style pubkey line — is itself
    /// NUL-terminated, so trailing zero bytes are never meaningful content).
    /// </summary>
    internal static (PeerInfoType Type, byte[] Data) Decode(in ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length != EncodedSize)
            throw new ArgumentException($"PeerInfo buffer must be exactly {EncodedSize} bytes", nameof(buffer));

        var type = (PeerInfoType)buffer[0];
        var data = buffer[1..];
        var end = data.Length;
        while (end > 0 && data[end - 1] == 0)
            end--;

        return (type, [.. data[..end]]);
    }
}
