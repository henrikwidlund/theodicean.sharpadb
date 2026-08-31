using System.Security.Cryptography;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>Which side of the SPAKE2 exchange this instance plays.</summary>
internal enum Spake2Role : byte
{
    /// <summary>"adb pair client" — the host initiating the pairing connection.</summary>
    Client,

    /// <summary>"adb pair server" — the Android device showing the pairing code.</summary>
    Server
}

/// <summary>
/// Reimplements BoringSSL's Curve25519-based SPAKE2 (<c>SPAKE2_CTX_new</c>/<c>SPAKE2_generate_msg</c>/
/// <c>SPAKE2_process_msg</c> in <c>crypto/curve25519/spake25519.cc</c>), which is what ADB's
/// <c>pairing_auth</c> module uses for the wireless-pairing handshake. This is the original
/// SPAKE2 construction over edwards25519 (mask points M/N with Elligator-style generation), not
/// the NIST P-256 variant standardized in RFC 9382 — the two are not wire-compatible.
/// </summary>
internal sealed class Spake2Handshake
{
    // BoringSSL passes sizeof(name) as the length, which for a C string literal includes the
    // trailing NUL. The transcript hash is sensitive to this exact 16-byte (15 chars + NUL) form.
    private static readonly byte[] ClientName = [.. "adb pair client\0"u8];
    private static readonly byte[] ServerName = [.. "adb pair server\0"u8];

    private static readonly Edwards25519Point PointM = DecodeConstant(
    [
        0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c, 0x6b, 0x5c,
        0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b, 0x88, 0xee, 0xd1, 0x2e
    ]);

    private static readonly Edwards25519Point PointN = DecodeConstant(
    [
        0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46, 0x72, 0x10,
        0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11, 0x69, 0x3b, 0xc7, 0x78
    ]);

    private readonly Spake2Role _role;
    private readonly byte[] _myName;
    private readonly byte[] _theirName;
    private readonly System.Numerics.BigInteger _privateKey;
    private readonly System.Numerics.BigInteger _passwordScalar;
    private readonly byte[] _passwordHash;
    private bool _consumed;

    /// <summary>Our outgoing SPAKE2 message: a 32-byte compressed masked point.</summary>
    internal byte[] Message { get; }

    internal Spake2Handshake(Spake2Role role, in ReadOnlySpan<byte> password)
    {
        _role = role;
        _myName = role == Spake2Role.Client ? ClientName : ServerName;
        _theirName = role == Spake2Role.Client ? ServerName : ClientName;

        Span<byte> ephemeral = stackalloc byte[64];
        RandomNumberGenerator.Fill(ephemeral);
        // Reduce mod the group order, then multiply by the cofactor (8) so this scalar always
        // clears the cofactor of whatever point we later multiply it against.
        _privateKey = Edwards25519Point.ReduceModOrder(ephemeral) * 8;

        _passwordHash = SHA512.HashData(password);
        var passwordScalar = Edwards25519Point.ReduceModOrder(_passwordHash);

        // Replicates BoringSSL's deliberately-preserved "password scalar hack": an early version
        // omitted clearing the cofactor on this scalar, which would leak the low 3 bits of the
        // password hash. Rather than break the wire format by fixing it directly, later BoringSSL
        // versions patch it up by adding multiples of the group order to zero the low 3 bits,
        // which is equivalent to adding points of small order to the masked value. Any peer
        // running unmodified adbd expects this exact adjustment.
        var order = Edwards25519Point.Order;
        if (!(passwordScalar & 1).IsZero) passwordScalar += order;
        order *= 2;
        if (!(passwordScalar & 2).IsZero) passwordScalar += order;
        order *= 2;
        if (!(passwordScalar & 4).IsZero) passwordScalar += order;
        _passwordScalar = passwordScalar;

        var p = Edwards25519Point.BasePoint.Multiply(_privateKey);
        var mask = (role == Spake2Role.Client ? PointM : PointN).Multiply(_passwordScalar);
        Message = p.Add(mask).Encode();
    }

    /// <summary>
    /// Processes the peer's SPAKE2 message and returns the 64-byte SHA-512 transcript key
    /// material (matching <c>SPAKE2_process_msg</c>'s <c>SPAKE2_MAX_KEY_SIZE</c> output). Can only
    /// be called once. Returns <see langword="null"/> if <paramref name="theirMessage"/> is not a
    /// valid point on the curve.
    /// </summary>
    internal byte[]? ProcessPeerMessage(in ReadOnlySpan<byte> theirMessage)
    {
        if (_consumed)
            throw new InvalidOperationException("ProcessPeerMessage can only be called once.");
        _consumed = true;

        if (theirMessage.Length != 32 || !Edwards25519Point.TryDecode(theirMessage, out var theirPoint))
            return null;

        var peersMask = (_role == Spake2Role.Client ? PointN : PointM).Multiply(_passwordScalar);
        var unmasked = theirPoint.Subtract(peersMask);
        var shared = unmasked.Multiply(_privateKey);
        var sharedEncoded = shared.Encode();

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        // The transcript is always written in (client name, server name, client msg, server msg)
        // order regardless of which role we're playing, so both sides hash identical bytes.
        if (_role == Spake2Role.Client)
        {
            AppendWithLength(sha, _myName);
            AppendWithLength(sha, _theirName);
            AppendWithLength(sha, Message);
            AppendWithLength(sha, theirMessage);
        }
        else
        {
            AppendWithLength(sha, _theirName);
            AppendWithLength(sha, _myName);
            AppendWithLength(sha, theirMessage);
            AppendWithLength(sha, Message);
        }
        AppendWithLength(sha, sharedEncoded);
        AppendWithLength(sha, _passwordHash);

        return sha.GetHashAndReset();
    }

    private static void AppendWithLength(IncrementalHash sha, in ReadOnlySpan<byte> data)
    {
        Span<byte> lengthLe = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(lengthLe, (ulong)data.Length);
        sha.AppendData(lengthLe);
        sha.AppendData(data);
    }

    private static Edwards25519Point DecodeConstant(byte[] encoded) =>
        Edwards25519Point.TryDecode(encoded, out var point)
            ? point
            : throw new InvalidOperationException("Invalid hardcoded curve constant");
}
