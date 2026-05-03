using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace SharpAdb.Auth;

/// <summary>
/// Android mincrypt RSAPublicKey wire format used by adbd:
/// <code>
/// struct RSAPublicKey {
///     uint32 modulus_size_words; // = 64 for 2048-bit
///     uint32 n0inv;              // -1 / N[0] mod 2^32
///     uint32 n[64];              // modulus, little-endian word order
///     uint32 rr[64];             // R^2 mod N (R = 2^2048), little-endian word order
///     uint32 exponent;
/// }
/// </code>
/// </summary>
internal static class AndroidPublicKey
{
    private const int ModulusBytes = AdbAuthKey.ModulusBytes;
    private const int ModulusWords = AdbAuthKey.ModulusWords;
    public const int EncodedSize = 4 + 4 + ModulusBytes + ModulusBytes + 4;

    public static byte[] Encode(in RSAParameters p)
    {
        ArgumentNullException.ThrowIfNull(p.Modulus);
        ArgumentNullException.ThrowIfNull(p.Exponent);
        if (p.Modulus.Length != ModulusBytes)
            throw new ArgumentException($"Modulus must be {ModulusBytes} bytes", nameof(p));

        var modulus = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var r = BigInteger.One << (ModulusWords * 32);            // R = 2^2048
        var rr = r * r % modulus;                               // R^2 mod N

        // n0inv = -modulus^-1 mod 2^32
        var b32 = BigInteger.One << 32;
        var nMod = modulus % b32;
        var inv = ModInverse(nMod, b32);
        var n0Inv = (uint)(b32 - inv);                            // -inv mod 2^32

        var result = new byte[EncodedSize];
        Span<byte> span = result;

        BinaryPrimitives.WriteUInt32LittleEndian(span, ModulusWords);
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..], n0Inv);

        WriteWordsLittleEndian(modulus, span.Slice(8, ModulusBytes));
        WriteWordsLittleEndian(rr, span.Slice(8 + ModulusBytes, ModulusBytes));

        // Exponent: ADB pubkey format stores it as a single uint32 (typically 65537).
        var exponent = ReadBigEndianExponent(p.Exponent);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(8 + 2 * ModulusBytes)..], exponent);

        return result;
    }

    private static uint ReadBigEndianExponent(in ReadOnlySpan<byte> exp)
    {
        if (exp.Length > 4)
            throw new NotSupportedException("ADB public-key format only supports exponents up to 32 bits");

        var v = 0u;
        foreach (var b in exp)
            v = (v << 8) | b;

        return v;
    }

    private static void WriteWordsLittleEndian(in BigInteger value, in Span<byte> dest)
    {
        // Each 4-byte word is little-endian, words are also in little-endian order
        // (i.e. least-significant word first), exactly matching mincrypt's layout.
        Span<byte> tmp = stackalloc byte[ModulusBytes + 1];
        if (!value.TryWriteBytes(tmp, out var written, isUnsigned: true, isBigEndian: false))
            throw new InvalidOperationException("Failed to serialize BigInteger");
        if (written > ModulusBytes)
        {
            // Extra leading zero word from sign byte; drop it.
            written = ModulusBytes;
        }
        dest.Clear();
        tmp[..written].CopyTo(dest);
    }

    private static BigInteger ModInverse(in BigInteger a, in BigInteger m)
    {
        // Extended Euclidean algorithm.
        BigInteger oldR = a, r = m;
        BigInteger oldS = 1, s = 0;
        while (r != 0)
        {
            var q = oldR / r;
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
        }

        if (oldR != 1)
            throw new InvalidOperationException("Modular inverse does not exist");

        return ((oldS % m) + m) % m;
    }
}
