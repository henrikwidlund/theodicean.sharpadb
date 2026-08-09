using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>
/// AES-128-GCM wrapper over the SPAKE2 key material, matching ADB's <c>Aes128Gcm</c>
/// (<c>pairing_auth/aes_128_gcm.cpp</c>): the 64-byte SPAKE2 transcript hash is run through
/// HKDF-SHA256 to derive a 16-byte AES key, and the 96-bit nonce is an all-zero buffer with an
/// 8-byte little-endian message counter in its low bytes. Encrypt and decrypt use independent
/// counters. Since the pairing protocol only ever encrypts a single message in each direction,
/// both counters are always 0 in practice — the nonce is never actually transmitted.
/// </summary>
internal sealed class PairingCipher
{
    private const int KeySizeBytes = 16;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private static readonly byte[] HkdfInfo = [.. "adb pairing_auth aes-128-gcm key"u8];

    private readonly AesGcm _aes;
    private ulong _encryptSequence;
    private ulong _decryptSequence;

    internal PairingCipher(in ReadOnlySpan<byte> keyMaterial)
    {
        Span<byte> key = stackalloc byte[KeySizeBytes];
        HKDF.Expand(HashAlgorithmName.SHA256, ExtractPrk(keyMaterial), key, HkdfInfo);
        _aes = new AesGcm(key, TagSizeBytes);
    }

    /// <summary>Encrypts <paramref name="plaintext"/>, returning ciphertext with the 16-byte tag appended.</summary>
    internal byte[] Encrypt(in ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + TagSizeBytes];
        Span<byte> nonce = stackalloc byte[NonceSizeBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, _encryptSequence);
        _aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length, TagSizeBytes));
        // Matches aes_128_gcm.cpp: the sequence only advances after a successful seal/open, not
        // unconditionally. Unobservable under this protocol's actual usage (each direction
        // encrypts/decrypts exactly once, so there is never a second attempt to diverge on) —
        // fixed anyway so this class's behavior doesn't quietly depend on that assumption holding.
        _encryptSequence++;
        return output;
    }

    /// <summary>Decrypts a ciphertext produced by <see cref="Encrypt"/> (ciphertext with trailing 16-byte tag).</summary>
    /// <returns>The plaintext, or <see langword="null"/> if authentication failed.</returns>
    internal byte[]? Decrypt(in ReadOnlySpan<byte> ciphertextWithTag)
    {
        if (ciphertextWithTag.Length < TagSizeBytes)
            return null;

        var plaintextLength = ciphertextWithTag.Length - TagSizeBytes;
        var plaintext = new byte[plaintextLength];
        Span<byte> nonce = stackalloc byte[NonceSizeBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, _decryptSequence);
        try
        {
            _aes.Decrypt(nonce, ciphertextWithTag[..plaintextLength], ciphertextWithTag[plaintextLength..], plaintext);
            _decryptSequence++;
            return plaintext;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // HKDF-Extract with an all-zero salt (BoringSSL's HKDF() with salt=nullptr,0 uses a
    // zero-filled hash-length salt per RFC 5869), producing the pseudorandom key HKDF.Expand needs.
    private static byte[] ExtractPrk(in ReadOnlySpan<byte> keyMaterial)
    {
        var prk = new byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, keyMaterial, stackalloc byte[32], prk);
        return prk;
    }
}
