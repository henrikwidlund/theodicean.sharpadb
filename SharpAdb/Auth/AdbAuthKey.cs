using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpAdb.Auth;

/// <summary>
/// 2048-bit RSA key used for ADB device pairing. Wraps an <see cref="RSA"/> instance and exposes
/// challenge signing plus Android mincrypt public-key serialization.
/// </summary>
public sealed class AdbAuthKey : IDisposable
{
    /// <summary>
    /// Required RSA key size in bits. ADB only accepts 2048-bit keys.
    /// </summary>
    public const int KeySizeBits = 2048;

    /// <summary>
    /// Modulus length in bytes (= 256 for a 2048-bit key).
    /// </summary>
    public const int ModulusBytes = KeySizeBits / 8;

    /// <summary>
    /// Modulus length in 32-bit words (= 64 for a 2048-bit key). Used by the mincrypt encoder.
    /// </summary>
    public const int ModulusWords = ModulusBytes / 4;

    private readonly RSA _rsa;
    private readonly bool _ownsRsa;
    private readonly string _userHost;

    /// <summary>
    /// Initializes a new instance that wraps an existing RSA instance for use as an ADB auth key.
    /// </summary>
    /// <param name="rsa">RSA key. Must be 2048-bit.</param>
    /// <param name="userHost">Identity string sent alongside the public key, formatted <c>user@host</c>.</param>
    /// <param name="ownsRsa">When <see langword="true"/>, disposing this object also disposes <paramref name="rsa"/>.</param>
    public AdbAuthKey(RSA rsa, string userHost = "sharpadb@dotnet", in bool ownsRsa = true)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        if (rsa.KeySize != KeySizeBits)
            throw new ArgumentException($"ADB requires {KeySizeBits}-bit RSA key, got {rsa.KeySize}", nameof(rsa));
        _rsa = rsa;
        _ownsRsa = ownsRsa;
        _userHost = userHost;
    }

    /// <summary>
    /// Generates a fresh 2048-bit RSA key pair. Persist the result with <see cref="ExportPrivateKeyPem"/> for reuse.
    /// </summary>
    public static AdbAuthKey Generate(string userHost = "sharpadb@dotnet")
    {
        var rsa = RSA.Create(KeySizeBits);
        return new AdbAuthKey(rsa, userHost);
    }

    /// <summary>
    /// Loads a key from a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
    /// </summary>
    public static AdbAuthKey LoadFromPem(string pem, string userHost = "sharpadb@dotnet")
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new AdbAuthKey(rsa, userHost);
    }

    /// <summary>
    /// Exports the private key in PKCS#1 PEM form (compatible with Google's <c>~/.android/adbkey</c>).
    /// </summary>
    public string ExportPrivateKeyPem() => _rsa.ExportRSAPrivateKeyPem();

    /// <summary>
    /// Builds a self-signed X.509 certificate wrapping this key, for use as the client cert during
    /// the ADB STLS upgrade. adbd does not validate the cert chain; only key ownership matters.
    /// </summary>
    public X509Certificate2 CreateSelfSignedCertificate(string subjectName = "CN=SharpAdb")
    {
        var req = new CertificateRequest(subjectName, _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);
        return req.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>
    /// Signs the 20-byte AUTH token. adbd treats the token as a SHA-1 digest and verifies with
    /// PKCS#1 v1.5; .NET's <c>SignHash</c> handles prefixing the DigestInfo wrapper internally.
    /// </summary>
    public byte[] SignToken(in ReadOnlySpan<byte> token)
    {
        if (token.Length != Protocol.AdbProtocolConstants.AuthTokenSize)
            throw new ArgumentException($"Token must be {Protocol.AdbProtocolConstants.AuthTokenSize} bytes", nameof(token));

        return _rsa.SignHash(token, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Encodes the public key in Android's mincrypt RSAPublicKey wire format, base64-encoded,
    /// followed by " user@host\0" — the exact string sent in <c>AUTH(RSAPUBLICKEY, ...)</c> packets.
    /// </summary>
    public byte[] EncodeAndroidPublicKey()
    {
        var p = _rsa.ExportParameters(includePrivateParameters: false);
        var keyBlob = AndroidPublicKey.Encode(p);

        var b64Len = (keyBlob.Length + 2) / 3 * 4;
        var suffixLen = 1 + Encoding.UTF8.GetByteCount(_userHost) + 1; // ' ' + userhost + NUL
        var result = new byte[b64Len + suffixLen];

        var charBuf = ArrayPool<char>.Shared.Rent(b64Len);
        try
        {
            if (!Convert.TryToBase64Chars(keyBlob, charBuf, out var written) || written != b64Len)
                throw new InvalidOperationException("Base64 encoding produced unexpected length");

            for (var i = 0; i < written; i++)
                result[i] = (byte)charBuf[i];
        }
        finally
        {
            ArrayPool<char>.Shared.Return(charBuf);
        }

        result[b64Len] = (byte)' ';
        var u = Encoding.UTF8.GetBytes(_userHost, result.AsSpan(b64Len + 1));
        result[b64Len + 1 + u] = 0;

        return result;
    }

    /// <summary>
    /// Disposes the underlying RSA instance if this object owns it.
    /// </summary>
    public void Dispose()
    {
        if (_ownsRsa)
            _rsa.Dispose();
    }
}
