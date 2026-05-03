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
    public const int KeySizeBits = 2048;
    public const int ModulusBytes = KeySizeBits / 8;
    public const int ModulusWords = ModulusBytes / 4;

    private readonly RSA _rsa;
    private readonly bool _ownsRsa;
    private readonly string _userHost;

    public AdbAuthKey(RSA rsa, string userHost = "sharpadb@dotnet", in bool ownsRsa = true)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        if (rsa.KeySize != KeySizeBits)
            throw new ArgumentException($"ADB requires {KeySizeBits}-bit RSA key, got {rsa.KeySize}", nameof(rsa));
        _rsa = rsa;
        _ownsRsa = ownsRsa;
        _userHost = userHost;
    }

    public static AdbAuthKey Generate(string userHost = "sharpadb@dotnet")
    {
        var rsa = RSA.Create(KeySizeBits);
        return new AdbAuthKey(rsa, userHost);
    }

    public static AdbAuthKey LoadFromPem(string pem, string userHost = "sharpadb@dotnet")
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new AdbAuthKey(rsa, userHost);
    }

    public string ExportPrivateKeyPem() => _rsa.ExportRSAPrivateKeyPem();

    /// <summary>
    /// Build a self-signed X.509 certificate wrapping this key, for use as the client cert during
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

        if (!Convert.TryToBase64Chars(keyBlob, default, out _))
        {
            // Fallback path; should never trigger.
        }

        // Fill base64 directly into ASCII bytes.
        var tmp = new char[b64Len];
        Convert.TryToBase64Chars(keyBlob, tmp, out var written);
        for (var i = 0; i < written; i++)
            result[i] = (byte)tmp[i];

        result[b64Len] = (byte)' ';
        var u = Encoding.UTF8.GetBytes(_userHost, result.AsSpan(b64Len + 1));
        result[b64Len + 1 + u] = 0;

        return result;
    }

    public void Dispose()
    {
        if (_ownsRsa) _rsa.Dispose();
    }
}
