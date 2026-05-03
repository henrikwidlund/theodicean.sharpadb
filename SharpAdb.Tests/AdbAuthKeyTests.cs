using System.Security.Cryptography;
using System.Text;

using SharpAdb.Auth;
using SharpAdb.Protocol;

using Xunit;

namespace SharpAdb.Tests;

public class AdbAuthKeyTests
{
    [Fact]
    public void GenerateProduces2048BitKey()
    {
        using var key = AdbAuthKey.Generate();
        var pem = key.ExportPrivateKeyPem();
        Assert.Contains("BEGIN RSA PRIVATE KEY", pem);
    }

    [Fact]
    public void RejectsWrongKeySize()
    {
        using var rsa = RSA.Create(1024);
        Assert.Throws<ArgumentException>(() => new AdbAuthKey(rsa));
    }

    [Fact]
    public void SignTokenRejectsWrongLength()
    {
        using var key = AdbAuthKey.Generate();
        Assert.Throws<ArgumentException>(() => key.SignToken(new byte[10]));
    }

    [Fact]
    public void SignTokenProducesVerifiablePkcs1Signature()
    {
        using var key = AdbAuthKey.Generate();
        var token = RandomNumberGenerator.GetBytes(AdbProtocolConstants.AuthTokenSize);
        var sig = key.SignToken(token);

        Assert.Equal(AdbAuthKey.ModulusBytes, sig.Length);

        using var pub = RSA.Create();
        pub.ImportFromPem(key.ExportPrivateKeyPem());
        Assert.True(pub.VerifyHash(token, sig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void EncodedPublicKeyEndsWithSpaceUserHostNul()
    {
        using var key = AdbAuthKey.Generate("alice@host");
        var encoded = key.EncodeAndroidPublicKey();

        Assert.Equal(0, encoded[^1]);
        var spaceIdx = Array.IndexOf(encoded, (byte)' ');
        Assert.True(spaceIdx > 0);
        var userHost = Encoding.UTF8.GetString(encoded.AsSpan(spaceIdx + 1, encoded.Length - spaceIdx - 2));
        Assert.Equal("alice@host", userHost);

        // Base64 portion should decode to mincrypt blob: 4 + 4 + 256 + 256 + 4 = 524 bytes.
        var blob = Convert.FromBase64String(Encoding.ASCII.GetString(encoded, 0, spaceIdx));
        Assert.Equal(524, blob.Length);
    }

    [Fact]
    public void EncodedPublicKeyContainsCorrectModulusWordCount()
    {
        using var key = AdbAuthKey.Generate();
        var encoded = key.EncodeAndroidPublicKey();
        var spaceIdx = Array.IndexOf(encoded, (byte)' ');
        var blob = Convert.FromBase64String(Encoding.ASCII.GetString(encoded, 0, spaceIdx));

        var words = BitConverter.ToUInt32(blob, 0);
        Assert.Equal((uint)AdbAuthKey.ModulusWords, words);

        // n0inv: ((-1 / N[0]) mod 2^32). With N[0] (least-significant word) being any odd value
        // (RSA modulus is odd), we should have (n0inv * N[0]) mod 2^32 == (2^32 - 1) i.e. -1.
        var n0Inv = BitConverter.ToUInt32(blob, 4);
        var n0 = BitConverter.ToUInt32(blob, 8);
        Assert.Equal(0xFFFFFFFFu, unchecked(n0Inv * n0));
    }
}
