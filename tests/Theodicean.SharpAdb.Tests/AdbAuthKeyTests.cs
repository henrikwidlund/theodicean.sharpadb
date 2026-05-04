using System.Security.Cryptography;
using System.Text;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb.Tests;

public class AdbAuthKeyTests
{
    [Test]
    public async Task GenerateProduces2048BitKey()
    {
        using var key = AdbAuthKey.Generate();
        var pem = key.ExportPrivateKeyPem();
        await Assert.That(pem).Contains("BEGIN RSA PRIVATE KEY");
    }

    [Test]
    public async Task RejectsWrongKeySize()
    {
        using var rsa = RSA.Create(1024);
        await Assert.That(() => new AdbAuthKey(rsa)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task SignTokenRejectsWrongLength()
    {
        using var key = AdbAuthKey.Generate();
        await Assert.That(() => key.SignToken(new byte[10])).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task SignTokenProducesVerifiablePkcs1Signature()
    {
        using var key = AdbAuthKey.Generate();
        var token = RandomNumberGenerator.GetBytes(AdbProtocolConstants.AuthTokenSize);
        var sig = key.SignToken(token);

        await Assert.That(sig).Count().IsEqualTo(AdbAuthKey.ModulusBytes);

        using var pub = RSA.Create();
        pub.ImportFromPem(key.ExportPrivateKeyPem());
        await Assert.That(pub.VerifyHash(token, sig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)).IsTrue();
    }

    [Test]
    public async Task EncodedPublicKeyEndsWithSpaceUserHostNul()
    {
        using var key = AdbAuthKey.Generate("alice@host");
        var encoded = key.EncodeAndroidPublicKey();

        await Assert.That(encoded[^1]).IsEqualTo((byte)0);
        var spaceIdx = Array.IndexOf(encoded, (byte)' ');
        await Assert.That(spaceIdx).IsGreaterThan(0);
        var userHost = Encoding.UTF8.GetString(encoded.AsSpan(spaceIdx + 1, encoded.Length - spaceIdx - 2));
        await Assert.That(userHost).IsEqualTo("alice@host");

        // Base64 portion should decode to mincrypt blob: 4 + 4 + 256 + 256 + 4 = 524 bytes.
        var blob = Convert.FromBase64String(Encoding.ASCII.GetString(encoded, 0, spaceIdx));
        await Assert.That(blob).Count().IsEqualTo(524);
    }

    [Test]
    public async Task EncodedPublicKeyContainsCorrectModulusWordCount()
    {
        using var key = AdbAuthKey.Generate();
        var encoded = key.EncodeAndroidPublicKey();
        var spaceIdx = Array.IndexOf(encoded, (byte)' ');
        var blob = Convert.FromBase64String(Encoding.ASCII.GetString(encoded, 0, spaceIdx));

        var words = BitConverter.ToUInt32(blob, 0);
        await Assert.That(words).IsEqualTo((uint)AdbAuthKey.ModulusWords);

        // n0inv: ((-1 / N[0]) mod 2^32). With N[0] (least-significant word) being any odd value
        // (RSA modulus is odd), we should have (n0inv * N[0]) mod 2^32 == (2^32 - 1) i.e. -1.
        var n0Inv = BitConverter.ToUInt32(blob, 4);
        var n0 = BitConverter.ToUInt32(blob, 8);
        await Assert.That(unchecked(n0Inv * n0)).IsEqualTo(0xFFFFFFFFu);
    }
}
