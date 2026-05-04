using System.Security.Cryptography;

using Theodicean.SharpAdb.Auth;

namespace Theodicean.SharpAdb.Tests;

public class AndroidPublicKeyTests
{
    [Test]
    public async Task EncodeRejectsNullModulus()
    {
        var p = new RSAParameters { Modulus = null, Exponent = [0x01, 0x00, 0x01] };
        await Assert.That(() => AndroidPublicKey.Encode(p)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task EncodeRejectsNullExponent()
    {
        var p = new RSAParameters { Modulus = new byte[AdbAuthKey.ModulusBytes], Exponent = null };
        await Assert.That(() => AndroidPublicKey.Encode(p)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task EncodeRejectsWrongSizeModulus()
    {
        var p = new RSAParameters { Modulus = new byte[AdbAuthKey.ModulusBytes - 1], Exponent = [0x01, 0x00, 0x01] };
        await Assert.That(() => AndroidPublicKey.Encode(p)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task EncodeRejectsExponentLargerThan4Bytes()
    {
        // Real key for valid modulus, but oversized exponent triggers the >4 byte guard.
        using var rsa = RSA.Create(AdbAuthKey.KeySizeBits);
        var p = rsa.ExportParameters(includePrivateParameters: false);
        p.Exponent = [0, 0, 0, 0, 1, 0, 1]; // 7 bytes
        await Assert.That(() => AndroidPublicKey.Encode(p)).ThrowsExactly<NotSupportedException>();
    }
}
