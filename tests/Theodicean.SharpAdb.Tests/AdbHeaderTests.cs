using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb.Tests;

public class AdbHeaderTests
{
    [Test]
    public async Task RoundTripsThroughBuffer()
    {
        var header = new AdbHeader(AdbCommand.Open, 42, 7, 16, 0xCAFEBABE);
        var buf = new byte[AdbProtocolConstants.HeaderSize];
        header.WriteTo(buf);

        var decoded = AdbHeader.Read(buf);

        await Assert.That(decoded.Command).IsEqualTo(AdbCommand.Open);
        await Assert.That(decoded.Arg0).IsEqualTo(42u);
        await Assert.That(decoded.Arg1).IsEqualTo(7u);
        await Assert.That(decoded.DataLength).IsEqualTo(16u);
        await Assert.That(decoded.DataChecksum).IsEqualTo(0xCAFEBABEu);
        await Assert.That(decoded.IsMagicValid).IsTrue();
    }

    [Test]
    [Arguments(AdbCommand.Cnxn, 0x4e584e43u)]
    [Arguments(AdbCommand.Auth, 0x48545541u)]
    [Arguments(AdbCommand.Open, 0x4e45504fu)]
    [Arguments(AdbCommand.Okay, 0x59414b4fu)]
    [Arguments(AdbCommand.Clse, 0x45534c43u)]
    [Arguments(AdbCommand.Wrte, 0x45545257u)]
    public async Task CommandValuesMatchAsciiTags(AdbCommand cmd, uint expected) =>
        await Assert.That((uint)cmd).IsEqualTo(expected);

    [Test]
    public async Task MagicIsCommandXorMax()
    {
        var header = new AdbHeader(AdbCommand.Cnxn, 1, 2, 3, 4);
        await Assert.That(header.Magic).IsEqualTo((uint)AdbCommand.Cnxn ^ 0xFFFFFFFFu);
    }

    [Test]
    public async Task DecodingWithBadMagicThrows()
    {
        var buf = new byte[AdbProtocolConstants.HeaderSize];
        new AdbHeader(AdbCommand.Cnxn, 0, 0, 0, 0).WriteTo(buf);
        // Corrupt magic
        buf[20] ^= 0xFF;
        await Assert.That(() => AdbHeader.Read(buf)).ThrowsExactly<InvalidDataException>();
    }

    [Test]
    public async Task ChecksumIsSumOfBytes()
    {
        ReadOnlySpan<byte> data = [1, 2, 3, 250];
        await Assert.That(AdbHeader.ComputeChecksum(data)).IsEqualTo(256u);
    }

    [Test]
    public async Task ChecksumOnEmptyIsZero() =>
        await Assert.That(AdbHeader.ComputeChecksum(ReadOnlySpan<byte>.Empty)).IsEqualTo(0u);

    [Test]
    public async Task WriteToWithUndersizedBufferThrows()
    {
        var header = new AdbHeader(AdbCommand.Cnxn, 0, 0, 0, 0);
        var buf = new byte[AdbProtocolConstants.HeaderSize - 1];
        await Assert.That(() => header.WriteTo(buf)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task ReadWithUndersizedBufferThrows()
    {
        var buf = new byte[AdbProtocolConstants.HeaderSize - 1];
        await Assert.That(() => AdbHeader.Read(buf)).ThrowsExactly<ArgumentException>();
    }
}
