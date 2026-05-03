using SharpAdb.Protocol;
using Xunit;

namespace SharpAdb.Tests;

public class AdbHeaderTests
{
    [Fact]
    public void RoundTripsThroughBuffer()
    {
        var header = new AdbHeader(AdbCommand.Open, 42, 7, 16, 0xCAFEBABE);
        Span<byte> buf = stackalloc byte[AdbProtocolConstants.HeaderSize];
        header.WriteTo(buf);

        var decoded = AdbHeader.Read(buf);

        Assert.Equal(AdbCommand.Open, decoded.Command);
        Assert.Equal(42u, decoded.Arg0);
        Assert.Equal(7u, decoded.Arg1);
        Assert.Equal(16u, decoded.DataLength);
        Assert.Equal(0xCAFEBABEu, decoded.DataChecksum);
        Assert.True(decoded.IsMagicValid);
    }

    [Theory]
    [InlineData(AdbCommand.Cnxn, 0x4e584e43u)]
    [InlineData(AdbCommand.Auth, 0x48545541u)]
    [InlineData(AdbCommand.Open, 0x4e45504fu)]
    [InlineData(AdbCommand.Okay, 0x59414b4fu)]
    [InlineData(AdbCommand.Clse, 0x45534c43u)]
    [InlineData(AdbCommand.Wrte, 0x45545257u)]
    public void CommandValuesMatchAsciiTags(AdbCommand cmd, uint expected) =>
        Assert.Equal(expected, (uint)cmd);

    [Fact]
    public void MagicIsCommandXorMax()
    {
        var header = new AdbHeader(AdbCommand.Cnxn, 1, 2, 3, 4);
        Assert.Equal((uint)AdbCommand.Cnxn ^ 0xFFFFFFFFu, header.Magic);
    }

    [Fact]
    public void DecodingWithBadMagicThrows()
    {
        Span<byte> buf = stackalloc byte[AdbProtocolConstants.HeaderSize];
        new AdbHeader(AdbCommand.Cnxn, 0, 0, 0, 0).WriteTo(buf);
        // Corrupt magic
        buf[20] ^= 0xFF;
        var arr = buf.ToArray();
        Assert.Throws<InvalidDataException>(() => AdbHeader.Read(arr));
    }

    [Fact]
    public void ChecksumIsSumOfBytes()
    {
        ReadOnlySpan<byte> data = [1, 2, 3, 250];
        Assert.Equal(256u, AdbHeader.ComputeChecksum(data));
    }

    [Fact]
    public void ChecksumOnEmptyIsZero() =>
        Assert.Equal(0u, AdbHeader.ComputeChecksum(ReadOnlySpan<byte>.Empty));
}
