using SharpAdb.Services;

using Xunit;

namespace SharpAdb.Tests;

public class SyncProtocolTests
{
    [Fact]
    public void TagsMatchAsciiLittleEndian()
    {
        Assert.Equal('L' | ((uint)'I' << 8) | ((uint)'S' << 16) | ((uint)'T' << 24), SyncProtocol.List);
        Assert.Equal('D' | ((uint)'A' << 8) | ((uint)'T' << 16) | ((uint)'A' << 24), SyncProtocol.Data);
        Assert.Equal('D' | ((uint)'O' << 8) | ((uint)'N' << 16) | ((uint)'E' << 24), SyncProtocol.Done);
        Assert.Equal('F' | ((uint)'A' << 8) | ((uint)'I' << 16) | ((uint)'L' << 24), SyncProtocol.Fail);
    }

    [Fact]
    public void FrameHeaderRoundTrips()
    {
        Span<byte> buf = stackalloc byte[8];
        SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Send, 0xCAFE);
        var (tag, arg) = SyncProtocol.ReadFrameHeader(buf);
        Assert.Equal(SyncProtocol.Send, tag);
        Assert.Equal(0xCAFEu, arg);
    }

    [Theory]
    [InlineData(0x4000u, true, false, false)]   // dir
    [InlineData(0x8000u, false, true, false)]   // regular
    [InlineData(0xA000u, false, false, true)]   // symlink
    public void FileStatModeBits(uint mode, bool dir, bool reg, bool sym)
    {
        var s = new AdbFileStat(mode, 0, DateTimeOffset.UnixEpoch);
        Assert.Equal(dir, s.IsDirectory);
        Assert.Equal(reg, s.IsRegularFile);
        Assert.Equal(sym, s.IsSymlink);
    }
}
