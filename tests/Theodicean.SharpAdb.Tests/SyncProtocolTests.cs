using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.Tests;

public class SyncProtocolTests
{
    [Test]
    public async Task TagsMatchAsciiLittleEndian()
    {
        await Assert.That(BitConverter.ToUInt32("LIST"u8)).IsEqualTo(SyncProtocol.List);
        await Assert.That(BitConverter.ToUInt32("DATA"u8)).IsEqualTo(SyncProtocol.Data);
        await Assert.That(BitConverter.ToUInt32("DONE"u8)).IsEqualTo(SyncProtocol.Done);
        await Assert.That(BitConverter.ToUInt32("FAIL"u8)).IsEqualTo(SyncProtocol.Fail);
    }

    [Test]
    public async Task FrameHeaderRoundTrips()
    {
        var buf = new byte[8];
        SyncProtocol.WriteFrameHeader(buf, SyncProtocol.Send, 0xCAFE);
        (uint tag, uint arg) = SyncProtocol.ReadFrameHeader(buf);
        await Assert.That(tag).IsEqualTo(SyncProtocol.Send);
        await Assert.That(arg).IsEqualTo(0xCAFEu);
    }

    [Test]
    [Arguments(0x4000u, true, false, false)]   // dir
    [Arguments(0x8000u, false, true, false)]   // regular
    [Arguments(0xA000u, false, false, true)]   // symlink
    public async Task FileStatModeBits(uint mode, bool dir, bool reg, bool sym)
    {
        var s = new AdbFileStat(mode, 0, DateTimeOffset.UnixEpoch);
        await Assert.That(s.IsDirectory).IsEqualTo(dir);
        await Assert.That(s.IsRegularFile).IsEqualTo(reg);
        await Assert.That(s.IsSymlink).IsEqualTo(sym);
    }
}
