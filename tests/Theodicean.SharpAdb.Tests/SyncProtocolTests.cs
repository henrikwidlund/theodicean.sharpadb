using System;
using System.Buffers.Binary;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.Tests;

public class SyncProtocolTests
{
    [Test]
    public async Task TagsMatchAsciiLittleEndian()
    {
        // Use BinaryPrimitives.ReadUInt32LittleEndian instead of BitConverter.ToUInt32 — the
        // latter reads in host byte order, which would silently flip on a big-endian runtime.
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("LIS2"u8)).IsEqualTo(SyncProtocol.ListV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("DNT2"u8)).IsEqualTo(SyncProtocol.DentV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("STA2"u8)).IsEqualTo(SyncProtocol.StatV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("LST2"u8)).IsEqualTo(SyncProtocol.LStatV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("SND2"u8)).IsEqualTo(SyncProtocol.SendV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("RCV2"u8)).IsEqualTo(SyncProtocol.RecvV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("DATA"u8)).IsEqualTo(SyncProtocol.Data);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("DONE"u8)).IsEqualTo(SyncProtocol.Done);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("OKAY"u8)).IsEqualTo(SyncProtocol.Okay);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("FAIL"u8)).IsEqualTo(SyncProtocol.Fail);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian("QUIT"u8)).IsEqualTo(SyncProtocol.Quit);
    }

    [Test]
    public async Task FrameHeaderRoundTrips()
    {
        var buf = new byte[8];
        SyncProtocol.WriteFrameHeader(buf, SyncProtocol.SendV2, 0xCAFE);
        (uint tag, uint arg) = SyncProtocol.ReadFrameHeader(buf);
        await Assert.That(tag).IsEqualTo(SyncProtocol.SendV2);
        await Assert.That(arg).IsEqualTo(0xCAFEu);
    }

    [Test]
    [Arguments(0x4000u, true, false, false)]   // dir
    [Arguments(0x8000u, false, true, false)]   // regular
    [Arguments(0xA000u, false, false, true)]   // symlink
    public async Task FileStatModeBits(uint mode, bool dir, bool reg, bool sym)
    {
        var s = new AdbFileStat(
            Mode: mode,
            Size: 0,
            ModifiedTime: DateTimeOffset.UnixEpoch,
            AccessedTime: DateTimeOffset.UnixEpoch,
            ChangedTime: DateTimeOffset.UnixEpoch,
            Uid: 0,
            Gid: 0,
            Nlink: 0,
            Inode: 0,
            Device: 0,
            Error: 0);
        await Assert.That(s.IsDirectory).IsEqualTo(dir);
        await Assert.That(s.IsRegularFile).IsEqualTo(reg);
        await Assert.That(s.IsSymlink).IsEqualTo(sym);
    }

    [Test]
    public async Task FileStatExistsRequiresModeAndZeroErrno()
    {
        var ok = new AdbFileStat(0x8000, 1, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch, 0, 0, 1, 1, 1, Error: 0);
        var missing = new AdbFileStat(0, 0, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch, 0, 0, 0, 0, 0, Error: 2);

        await Assert.That(ok.Exists).IsTrue();
        await Assert.That(missing.Exists).IsFalse();
    }

    [Test]
    public async Task WriteFrameHeaderUndersizedBufferThrows()
    {
        var buf = new byte[SyncProtocol.FrameHeaderSize - 1];
        await Assert.That(() => SyncProtocol.WriteFrameHeader(buf, SyncProtocol.SendV2, 0)).ThrowsExactly<ArgumentOutOfRangeException>();
    }
}
