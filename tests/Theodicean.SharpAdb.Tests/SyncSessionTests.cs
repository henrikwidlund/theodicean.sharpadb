using System.Buffers.Binary;
using System.Text;

using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Services;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class SyncSessionTests
{
    [Test]
    public async Task OpenAsyncRejectsDeviceWithoutSendRecvV2Feature()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = RunHandshakeAsync(deviceTransport, features: "shell_v2");

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        await Assert.That(async () => await SyncSession.OpenAsync(conn))
            .ThrowsExactly<NotSupportedException>();
    }

    [Test]
    public async Task OpenAsyncOpensSyncServiceWhenFeaturePresent()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var observedService = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        var deviceTask = Task.Run(async () =>
        {
            await RunHandshakeAsync(deviceTransport, features: "shell_v2,sendrecv_v2");
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                observedService.SetResult(Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0'));
                clientLocalId = pkt.Header.Arg0;
            }

            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, 7777, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var sync = await SyncSession.OpenAsync(conn);
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        await Assert.That(await observedService.Task).IsEqualTo("sync:");
    }

    [Test]
    public async Task StatAsyncSendsLst2AndParsesReply()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var observedRequest = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var fixedMtime = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var fixedAtime = DateTimeOffset.FromUnixTimeSeconds(1_699_000_000);
        var fixedCtime = DateTimeOffset.FromUnixTimeSeconds(1_700_500_000);

        const uint deviceLocalId = 5555;

        var deviceTask = Task.Run(async () =>
        {
            try
            {
                var clientLocalId = await OpenSyncStreamAsync(deviceTransport, deviceLocalId);

                // Read the LST2 + namelen + path frame from one or more WRTE packets.
                var req = await ReadStreamFrameAsync(deviceTransport, deviceLocalId, clientLocalId, minBytes: 8);
                observedRequest.SetResult(req);

                // Build LST2 reply: tag(4) + payload(68).
                var reply = new byte[72];
                BinaryPrimitives.WriteUInt32LittleEndian(reply, SyncProtocol.LStatV2);
                // error(4)=0, dev(8)=4660, ino(8)=22136, mode(4)=0x81A4 regular 0o644,
                // nlink(4)=1, uid(4)=1000, gid(4)=1001, size(8)=0x0123_4567_89AB_CDEF,
                // atime(8)/mtime(8)/ctime(8).
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4), 0);
                BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(8), 4660UL);
                BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(16), 22136UL);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(24), 0x81A4);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(28), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(32), 1000);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(36), 1001);
                BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(40), 0x0123_4567_89AB_CDEFUL);
                BinaryPrimitives.WriteInt64LittleEndian(reply.AsSpan(48), fixedAtime.ToUnixTimeSeconds());
                BinaryPrimitives.WriteInt64LittleEndian(reply.AsSpan(56), fixedMtime.ToUnixTimeSeconds());
                BinaryPrimitives.WriteInt64LittleEndian(reply.AsSpan(64), fixedCtime.ToUnixTimeSeconds());

                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)reply.Length, 0), reply);

                using var ack = await deviceTransport.ReadPacketAsync();
                await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);
            }
            catch (Exception ex)
            {
                observedRequest.TrySetException(ex);
                throw;
            }
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var sync = await SyncSession.OpenAsync(conn);
        var stat = await sync.StatAsync("/sdcard/foo");
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        var req = await observedRequest.Task;
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(req)).IsEqualTo(SyncProtocol.LStatV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(req.AsSpan(4))).IsEqualTo((uint)"/sdcard/foo"u8.Length);
        await Assert.That(Encoding.UTF8.GetString(req.AsSpan(8))).IsEqualTo("/sdcard/foo");

        await Assert.That(stat.Exists).IsTrue();
        await Assert.That(stat.IsRegularFile).IsTrue();
        await Assert.That(stat.Mode).IsEqualTo(0x81A4u);
        await Assert.That(stat.Size).IsEqualTo(0x0123_4567_89AB_CDEFUL);
        await Assert.That(stat.Uid).IsEqualTo(1000u);
        await Assert.That(stat.Gid).IsEqualTo(1001u);
        await Assert.That(stat.Nlink).IsEqualTo(1u);
        await Assert.That(stat.Inode).IsEqualTo(22136UL);
        await Assert.That(stat.Device).IsEqualTo(4660UL);
        await Assert.That(stat.Error).IsEqualTo(0u);
        await Assert.That(stat.ModifiedTime).IsEqualTo(fixedMtime);
        await Assert.That(stat.AccessedTime).IsEqualTo(fixedAtime);
        await Assert.That(stat.ChangedTime).IsEqualTo(fixedCtime);
    }

    [Test]
    public async Task ListAsyncParsesMultipleDnt2EntriesThenDone()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        const uint deviceLocalId = 6000;

        var deviceTask = Task.Run(async () =>
        {
            var clientLocalId = await OpenSyncStreamAsync(deviceTransport, deviceLocalId);

            // Drain the LIS2 request.
            _ = await ReadStreamFrameAsync(deviceTransport, deviceLocalId, clientLocalId, minBytes: 8);

            // Two entries: "alpha" (regular), "beta" (dir), then DONE.
            var payload = new MemoryStream();
            WriteDent(payload, "alpha", mode: 0x81A4, size: 100);
            WriteDent(payload, "beta", mode: 0x41ED, size: 0);
            WriteDoneTerminator(payload);

            var arr = payload.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)arr.Length, 0), arr);
            using var ack = await deviceTransport.ReadPacketAsync();
            await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var sync = await SyncSession.OpenAsync(conn);

        var entries = new List<AdbDirectoryEntry>();
        await foreach (var e in sync.ListAsync("/sdcard"))
            entries.Add(e);

        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        await Assert.That(entries.Count).IsEqualTo(2);
        await Assert.That(entries[0].Name).IsEqualTo("alpha");
        await Assert.That(entries[0].IsRegularFile).IsTrue();
        await Assert.That(entries[0].Size).IsEqualTo(100UL);
        await Assert.That(entries[1].Name).IsEqualTo("beta");
        await Assert.That(entries[1].IsDirectory).IsTrue();
    }

    [Test]
    public async Task PullAsyncSendsRecvV2MetadataAndCollectsDataChunks()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        const uint deviceLocalId = 6100;
        var observedRecvMeta = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        var deviceTask = Task.Run(async () =>
        {
            try
            {
                var clientLocalId = await OpenSyncStreamAsync(deviceTransport, deviceLocalId);

                // Expect: RCV2 + namelen(4) + path, then sync_recv_v2 (8 bytes: id + flags).
                var pathFrame = await ReadStreamFrameAsync(deviceTransport, deviceLocalId, clientLocalId, minBytes: 8);
                await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(pathFrame)).IsEqualTo(SyncProtocol.RecvV2);
                var pathLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(pathFrame.AsSpan(4));
                // Path frame and meta frame might arrive in same or separate WRTEs. Drain whatever
                // is left in pathFrame past the path itself, then top up to 8 bytes of metadata.
                var totalAfterCmd = pathFrame.Length - (8 + pathLen);
                var collected = new MemoryStream();
                if (totalAfterCmd > 0)
                    collected.Write(pathFrame.AsSpan(8 + pathLen));
                while (collected.Length < 8)
                {
                    var more = await ReadStreamFrameAsync(deviceTransport, deviceLocalId, clientLocalId, minBytes: 1);
                    collected.Write(more);
                }
                observedRecvMeta.SetResult(collected.ToArray()[..8]);

                // Reply with two DATA frames + DONE.
                var data1 = Enumerable.Range(0, 128).Select(static i => (byte)i).ToArray();
                var data2 = Enumerable.Range(0, 64).Select(static i => (byte)(i + 200)).ToArray();
                var payload = new MemoryStream();
                WriteFrame(payload, SyncProtocol.Data, data1);
                WriteFrame(payload, SyncProtocol.Data, data2);
                WriteFrame(payload, SyncProtocol.Done, []);

                var arr = payload.ToArray();
                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)arr.Length, 0), arr);
                using var ack = await deviceTransport.ReadPacketAsync();
                await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);
            }
            catch (Exception ex)
            {
                observedRecvMeta.TrySetException(ex);
                throw;
            }
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var sync = await SyncSession.OpenAsync(conn);
        using var dest = new MemoryStream();
        await sync.PullAsync("/sdcard/foo", dest);
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        var meta = await observedRecvMeta.Task;
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(meta)).IsEqualTo(SyncProtocol.RecvV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(4))).IsEqualTo(0u); // flags=None
        await Assert.That(dest.Length).IsEqualTo(128L + 64L);
    }

    [Test]
    public async Task PushAsyncSendsSendV2MetadataDataChunksAndDone()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        const uint deviceLocalId = 6200;
        var observedSendMeta = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var observedPayload = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        var sourceBytes = Enumerable.Range(0, 300).Select(static i => (byte)i).ToArray();

        var deviceTask = Task.Run(async () =>
        {
            try
            {
                var clientLocalId = await OpenSyncStreamAsync(deviceTransport, deviceLocalId);

                // Accumulate the whole client byte stream until DONE frame seen, then build the
                // response. Avoids tracking WRTE boundaries since sync frames cross them.
                var collected = new MemoryStream();
                while (true)
                {
                    var more = await ReadStreamFrameAsync(deviceTransport, deviceLocalId, clientLocalId, minBytes: 1);
                    collected.Write(more);
                    if (TryFindDone(collected.ToArray(), out _))
                        break;
                }

                var all = collected.ToArray();
                // Layout: [SND2 + namelen + path] [SND2 meta = id+mode+flags = 12B]
                //         [DATA + len + bytes] * N [DONE + mtime]
                var pathFrameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(4));
                var afterPath = 8 + pathFrameLen;
                observedSendMeta.SetResult(all.AsSpan(afterPath, 12).ToArray());

                var dataStart = afterPath + 12;
                var payload = new MemoryStream();
                var cursor = dataStart;
                while (cursor < all.Length)
                {
                    var tag = BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(cursor));
                    var len = (int)BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(cursor + 4));
                    if (tag == SyncProtocol.Done)
                        break;
                    if (tag != SyncProtocol.Data)
                        throw new IOException($"Unexpected push frame tag: 0x{tag:X8}");
                    payload.Write(all.AsSpan(cursor + 8, len));
                    cursor += 8 + len;
                }
                observedPayload.SetResult(payload.ToArray());

                // Send final OKAY frame.
                var okBytes = new byte[8];
                SyncProtocol.WriteFrameHeader(okBytes, SyncProtocol.Okay, 0);
                await deviceTransport.WritePacketAsync(
                    new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)okBytes.Length, 0), okBytes);
                using var ack = await deviceTransport.ReadPacketAsync();
                await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);
            }
            catch (Exception ex)
            {
                observedSendMeta.TrySetException(ex);
                observedPayload.TrySetException(ex);
                throw;
            }
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var sync = await SyncSession.OpenAsync(conn);
        using var source = new MemoryStream(sourceBytes);
        await sync.PushAsync(source, "/sdcard/bar", mode: 0x1A4);
        await deviceTask.WaitAsync(TimeSpan.FromSeconds(10));

        var meta = await observedSendMeta.Task;
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(meta)).IsEqualTo(SyncProtocol.SendV2);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(4))).IsEqualTo(0x1A4u);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(8))).IsEqualTo(0u); // flags=None

        var got = await observedPayload.Task;
        await Assert.That(got).IsEquivalentTo(sourceBytes, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }

    private static bool TryFindDone(byte[] bytes, out int doneOffset)
    {
        // Walk frames from start until we either hit DONE or run out of bytes for a full frame.
        // Layout from PushAsync: [SND2 cmd + namelen + path] [12B meta] [DATA*N] [DONE].
        if (bytes.Length < 8)
        {
            doneOffset = -1;
            return false;
        }

        var pathLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4));
        var cursor = 8 + pathLen + 12;
        while (cursor + 8 <= bytes.Length)
        {
            var tag = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(cursor));
            if (tag == SyncProtocol.Done)
            {
                doneOffset = cursor;
                return true;
            }

            if (tag != SyncProtocol.Data)
            {
                doneOffset = -1;
                return false;
            }

            var len = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(cursor + 4));
            if (cursor + 8 + len > bytes.Length)
            {
                doneOffset = -1;
                return false;
            }
            cursor += 8 + len;
        }

        doneOffset = -1;
        return false;
    }

    private static void WriteFrame(MemoryStream dest, uint tag, ReadOnlySpan<byte> payload)
    {
        Span<byte> hdr = stackalloc byte[8];
        SyncProtocol.WriteFrameHeader(hdr, tag, (uint)payload.Length);
        dest.Write(hdr);
        dest.Write(payload);
    }

    private static void WriteDent(MemoryStream dest, string name, uint mode, ulong size)
    {
        // sync_dent_v2 = tag(4) + error(4) + dev(8) + ino(8) + mode(4) + nlink(4) + uid(4) + gid(4)
        //              + size(8) + atime(8) + mtime(8) + ctime(8) + namelen(4) + name
        Span<byte> hdr = stackalloc byte[76];
        BinaryPrimitives.WriteUInt32LittleEndian(hdr, SyncProtocol.DentV2);
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[4..], 0); // error
        BinaryPrimitives.WriteUInt64LittleEndian(hdr[8..], 0); // dev
        BinaryPrimitives.WriteUInt64LittleEndian(hdr[16..], 0); // ino
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[24..], mode);
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[28..], 1); // nlink
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[32..], 1000); // uid
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[36..], 1000); // gid
        BinaryPrimitives.WriteUInt64LittleEndian(hdr[40..], size);
        BinaryPrimitives.WriteInt64LittleEndian(hdr[48..], 0);
        BinaryPrimitives.WriteInt64LittleEndian(hdr[56..], 0);
        BinaryPrimitives.WriteInt64LittleEndian(hdr[64..], 0);
        var nameBytes = Encoding.UTF8.GetBytes(name);
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[72..], (uint)nameBytes.Length);
        dest.Write(hdr);
        dest.Write(nameBytes);
    }

    private static void WriteDoneTerminator(MemoryStream dest)
    {
        Span<byte> hdr = stackalloc byte[76];
        hdr.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(hdr, SyncProtocol.Done);
        dest.Write(hdr);
    }

    private static async Task RunHandshakeAsync(StreamAdbTransport deviceTransport, string features)
    {
        using (var pkt = await deviceTransport.ReadPacketAsync())
            await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

        var banner = Encoding.UTF8.GetBytes($"device::features={features}\0");
        await deviceTransport.WritePacketAsync(
            new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                (uint)banner.Length, 0), banner);
    }

    private static async Task<uint> OpenSyncStreamAsync(StreamAdbTransport deviceTransport, uint deviceLocalId)
    {
        await RunHandshakeAsync(deviceTransport, features: "shell_v2,sendrecv_v2");

        uint clientLocalId;
        using (var pkt = await deviceTransport.ReadPacketAsync())
        {
            await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
            await Assert.That(Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0')).IsEqualTo("sync:");
            clientLocalId = pkt.Header.Arg0;
        }

        await deviceTransport.WritePacketAsync(
            new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        return clientLocalId;
    }

    private static async Task<byte[]> ReadStreamFrameAsync(StreamAdbTransport deviceTransport, uint deviceLocalId,
        uint clientLocalId, int minBytes)
    {
        var acc = new MemoryStream();
        while (acc.Length < minBytes)
        {
            using var pkt = await deviceTransport.ReadPacketAsync();
            if (pkt.Header.Command != AdbCommand.Wrte)
                continue;
            acc.Write(pkt.PayloadSpan);
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        }
        return acc.ToArray();
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }
}
