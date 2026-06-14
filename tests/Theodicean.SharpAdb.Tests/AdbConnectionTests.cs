using System.Security.Cryptography;
using System.Text;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Services;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb.Tests;

public class AdbConnectionTests
{
    [Test]
    public async Task HandshakeWithoutAuthSucceeds()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        // Fake device side: receive CNXN, reply CNXN.
        var deviceTask = Task.Run(async () =>
        {
            using var pkt = await deviceTransport.ReadPacketAsync();
            await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var banner = "device::ro.product.name=test;ro.product.model=Pixel\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0),
                banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        await Assert.That(conn.DeviceInfo.SystemType).IsEqualTo("device");
        await Assert.That(conn.DeviceInfo.Product).IsEqualTo("test");
        await Assert.That(conn.DeviceInfo.Model).IsEqualTo("Pixel");
    }

    [Test]
    public async Task HandshakeWithAuthChallengeAndSignature()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);
        using var key = AdbAuthKey.Generate();

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var token = RandomNumberGenerator.GetBytes(AdbProtocolConstants.AuthTokenSize);
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.Token, 0, (uint)token.Length, 0), token);

            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Auth);
                await Assert.That(pkt.Header.Arg0).IsEqualTo((uint)AdbAuthType.Signature);

                using var pub = RSA.Create();
                pub.ImportFromPem(key.ExportPrivateKeyPem());
                await Assert.That(pub.VerifyHash(token, pkt.PayloadSpan.ToArray(),
                    HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)).IsTrue();
            }

            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0),
                banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [key], new AdbConnectOptions());
        await deviceTask;
    }

    [Test]
    public async Task OpenStreamRoundTripsData()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0), banner);

            // Expect OPEN.
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                await Assert.That(Encoding.UTF8.GetString(pkt.PayloadSpan)).IsEqualTo("shell:echo hi\0");
                clientLocalId = pkt.Header.Arg0;
            }

            const uint deviceLocalId = 9999;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            var payload = "hi\n"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalId, clientLocalId, (uint)payload.Length, 0), payload);

            // Expect OKAY ack.
            using (var ack = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(ack.Header.Command).IsEqualTo(AdbCommand.Okay);
                await Assert.That(ack.Header.Arg0).IsEqualTo(clientLocalId);
                await Assert.That(ack.Header.Arg1).IsEqualTo(deviceLocalId);
            }

            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Clse, deviceLocalId, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        var output = await conn.ExecuteAsync("echo hi");
        await deviceTask;
        await Assert.That(output).IsEqualTo("hi\n");
    }

    [Test]
    public async Task ReadLoopFaultPropagatesToOpenStreams()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        // Bring connection up.
        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload, (uint)banner.Length, 0), banner);

            // Accept the OPEN, then send a malformed packet to fault the read loop.
            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
                clientLocalId = pkt.Header.Arg0;
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, 1234, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Send a packet whose DataLength exceeds MaxPayload — transport should throw InvalidDataException.
            var hdr = new byte[AdbProtocolConstants.HeaderSize];
            new AdbHeader(AdbCommand.Wrte, 1234, clientLocalId, AdbProtocolConstants.MaxPayload + 1, 0).WriteTo(hdr);
            await deviceStream.WriteAsync(hdr);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var stream = await conn.OpenAsync("shell:cat");
        await deviceTask;

        // Pending read on the stream should observe the fault (or 0/EOF) once the loop dies.
        var buf = new byte[1024];
        Exception? ex = null;
        try
        {
            var read = await stream.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(2));
            // If we got here, a graceful close happened — accept 0 too.
            await Assert.That(read).IsZero();
        }
        catch (Exception e)
        {
            ex = e;
        }

        // Either a fault propagated (exception from pipe) or graceful EOF (0 bytes). Both acceptable.
        await Assert.That(ex is null or InvalidDataException or IOException).IsTrue();

        // Subsequent OpenAsync must surface the recorded fault.
        await Assert.That(conn.FaultException).IsNotNull();
        await Assert.That(async () => await conn.OpenAsync("shell:noop")).ThrowsExactly<IOException>();
    }

    [Test]
    public async Task MidSessionAuthFaultsConnection()
    {
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        // Bring connection up with a no-auth handshake.
        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            // After the handshake the device sends an unsolicited AUTH packet, which is illegal
            // in the middle of a live session and must cause the read loop to fault.
            var token = new byte[AdbProtocolConstants.AuthTokenSize];
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.Token, 0, (uint)token.Length, 0), token);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        // Wait briefly for the read loop to ingest the bad packet and fault.
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (conn.FaultException is null && DateTime.UtcNow < deadline)
            await Task.Delay(20);

        await Assert.That(conn.FaultException).IsNotNull();
        await Assert.That(conn.FaultException).IsTypeOf<InvalidDataException>();

        // Subsequent OpenAsync must surface the recorded fault rather than hanging.
        await Assert.That(async () => await conn.OpenAsync("shell:noop")).ThrowsExactly<IOException>();
    }

    [Test]
    public async Task DispatchAfterStreamDisposeDoesNotFaultReadLoop()
    {
        // Regression: if a packet for a stream is in flight on the read loop at the moment the
        // user disposes the stream, OnAck()/OnOpened() must not throw ObjectDisposedException
        // from the torn-down SemaphoreSlim — that would escape the demuxer and fault the entire
        // connection (and with it every sibling stream).
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);

            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                clientLocalId = pkt.Header.Arg0;
            }

            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, 4242, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        var stream = await conn.OpenAsync("shell:race");
        await deviceTask;

        // Sync dispose tears down the SemaphoreSlim deterministically (synchronous removal from
        // the connection's stream map plus immediate _writeAck.Dispose()).
        await stream.DisposeAsync();

        // Simulate the race window: a packet snapshot captured a reference to the stream just
        // before TryRemove ran. The dispatcher would then call OnAck()/OnOpened() on it. After
        // the fix, both calls swallow the resulting ObjectDisposedException.
        stream.OnAck();
        stream.OnOpened(9999);

        // Connection must still be healthy.
        await Assert.That(conn.FaultException).IsNull();
    }

    [Test]
    public async Task SlowConsumerOnOneStreamDoesNotBlockAnother()
    {
        // Regression for the per-stream drain refactor (the demux-deadlock fix). With the old
        // implementation the connection-wide read loop awaited Pipe.WriteAsync per WRTE, so a
        // stream whose consumer never read would block ALL inbound dispatch — including OKAYs
        // and WRTEs for sibling streams. With the new drain-per-stream design that head-of-line
        // block is gone: stream A may stall but stream B keeps making progress.
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        uint clientLocalIdA;
        uint clientLocalIdB;
        const uint deviceLocalIdA = 1111;
        const uint deviceLocalIdB = 2222;

        var setupComplete = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                clientLocalIdA = pkt.Header.Arg0;
            }
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalIdA, clientLocalIdA, 0, 0), ReadOnlyMemory<byte>.Empty);

            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                clientLocalIdB = pkt.Header.Arg0;
            }
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, deviceLocalIdB, clientLocalIdB, 0, 0), ReadOnlyMemory<byte>.Empty);

            // Push a WRTE to A whose size exceeds the inbound Pipe's default PauseWriterThreshold
            // (64 KiB). Under the old code the dispatcher would await Pipe.WriteAsync here and
            // block forever — the test consumer never reads from A — wedging the read loop and
            // every sibling stream with it.
            var payloadA = new byte[128 * 1024];
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalIdA, clientLocalIdA, (uint)payloadA.Length, 0), payloadA);

            var payloadB = "hello from B"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Wrte, deviceLocalIdB, clientLocalIdB, (uint)payloadB.Length, 0), payloadB);

            setupComplete.SetResult(true);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await using var streamA = await conn.OpenAsync("shell:slow");
        await using var streamB = await conn.OpenAsync("shell:fast");
        await setupComplete.Task.WaitAsync(TimeSpan.FromSeconds(2));

        // Read from B with a short timeout. If A were head-of-line blocking the demuxer, this
        // would never complete.
        var buf = new byte[64];
        var n = await streamB.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(Encoding.UTF8.GetString(buf, 0, n)).IsEqualTo("hello from B");

        // Connection must still be healthy.
        await Assert.That(conn.FaultException).IsNull();

        await deviceTask.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Test]
    public async Task DeviceWrteLargerThanAdvertisedFaultsConnection()
    {
        // Regression for the inbound-cap fix: a peer must not be allowed to send a payload
        // larger than we advertised in CNXN. The transport's MaxInboundPayload is plumbed from
        // AdbConnectOptions.MaxPayload, so a WRTE above that should fault the read loop.
        const uint advertisedMax = 64 * 1024;

        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, AdbProtocolConstants.MaxPayload,
                    (uint)banner.Length, 0), banner);

            uint clientLocalId;
            using (var pkt = await deviceTransport.ReadPacketAsync())
            {
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Open);
                clientLocalId = pkt.Header.Arg0;
            }
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Okay, 4321, clientLocalId, 0, 0), ReadOnlyMemory<byte>.Empty);

            // DataLength one byte over what we advertised. Transport rejects this without
            // attempting to allocate the payload buffer.
            var hdr = new byte[AdbProtocolConstants.HeaderSize];
            new AdbHeader(AdbCommand.Wrte, 4321, clientLocalId, advertisedMax + 1, 0).WriteTo(hdr);
            await deviceStream.WriteAsync(hdr);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [],
            new AdbConnectOptions { MaxPayload = advertisedMax });
        await using var stream = await conn.OpenAsync("shell:cat");
        await deviceTask;

        // Wait briefly for the read loop to ingest the oversize header and fault.
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (conn.FaultException is null && DateTime.UtcNow < deadline)
            await Task.Delay(20);

        await Assert.That(conn.FaultException).IsNotNull();
        await Assert.That(conn.FaultException).IsTypeOf<InvalidDataException>();
    }

    [Test]
    public async Task DeviceAdvertisedZeroMaxPayloadClampedToFloor()
    {
        // Regression for the negotiated-min clamp: a broken device advertising max_data=0 must
        // not produce a zero-length write chunk that loops forever in WriteAsync. Clamp up to
        // AdbProtocolConstants.MinPayload.
        (Stream clientStream, Stream deviceStream) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);
        await using var deviceTransport = new StreamAdbTransport(deviceStream);

        var deviceTask = Task.Run(async () =>
        {
            using (var pkt = await deviceTransport.ReadPacketAsync())
                await Assert.That(pkt.Header.Command).IsEqualTo(AdbCommand.Cnxn);
            var banner = "device::\0"u8.ToArray();
            await deviceTransport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, /* Arg1 = max_data */ 0,
                    (uint)banner.Length, 0), banner);
        });

        await using var conn = await AdbConnection.ConnectAsync(clientTransport, [], new AdbConnectOptions());
        await deviceTask;

        await Assert.That(conn.MaxPayload).IsGreaterThanOrEqualTo(AdbProtocolConstants.MinPayload);
    }

    [Test]
    public async Task VerifyChecksumWithoutWriteChecksumThrows()
    {
        (Stream clientStream, Stream _) = CreateDuplexPair();
        var clientTransport = new StreamAdbTransport(clientStream);

        await Assert.That(async () => await AdbConnection.ConnectAsync(
            clientTransport, [],
            new AdbConnectOptions { VerifyChecksum = true, WriteChecksum = false })).ThrowsExactly<ArgumentException>();
    }

    private static (Stream A, Stream B) CreateDuplexPair()
    {
        var aToB = new BlockingMemoryStream();
        var bToA = new BlockingMemoryStream();
        return (new DuplexStream(bToA, aToB), new DuplexStream(aToB, bToA));
    }
}
