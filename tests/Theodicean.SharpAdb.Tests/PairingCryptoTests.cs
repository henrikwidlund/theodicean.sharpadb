using System;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Pairing;

namespace Theodicean.SharpAdb.Tests;

public class PairingCryptoTests
{
    [Test]
    public async Task MatchingPasswordsDeriveIdenticalKeyMaterial()
    {
        var password = "123456"u8.ToArray();
        var client = new Spake2Handshake(Spake2Role.Client, password);
        var server = new Spake2Handshake(Spake2Role.Server, password);

        var clientKey = client.ProcessPeerMessage(server.Message);
        var serverKey = server.ProcessPeerMessage(client.Message);

        await Assert.That(clientKey).IsNotNull();
        await Assert.That(serverKey).IsNotNull();
        await Assert.That(clientKey).IsEquivalentTo(serverKey!);
        await Assert.That(clientKey!.Length).IsEqualTo(64);
    }

    [Test]
    public async Task MismatchedPasswordsDeriveDifferentKeyMaterial()
    {
        var client = new Spake2Handshake(Spake2Role.Client, [.. "123456"u8]);
        var server = new Spake2Handshake(Spake2Role.Server, [.. "654321"u8]);

        var clientKey = client.ProcessPeerMessage(server.Message);
        var serverKey = server.ProcessPeerMessage(client.Message);

        await Assert.That(clientKey).IsNotEquivalentTo(serverKey!);
    }

    [Test]
    public async Task ProcessPeerMessageRejectsInvalidCurvePoint()
    {
        var client = new Spake2Handshake(Spake2Role.Client, [.. "123456"u8]);
        var garbage = new byte[32];
        Array.Fill(garbage, (byte)0xFF);

        await Assert.That(client.ProcessPeerMessage(garbage)).IsNull();
    }

    [Test]
    public async Task ProcessPeerMessageCanOnlyBeCalledOnce()
    {
        var client = new Spake2Handshake(Spake2Role.Client, [.. "123456"u8]);
        var server = new Spake2Handshake(Spake2Role.Server, [.. "123456"u8]);
        client.ProcessPeerMessage(server.Message);

        await Assert.That(() => client.ProcessPeerMessage(server.Message)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CipherRoundTripsAndSequencesIndependently()
    {
        var keyMaterial = new byte[64];
        Array.Fill(keyMaterial, (byte)0x42);

        var sender = new PairingCipher(keyMaterial);
        var receiver = new PairingCipher(keyMaterial);

        var plaintext1 = "first message"u8.ToArray();
        var encrypted1 = sender.Encrypt(plaintext1);
        var decrypted1 = receiver.Decrypt(encrypted1);
        await Assert.That(decrypted1).IsEquivalentTo(plaintext1);

        var plaintext2 = "second message"u8.ToArray();
        var encrypted2 = sender.Encrypt(plaintext2);
        var decrypted2 = receiver.Decrypt(encrypted2);
        await Assert.That(decrypted2).IsEquivalentTo(plaintext2);

        // Replaying the first ciphertext against the now-advanced receiver sequence must fail:
        // the nonce for slot 0 has already been consumed, so this decrypts under nonce=1's key
        // stream and authentication must fail.
        await Assert.That(receiver.Decrypt(encrypted1)).IsNull();
    }

    [Test]
    public async Task CipherRejectsTamperedCiphertext()
    {
        var keyMaterial = new byte[64];
        Array.Fill(keyMaterial, (byte)0x7);
        var sender = new PairingCipher(keyMaterial);
        var receiver = new PairingCipher(keyMaterial);

        var encrypted = sender.Encrypt([.. "hello"u8]);
        encrypted[0] ^= 0xFF;

        await Assert.That(receiver.Decrypt(encrypted)).IsNull();
    }

    [Test]
    public async Task PeerInfoRoundTripsAndTrimsPadding()
    {
        var line = "AAAA base64keydata== fake@host\0"u8.ToArray();
        var encoded = PeerInfo.Encode(PeerInfoType.AdbRsaPublicKey, line);

        await Assert.That(encoded.Length).IsEqualTo(PeerInfo.EncodedSize);

        var (type, data) = PeerInfo.Decode(encoded);
        await Assert.That(type).IsEqualTo(PeerInfoType.AdbRsaPublicKey);
        // The payload's own trailing NUL terminator is indistinguishable from padding and is
        // trimmed along with it; callers get the line back without it.
        await Assert.That(data).IsEquivalentTo(line[..^1]);
    }

    [Test]
    public async Task PairingPacketHeaderRoundTrips()
    {
        Span<byte> buffer = stackalloc byte[PairingPacketHeader.Size];
        PairingPacketHeader.Write(buffer, PairingPacketType.PeerInfo, PeerInfo.EncodedSize);

        var ok = PairingPacketHeader.TryRead(buffer, PeerInfo.EncodedSize * 2, out var type, out var length);

        await Assert.That(ok).IsTrue();
        await Assert.That(type).IsEqualTo(PairingPacketType.PeerInfo);
        await Assert.That(length).IsEqualTo(PeerInfo.EncodedSize);
    }
}
