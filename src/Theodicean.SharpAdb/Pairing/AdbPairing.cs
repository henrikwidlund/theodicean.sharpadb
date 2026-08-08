using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Theodicean.SharpAdb.Auth;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>
/// Result of a successful pairing exchange: the identity the device sent back, encrypted, once
/// the SPAKE2 password check succeeded.
/// </summary>
/// <param name="PeerInfoType">What kind of identity <paramref name="PeerInfoData"/> contains.</param>
/// <param name="PeerInfoData">
/// The device's identity payload, trailing NUL/padding trimmed. For <see cref="Pairing.PeerInfoType.AdbRsaPublicKey"/>
/// this is the same "<c>&lt;base64 mincrypt key&gt; user@host</c>" text used in normal ADB AUTH.
/// </param>
// ReSharper disable once NotAccessedPositionalProperty.Global
public sealed record AdbPairingResult(in PeerInfoType PeerInfoType, byte[] PeerInfoData);

/// <summary>
/// Thrown when the wireless-pairing handshake fails for reasons specific to the pairing protocol
/// itself (as opposed to a lower-level socket/TLS/IO failure, which surfaces as the underlying
/// exception type).
/// </summary>
public sealed class AdbPairingException : Exception
{
    /// <summary>Initializes a new instance with the given diagnostic message.</summary>
    public AdbPairingException(string message) : base(message) { }
}

/// <summary>
/// Android 11+ wireless-debugging pairing: the one-shot 6-digit-code exchange shown under
/// Developer Options → Wireless debugging → "Pair device with pairing code" (equivalent to
/// <c>adb pair host:port</c>). Successful pairing causes the device to trust the supplied key
/// for later ADB-over-Wi-Fi connections — it does not itself open an <see cref="AdbConnection"/>.
/// </summary>
public static class AdbPairing
{
    internal const string ExportedKeyingMaterialLabel = "adb-label\0";
    internal const int ExportedKeyingMaterialLength = 64;

    /// <summary>
    /// Connects to <paramref name="host"/>:<paramref name="port"/> (the address and port shown on
    /// the device's pairing screen) and completes
    /// the SPAKE2-authenticated pairing exchange using <paramref name="pairingCode"/>.
    /// </summary>
    /// <param name="host">DNS name or IP of the device.</param>
    /// <param name="port">The pairing service port shown on the device's pairing screen.</param>
    /// <param name="pairingCode">The 6-digit code shown on the device's pairing screen.</param>
    /// <param name="key">
    /// The key to authorize for future connections. Its self-signed certificate is presented as
    /// the TLS client certificate; its mincrypt-encoded public key is sent as this side's <see cref="PeerInfo"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation for the connect and pairing exchange.</param>
    /// <exception cref="AdbPairingException">The pairing code did not match what the device expects.</exception>
    /// <remarks>This method does not perform mDNS discovery.</remarks>
    public static async Task<AdbPairingResult> PairAsync(
        string host, int port, string pairingCode, AdbAuthKey key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(key);
        ValidatePairingCode(pairingCode);

        // Fail fast, before touching the network: PeerInfo has a fixed 8191-byte data budget, and
        // an unusually long userHost on the key could blow past it. This limit is specific to
        // pairing's fixed-size PeerInfo buffer — normal AUTH has no equivalent cap — so it's
        // validated here rather than unconditionally in AdbAuthKey, which normal AUTH users
        // shouldn't be constrained by.
        var ourPublicKeyLine = key.EncodeAndroidPublicKey();
        if (ourPublicKeyLine.Length > PeerInfo.EncodedSize - 1)
            throw new ArgumentException(
                $"The key's encoded public key line is {ourPublicKeyLine.Length} bytes, but a pairing " +
                $"PeerInfo can hold at most {PeerInfo.EncodedSize - 1} bytes. Use a shorter userHost.",
                nameof(key));

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(host, port, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
        socket.NoDelay = true;

        await using var networkStream = new NetworkStream(socket, ownsSocket: true);

        // BC-TLS's TLS 1.3 client is fully synchronous — both the handshake (Connect) and the
        // post-handshake record-layer Stream are blocking APIs with no async variant. There is
        // also no way to hand off to SslStream once BC-TLS holds the session: SslStream never
        // exposes its session secrets to managed code, so the exported keying material this
        // protocol needs is only reachable if BC-TLS runs the *entire* connection, not just the
        // exporter call. Consequently the only way `cancellationToken` can do anything for the
        // rest of this method is by tearing down the socket a blocked call is stuck on.
        await using var cancellationRegistration = cancellationToken.Register(static s => ((Socket)s!).Dispose(), socket);

        using var certificate = key.CreateSelfSignedCertificate();
        var certificateDer = certificate.Export(X509ContentType.Cert);
        var privateKey = AdbPairingTlsClient.ToBouncyCastleKey(key.Rsa.ExportParameters(includePrivateParameters: true));

        var tlsClient = new AdbPairingTlsClient(privateKey, certificateDer);
        var protocol = new Org.BouncyCastle.Tls.TlsClientProtocol(networkStream);

        try
        {
            await Task.Run(() => protocol.Connect(tlsClient), cancellationToken).ConfigureAwait(false);

            var exportedKeyMaterial = tlsClient.ExportedKeyingMaterial;

            var codeBytes = Encoding.ASCII.GetBytes(pairingCode);
            var password = new byte[codeBytes.Length + exportedKeyMaterial.Length];
            codeBytes.CopyTo(password, 0);
            exportedKeyMaterial.CopyTo(password, codeBytes.Length);

            var spake2 = new Spake2Handshake(Spake2Role.Client, password);
            var tlsStream = protocol.Stream;

            await WritePacketAsync(tlsStream, PairingPacketType.Spake2Msg, spake2.Message, cancellationToken);
            var (theirSpakeType, theirSpakeMsg) = await ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, cancellationToken);
            if (theirSpakeType != PairingPacketType.Spake2Msg)
                throw new IOException($"Expected a SPAKE2_MSG packet, got {theirSpakeType}");

            var keyMaterial = spake2.ProcessPeerMessage(theirSpakeMsg)
                ?? throw new AdbPairingException("The device's SPAKE2 message was not a valid curve point.");
            var cipher = new PairingCipher(keyMaterial);

            var ourPeerInfo = PeerInfo.Encode(PeerInfoType.AdbRsaPublicKey, ourPublicKeyLine);
            await WritePacketAsync(tlsStream, PairingPacketType.PeerInfo, cipher.Encrypt(ourPeerInfo), cancellationToken);

            var (theirPeerInfoType, encryptedTheirPeerInfo) = await ReadPacketAsync(tlsStream, PeerInfo.EncodedSize * 2, cancellationToken);
            if (theirPeerInfoType != PairingPacketType.PeerInfo)
                throw new IOException($"Expected a PEER_INFO packet, got {theirPeerInfoType}");

            var decrypted = cipher.Decrypt(encryptedTheirPeerInfo)
                // A decrypt failure here (rather than during the SPAKE2 exchange itself) is how a
                // password mismatch actually surfaces: SPAKE2 always "succeeds" and produces *some*
                // shared key material, valid curve point or not — only the AEAD tag check downstream
                // reveals whether both sides actually used the same pairing code.
                ?? throw new AdbPairingException("Failed to decrypt the device's PeerInfo — the pairing code does not match.");

            if (decrypted.Length != PeerInfo.EncodedSize)
                throw new IOException($"Decrypted PeerInfo had unexpected size {decrypted.Length} (expected {PeerInfo.EncodedSize})");

            var (type, data) = PeerInfo.Decode(decrypted);
            return new AdbPairingResult(type, data);
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && ex is not OperationCanceledException)
        {
            // The socket-dispose-on-cancel above surfaces as ObjectDisposedException/IOException
            // from whichever blocked call it interrupted, not as OperationCanceledException —
            // translate it so callers can rely on the normal cancellation contract.
            throw new OperationCanceledException("Pairing was canceled.", ex, cancellationToken);
        }
        finally
        {
            // Best-effort close_notify. The socket is torn down right after this regardless
            // (networkStream/socket disposal below), so a failure here — the peer already gone,
            // cancellation having just disposed the socket, etc. — has nothing left to protect.
            try
            {
                protocol.Close();
            }
            catch
            {
                // Ignore
            }
        }
    }

    private static void ValidatePairingCode(string pairingCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pairingCode);
        if (pairingCode.Length != 6)
            throw new ArgumentException("Pairing code must be exactly 6 digits.", nameof(pairingCode));

        if (pairingCode.Any(static c => !char.IsAsciiDigit(c)))
            throw new ArgumentException("Pairing code must only contain digits.", nameof(pairingCode));
    }

    // Internal (not private) so the test suite can drive the same framing against a hand-rolled
    // server counterpart without duplicating — and risking silently diverging from — this logic.
    internal static async Task WritePacketAsync(Stream stream, PairingPacketType type, byte[] payload, CancellationToken cancellationToken)
    {
        var header = new byte[PairingPacketHeader.Size];
        PairingPacketHeader.Write(header, type, payload.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
    }

    internal static async Task<(PairingPacketType Type, byte[] Payload)> ReadPacketAsync(
        Stream stream, int maxPayloadSize, CancellationToken cancellationToken)
    {
        var header = new byte[PairingPacketHeader.Size];
        await stream.ReadExactlyAsync(header, cancellationToken);
        if (!PairingPacketHeader.TryRead(header, maxPayloadSize, out var type, out var payloadLength))
            throw new IOException("Invalid PairingPacketHeader received from the device.");

        var payload = new byte[payloadLength];
        await stream.ReadExactlyAsync(payload, cancellationToken);
        return (type, payload);
    }
}
