using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;

using SharpAdb.Auth;
using SharpAdb.Protocol;
using SharpAdb.Transport;

namespace SharpAdb;

/// <summary>
/// Options controlling the ADB connection handshake and per-connection behavior.
/// </summary>
public sealed class AdbConnectOptions
{
    /// <summary>
    /// Identity string sent in the CNXN packet. Format: <c>host::features=...</c>.
    /// </summary>
    public string Banner { get; init; } = "host::features=shell_v2,cmd";

    /// <summary>
    /// Maximum payload size we are willing to receive. Negotiated downward against the device's value.
    /// </summary>
    public uint MaxPayload { get; init; } = AdbProtocolConstants.MaxPayload;

    /// <summary>
    /// Computes and sends the legacy sum-of-bytes checksum on outbound payloads. Modern adbd ignores it.
    /// </summary>
    public bool WriteChecksum { get; init; } = false;

    /// <summary>
    /// Verifies the legacy checksum on inbound payloads. Off by default since modern devices send 0.
    /// </summary>
    public bool VerifyChecksum { get; init; } = false;

    /// <summary>
    /// Maximum time the CNXN/AUTH handshake may take before <see cref="AdbAuthenticationException"/> is thrown.
    /// </summary>
    public TimeSpan AuthTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When all signatures are rejected by the device, send the first key's public key so the
    /// device can prompt the user to add it. Disable to fail fast in tests where you want to
    /// prove signature-based auth specifically (no on-device prompt).
    /// </summary>
    public bool SendPublicKeyOnAuthFailure { get; init; } = true;
}

/// <summary>
/// How the connection authenticated to the device.
/// </summary>
public enum AdbAuthenticationMethod
{
    /// <summary>
    /// Device did not request authentication (rare; debug builds).
    /// </summary>
    None,

    /// <summary>
    /// Device accepted a signature produced from one of the supplied keys.
    /// </summary>
    Signature,

    /// <summary>
    /// Device accepted only after the public key was sent and the user tapped "Allow".
    /// </summary>
    PublicKey,

    /// <summary>
    /// Authentication was bypassed because the TLS client cert proved key ownership.
    /// </summary>
    Tls
}

/// <summary>
/// Identifying information returned by the device in the CNXN banner.
/// </summary>
/// <param name="SystemType">Connection class string sent by the device, e.g. <c>device</c>, <c>recovery</c>, <c>bootloader</c>.</param>
/// <param name="Serial">Device serial number from the banner. Often empty over TCP.</param>
/// <param name="Banner">The full unparsed banner string for diagnostic purposes.</param>
/// <param name="Properties">Key/value pairs the device advertised after its serial (e.g. <c>ro.product.model</c>, <c>features</c>).</param>
public sealed record AdbDeviceInfo(string SystemType, string Serial, string Banner, IReadOnlyDictionary<string, string> Properties)
{
    /// <summary>
    /// Value of <c>ro.product.name</c> if present.
    /// </summary>
    public string? Product => Properties.GetValueOrDefault("ro.product.name");

    /// <summary>
    /// Value of <c>ro.product.model</c> if present.
    /// </summary>
    public string? Model => Properties.GetValueOrDefault("ro.product.model");

    /// <summary>
    /// Value of <c>ro.product.device</c> if present.
    /// </summary>
    public string? Device => Properties.GetValueOrDefault("ro.product.device");

    /// <summary>
    /// Set of feature flags advertised by the device (parsed from the comma-separated <c>features</c> property).
    /// </summary>
    public IReadOnlySet<string> Features => Properties.TryGetValue("features", out var v)
        ? new HashSet<string>(v.Split(','), StringComparer.Ordinal)
        : new HashSet<string>(StringComparer.Ordinal);
}

/// <summary>
/// Owns an <see cref="IAdbTransport"/>, runs the demux read-loop, and dispatches packets to
/// <see cref="AdbStream"/> instances. Build via
/// <see cref="ConnectAsync(IAdbTransport, IReadOnlyList{AdbAuthKey}, AdbConnectOptions?, CancellationToken)"/>.
/// </summary>
public sealed class AdbConnection : IAsyncDisposable
{
    private readonly IAdbTransport _transport;
    private readonly ConcurrentDictionary<uint, AdbStream> _streams = new();
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly Task _readLoop;
    private uint _nextLocalId;
    private int _disposed;
    private Exception? _faultException;

    /// <summary>
    /// Set after the read loop terminates abnormally; surfaced on subsequent stream/connection calls.
    /// </summary>
    public Exception? FaultException => Volatile.Read(ref _faultException);

    /// <summary>
    /// Maximum payload size in bytes negotiated during CNXN.
    /// </summary>
    public uint MaxPayload { get; }

    /// <summary>
    /// Whether outbound payloads carry the legacy sum-of-bytes checksum.
    /// </summary>
    public bool WriteChecksum { get; }

    /// <summary>
    /// Device identity returned by the CNXN banner.
    /// </summary>
    public AdbDeviceInfo DeviceInfo { get; }

    /// <summary>
    /// How authentication resolved during the handshake.
    /// </summary>
    public AdbAuthenticationMethod AuthenticationMethod { get; }

    private AdbConnection(IAdbTransport transport, AdbDeviceInfo info, in uint maxPayload, in bool writeChecksum, in AdbAuthenticationMethod authMethod)
    {
        _transport = transport;
        MaxPayload = maxPayload;
        WriteChecksum = writeChecksum;
        DeviceInfo = info;
        AuthenticationMethod = authMethod;
        _readLoop = Task.Run(ReadLoopAsync);
    }

    /// <summary>
    /// Opens a TCP socket to <paramref name="host"/>:<paramref name="port"/> and performs the ADB handshake.
    /// </summary>
    /// <param name="host">DNS name or IP of the device.</param>
    /// <param name="port">TCP port adbd is listening on (typically 5555 for <c>adb tcpip</c>).</param>
    /// <param name="keys">RSA keys to try for AUTH; the first key is also used for STLS / public-key push if needed.</param>
    /// <param name="options">Optional handshake settings.</param>
    /// <param name="cancellationToken">Cancellation for the connect + handshake.</param>
    /// <exception cref="AdbAuthenticationException">Device rejected all keys or required STLS without a key.</exception>
    public static async ValueTask<AdbConnection> ConnectTcpAsync(
        string host, int port, IReadOnlyList<AdbAuthKey> keys,
        AdbConnectOptions? options = null, CancellationToken cancellationToken = default)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var transport = StreamAdbTransport.CreateTcp(socket, options?.VerifyChecksum ?? false);
        try
        {
            return await ConnectAsync(transport, keys, options, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Performs the ADB handshake on an arbitrary <see cref="IAdbTransport"/>.
    /// </summary>
    /// <param name="transport">A connected transport. Ownership transfers to the returned <see cref="AdbConnection"/>.</param>
    /// <param name="keys">RSA keys to try for AUTH; the first key is also used for STLS / public-key push if needed.</param>
    /// <param name="options">Optional handshake settings.</param>
    /// <param name="cancellationToken">Cancellation for the handshake.</param>
    /// <exception cref="AdbAuthenticationException">Device rejected all keys or required STLS without a key.</exception>
    public static async ValueTask<AdbConnection> ConnectAsync(
        IAdbTransport transport, IReadOnlyList<AdbAuthKey> keys,
        AdbConnectOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(keys);
        options ??= new AdbConnectOptions();

        // Send CNXN.
        var bannerBytes = EncodeNullTerminated(options.Banner);
        await transport.WritePacketAsync(
            new AdbHeader(AdbCommand.Cnxn, AdbProtocolConstants.Version, options.MaxPayload,
                (uint)bannerBytes.Length, options.WriteChecksum ? AdbHeader.ComputeChecksum(bannerBytes) : 0u),
            bannerBytes, cancellationToken).ConfigureAwait(false);

        var keyIndex = 0;
        var sentPubkey = false;
        var authMethod = AdbAuthenticationMethod.None;
        using var authCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        authCts.CancelAfter(options.AuthTimeout);

        while (true)
        {
            using var pkt = await transport.ReadPacketAsync(authCts.Token).ConfigureAwait(false);

            switch (pkt.Header.Command)
            {
                case AdbCommand.Cnxn:
                    {
                        var banner = Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0');
                        var info = ParseBanner(banner);
                        var negotiated = Math.Min(options.MaxPayload, pkt.Header.Arg1);
                        return new AdbConnection(transport, info, negotiated, options.WriteChecksum, authMethod);
                    }
                case AdbCommand.Auth when pkt.Header.Arg0 == (uint)AdbAuthType.Token:
                    {
                        if (keyIndex < keys.Count)
                        {
                            var sig = keys[keyIndex++].SignToken(pkt.PayloadSpan);
                            authMethod = AdbAuthenticationMethod.Signature;
                            await transport.WritePacketAsync(
                                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.Signature, 0,
                                    (uint)sig.Length, options.WriteChecksum ? AdbHeader.ComputeChecksum(sig) : 0u),
                                sig, authCts.Token).ConfigureAwait(false);
                        }
                        else if (!sentPubkey && keys.Count > 0 && options.SendPublicKeyOnAuthFailure)
                        {
                            sentPubkey = true;
                            authMethod = AdbAuthenticationMethod.PublicKey;
                            var pub = keys[0].EncodeAndroidPublicKey();
                            await transport.WritePacketAsync(
                                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.RsaPublicKey, 0,
                                    (uint)pub.Length, options.WriteChecksum ? AdbHeader.ComputeChecksum(pub) : 0u),
                                pub, authCts.Token).ConfigureAwait(false);
                        }
                        else if (keys.Count == 0)
                        {
                            throw new AdbAuthenticationException("Device requested authentication but no keys were supplied");
                        }
                        else
                        {
                            throw new AdbAuthenticationException(sentPubkey
                                ? "Device rejected the public key (user did not allow on device)"
                                : "Device rejected all signatures and SendPublicKeyOnAuthFailure is disabled");
                        }
                        break;
                    }
                case AdbCommand.Stls:
                    {
                        if (transport is not StreamAdbTransport tlsCapable)
                            throw new NotSupportedException("Transport does not support TLS upgrade");

                        if (keys.Count == 0)
                            throw new AdbAuthenticationException("Device requested STLS but no keys provided for client cert");

                        // Reply STLS to confirm we will upgrade.
                        await transport.WritePacketAsync(
                            new AdbHeader(AdbCommand.Stls, 1, 0, 0, 0),
                            ReadOnlyMemory<byte>.Empty, authCts.Token).ConfigureAwait(false);

                        using var clientCert = keys[0].CreateSelfSignedCertificate();
                        await tlsCapable.UpgradeToTlsAsync(clientCert, authCts.Token).ConfigureAwait(false);
                        authMethod = AdbAuthenticationMethod.Tls;

                        // After TLS, device sends CNXN on the encrypted channel; AUTH is no longer required
                        // because the cert in the TLS handshake already proved key ownership.
                        break;
                    }
                default:
                    throw new InvalidDataException($"Unexpected packet during connect: {pkt.Header.Command}");
            }
        }
    }

    private static byte[] EncodeNullTerminated(in ReadOnlySpan<char> s)
    {
        var len = Encoding.UTF8.GetByteCount(s);
        var b = new byte[len + 1];
        Encoding.UTF8.GetBytes(s, b);
        return b;
    }

    private static AdbDeviceInfo ParseBanner(string banner)
    {
        // Format: "<systemtype>:<serial>:<key1=v1;key2=v2;...>"
        var firstColon = banner.IndexOf(':');
        if (firstColon < 0)
            return new AdbDeviceInfo(banner, "", "", new Dictionary<string, string>(0, StringComparer.Ordinal));

        var secondColon = banner.IndexOf(':', firstColon + 1);
        var systemType = banner[..firstColon];
        if (secondColon < 0)
            return new AdbDeviceInfo(systemType, banner[(firstColon + 1)..], "", new Dictionary<string, string>(0, StringComparer.Ordinal));

        var serial = banner[(firstColon + 1)..secondColon];
        var props = banner[(secondColon + 1)..];

        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        var alternateLookup = dict.GetAlternateLookup<ReadOnlySpan<char>>();
        var propsSpan = props.AsSpan();
        foreach (var range in propsSpan.Split(';'))
        {
            var entry = propsSpan[range];
            if (entry.IsEmpty || entry.IsWhiteSpace())
                continue;

            var eq = entry.IndexOf('=');
            if (eq > 0)
                alternateLookup[entry[..eq]] = entry[(eq + 1)..].ToString();
        }
        return new AdbDeviceInfo(systemType, serial, banner, dict);
    }

    /// <summary>
    /// Opens a service stream identified by <paramref name="service"/>.
    /// </summary>
    /// <param name="service">ADB service string, e.g. <c>shell:ls -la /sdcard</c>, <c>sync:</c>, <c>tcp:8080</c>, <c>reboot:</c>.</param>
    /// <param name="cancellationToken">Cancellation for the OPEN/OKAY round trip.</param>
    /// <returns>A bidirectional <see cref="AdbStream"/> to the device-side service.</returns>
    /// <exception cref="IOException">Device sent CLSE in response to the OPEN, or the connection has faulted.</exception>
    public async Task<AdbStream> OpenAsync(string service, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(service);
        ThrowIfDisposed();
        ThrowIfFaulted();

        uint localId;
        AdbStream stream;
        while (true)
        {
            localId = Interlocked.Increment(ref _nextLocalId);
            if (localId == 0) continue;
            stream = new AdbStream(this, localId);
            if (_streams.TryAdd(localId, stream)) break;
        }

        var payload = EncodeNullTerminated(service);
        var header = new AdbHeader(AdbCommand.Open, localId, 0, (uint)payload.Length,
            WriteChecksum ? AdbHeader.ComputeChecksum(payload) : 0u);

        try
        {
            await _transport.WritePacketAsync(header, payload, cancellationToken).ConfigureAwait(false);
            using var openCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var ok = await stream.OpenedTask.WaitAsync(openCts.Token).ConfigureAwait(false);
            return !ok ? throw new IOException($"ADB device rejected service: {service}") : stream;
        }
        catch
        {
            _streams.TryRemove(localId, out _);
            throw;
        }
    }

    internal ValueTask SendAsync(AdbHeader header, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
        _transport.WritePacketAsync(header, payload, cancellationToken);

    internal async Task CloseStreamAsync(AdbStream stream)
    {
        if (!_streams.TryRemove(stream.LocalId, out _)) return;
        try
        {
            var header = new AdbHeader(AdbCommand.Clse, stream.LocalId, stream.RemoteId, 0, 0);
            await _transport.WritePacketAsync(header, ReadOnlyMemory<byte>.Empty, _shutdownCts.Token).ConfigureAwait(false);
        }
        catch { /* connection may already be dead */ }
    }

    private async Task ReadLoopAsync()
    {
        Exception? fault = null;
        try
        {
            while (!_shutdownCts.IsCancellationRequested)
            {
                using var pkt = await _transport.ReadPacketAsync(_shutdownCts.Token).ConfigureAwait(false);
                await DispatchAsync(pkt).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (EndOfStreamException) { }
        catch (Exception ex)
        {
            fault = ex;
        }
        finally
        {
            if (fault is not null)
                Volatile.Write(ref _faultException, fault);

            foreach (var s in _streams.Values)
            {
                if (fault is not null) s.OnFaulted(fault);
                else s.OnClosed();
            }
            _streams.Clear();
        }
    }

    private async ValueTask DispatchAsync(AdbPacket pkt)
    {
        switch (pkt.Header.Command)
        {
            case AdbCommand.Okay:
                {
                    var remoteLocalId = pkt.Header.Arg0; // device's local id (= our remote id)
                    var ourLocalId = pkt.Header.Arg1;
                    if (_streams.TryGetValue(ourLocalId, out var s))
                    {
                        if (s.RemoteId == 0)
                            s.OnOpened(remoteLocalId);
                        else s.OnAck();
                    }
                    break;
                }
            case AdbCommand.Wrte:
                {
                    var remoteLocalId = pkt.Header.Arg0;
                    var ourLocalId = pkt.Header.Arg1;
                    if (_streams.TryGetValue(ourLocalId, out var s))
                    {
                        await s.OnDataAsync(pkt.Payload, _shutdownCts.Token).ConfigureAwait(false);
                        var ack = new AdbHeader(AdbCommand.Okay, ourLocalId, remoteLocalId, 0, 0);
                        await _transport.WritePacketAsync(ack, ReadOnlyMemory<byte>.Empty, _shutdownCts.Token).ConfigureAwait(false);
                    }
                    break;
                }
            case AdbCommand.Clse:
                {
                    var ourLocalId = pkt.Header.Arg1;
                    if (_streams.TryRemove(ourLocalId, out var s))
                        s.OnClosed();
                    break;
                }
            case AdbCommand.Auth:
                // Mid-session re-auth — not supported here.
                break;
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private void ThrowIfFaulted()
    {
        if (Volatile.Read(ref _faultException) is { } fault)
            throw new IOException("ADB connection faulted: " + fault.Message, fault);
    }

    /// <summary>
    /// Cancels the read loop, closes all open streams, and disposes the underlying transport.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await _shutdownCts.CancelAsync().ConfigureAwait(false);
        try
        {
            await _readLoop.ConfigureAwait(false);
        }
        catch
        {
            // Don't throw in dispose
        }
        await _transport.DisposeAsync().ConfigureAwait(false);
        _shutdownCts.Dispose();
    }
}

/// <summary>
/// Thrown when the ADB handshake cannot complete because the device rejected all keys, no keys were supplied, or the user did not allow the public key on-device.
/// </summary>
public sealed class AdbAuthenticationException : Exception
{
    /// <summary>
    /// Initializes a new instance with the given diagnostic message.
    /// </summary>
    public AdbAuthenticationException(string message) : base(message) { }
}
