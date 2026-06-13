using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Protocol;
using Theodicean.SharpAdb.Transport;

namespace Theodicean.SharpAdb;

/// <summary>
/// Options controlling the ADB connection handshake and per-connection behavior.
/// </summary>
public sealed class AdbConnectOptions
{
    // ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

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

    /// <summary>
    /// Invoked once, immediately before the first key's public key is written to the transport
    /// via <c>AUTH(RSAPUBLICKEY)</c>. This step typically causes the device to display its
    /// approval dialog, unless the key is already in <c>adb_keys</c>, in which case adbd
    /// silently accepts The callback receives the auth-handshake cancellation token,
    /// which fires on <see cref="AuthTimeout"/> or caller cancellation.
    /// </summary>
    // ReSharper disable once UnusedAutoPropertyAccessor.Global
    public Func<AdbAuthKey, CancellationToken, ValueTask>? OnBeforePublicKeyPush { get; init; }

    /// <summary>
    /// Logger used to emit diagnostic events during the connect handshake (CNXN/AUTH/STLS
    /// transitions, signature attempts, public-key push, banner parse).
    /// </summary>
    public ILogger Logger { get; init; } = NullLogger.Instance;

    // ReSharper restore AutoPropertyCanBeMadeGetOnly.Global
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
// ReSharper disable once NotAccessedPositionalProperty.Global
public sealed record AdbDeviceInfo(string SystemType, string Serial, string Banner, IReadOnlyDictionary<string, string> Properties)
{
    /// <summary>
    /// Value of <c>ro.product.name</c> if present.
    /// </summary>
    public string? Product => field ??= Properties.GetValueOrDefault("ro.product.name");

    /// <summary>
    /// Value of <c>ro.product.model</c> if present.
    /// </summary>
    public string? Model => field ??= Properties.GetValueOrDefault("ro.product.model");

    /// <summary>
    /// Value of <c>ro.product.device</c> if present.
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public string? Device => field ??= Properties.GetValueOrDefault("ro.product.device");

    /// <summary>
    /// Set of feature flags advertised by the device (parsed from the comma-separated <c>features</c> property).
    /// </summary>
    // ReSharper disable once UnusedMember.Global
    public IReadOnlySet<string> Features => field ??= Properties.TryGetValue("features", out var v)
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

    internal ILogger Logger { get; }

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

    private AdbConnection(IAdbTransport transport, AdbDeviceInfo info, in uint maxPayload, in bool writeChecksum, in AdbAuthenticationMethod authMethod, ILogger logger)
    {
        _transport = transport;
        MaxPayload = maxPayload;
        WriteChecksum = writeChecksum;
        DeviceInfo = info;
        AuthenticationMethod = authMethod;
        Logger = logger;
        _readLoop = Task.Run(ReadLoopAsync, _shutdownCts.Token);
    }

    /// <summary>
    /// Opens a TCP socket to <paramref name="host"/>:<paramref name="port"/> and performs the ADB handshake.
    /// </summary>
    /// <remarks>This method will generate a private key if one doesn't already exist.</remarks>
    /// <param name="host">DNS name or IP of the device.</param>
    /// <param name="port">TCP port adbd is listening on (typically 5555 for <c>adb tcpip</c>).</param>
    /// <param name="options">Optional handshake settings.</param>
    /// <param name="cancellationToken">Cancellation for the connect + handshake.</param>
    /// <exception cref="AdbAuthenticationException">Device rejected all keys or required STLS without a key.</exception>
    // ReSharper disable once UnusedMember.Global
    public static async ValueTask<AdbConnection> ConnectTcpAsync(
        string host, int port,
        AdbConnectOptions? options = null, CancellationToken cancellationToken = default)
    {
        var defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".android");
        if (!Directory.Exists(defaultPath))
            Directory.CreateDirectory(defaultPath);

        var keyPath = Environment.GetEnvironmentVariable("ADB_KEY_PATH") ?? Path.Combine(defaultPath, "adbkey");

        AdbAuthKey key;
        if (File.Exists(keyPath))
        {
            key = AdbAuthKey.LoadFromPem(await File.ReadAllTextAsync(keyPath, cancellationToken));
        }
        else
        {
            key = AdbAuthKey.Generate();
            await File.WriteAllTextAsync(keyPath, key.ExportPrivateKeyPem(), cancellationToken);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

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

        var transport = StreamAdbTransport.CreateTcp(socket, options?.VerifyChecksum ?? false);
        try
        {
            return await ConnectAsync(transport, [key], options, cancellationToken);
        }
        catch
        {
            await transport.DisposeAsync();
            throw;
        }
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
            await socket.ConnectAsync(host, port, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var transport = StreamAdbTransport.CreateTcp(socket, options?.VerifyChecksum ?? false);
        try
        {
            return await ConnectAsync(transport, keys, options, cancellationToken);
        }
        catch
        {
            await transport.DisposeAsync();
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

        // The ADB legacy checksum mode is symmetric: whichever side advertises the legacy wire
        // version commits both sides to sending and verifying the sum-of-bytes payload checksum.
        // VerifyChecksum=true without WriteChecksum=true would have us advertise the legacy
        // version and then send payloads with DataChecksum=0 — adbd would reject them.
        if (options.VerifyChecksum && !options.WriteChecksum)
            throw new ArgumentException(
                "VerifyChecksum=true requires WriteChecksum=true: the ADB legacy checksum mode is symmetric.",
                nameof(options));

        // Advertise legacy wire version iff we will send checksums. Otherwise the peer treats us
        // as a modern client and skips its own checksum (so there is nothing for us to verify).
        var advertisedVersion = options.WriteChecksum
            ? AdbProtocolConstants.VersionLegacy
            : AdbProtocolConstants.VersionSkipChecksum;

        // Send CNXN.
        var bannerBuf = RentNullTerminated(options.Banner, out var bannerLen);
        try
        {
            var bannerPayload = bannerBuf.AsMemory(0, bannerLen);
            await transport.WritePacketAsync(
                new AdbHeader(AdbCommand.Cnxn, advertisedVersion, options.MaxPayload,
                    (uint)bannerLen, options.WriteChecksum ? AdbHeader.ComputeChecksum(bannerPayload.Span) : 0u),
                bannerPayload, cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bannerBuf);
        }
        options.Logger.CnxnSent(options.Banner, options.MaxPayload);

        var keyIndex = 0;
        var sentPubkey = false;
        var authMethod = AdbAuthenticationMethod.None;
        using var authCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        authCts.CancelAfter(options.AuthTimeout);

        while (true)
        {
            using var pkt = await transport.ReadPacketAsync(authCts.Token);

            switch (pkt.Header.Command)
            {
                case AdbCommand.Cnxn:
                    {
                        if (pkt.Header.Arg0 < AdbProtocolConstants.MinSupportedVersion)
                            throw new InvalidDataException(
                                $"Unsupported ADB protocol version 0x{pkt.Header.Arg0:X8} from device (minimum 0x{AdbProtocolConstants.MinSupportedVersion:X8})");

                        var banner = Encoding.UTF8.GetString(pkt.PayloadSpan).TrimEnd('\0');
                        var info = ParseBanner(banner);
                        var negotiated = Math.Min(options.MaxPayload, pkt.Header.Arg1);
                        options.Logger.ConnectionEstablished(authMethod, info.SystemType, info.Serial, negotiated);
                        return new AdbConnection(transport, info, negotiated, options.WriteChecksum, authMethod, options.Logger);
                    }
                case AdbCommand.Auth when pkt.Header.Arg0 == (uint)AdbAuthType.Token:
                    {
                        options.Logger.AuthTokenReceived();
                        if (keyIndex < keys.Count)
                        {
                            var key = keys[keyIndex];
                            if (options.Logger.IsEnabled(LogLevel.Debug))
                                options.Logger.SigningToken(key.GetAdbFingerprint(), keyIndex + 1, keys.Count);

                            var sig = key.SignToken(pkt.PayloadSpan);
                            keyIndex++;
                            authMethod = AdbAuthenticationMethod.Signature;
                            await transport.WritePacketAsync(
                                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.Signature, 0,
                                    (uint)sig.Length, options.WriteChecksum ? AdbHeader.ComputeChecksum(sig) : 0u),
                                sig, authCts.Token);
                        }
                        else if (!sentPubkey && keys.Count > 0 && options.SendPublicKeyOnAuthFailure)
                        {
                            sentPubkey = true;
                            authMethod = AdbAuthenticationMethod.PublicKey;
                            if (options.Logger.IsEnabled(LogLevel.Information))
                                options.Logger.PushingPublicKey(keys.Count, keys[0].GetAdbFingerprint());
                            if (options.OnBeforePublicKeyPush != null)
                            {
                                try
                                {
                                    await options.OnBeforePublicKeyPush(keys[0], authCts.Token);
                                }
                                catch (Exception ex)
                                {
                                    options.Logger.CallbackThrew(ex);
                                }
                            }

                            var pub = keys[0].EncodeAndroidPublicKey();
                            await transport.WritePacketAsync(
                                new AdbHeader(AdbCommand.Auth, (uint)AdbAuthType.RsaPublicKey, 0,
                                    (uint)pub.Length, options.WriteChecksum ? AdbHeader.ComputeChecksum(pub) : 0u),
                                pub, authCts.Token);
                        }
                        else
                        {
                            if (keys.Count == 0)
                                throw new AdbAuthenticationException("Device requested authentication but no keys were supplied");

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

                        if (options.Logger.IsEnabled(LogLevel.Information))
                            options.Logger.StlsUpgrade(keys[0].GetAdbFingerprint());

                        // Reply STLS to confirm we will upgrade.
                        await transport.WritePacketAsync(
                            new AdbHeader(AdbCommand.Stls, 1, 0, 0, 0),
                            ReadOnlyMemory<byte>.Empty, authCts.Token);

                        using var clientCert = keys[0].CreateSelfSignedCertificate();
                        await tlsCapable.UpgradeToTlsAsync(clientCert, authCts.Token);
                        authMethod = AdbAuthenticationMethod.Tls;
                        if (options.Logger.IsEnabled(LogLevel.Information))
                        {
                            options.Logger.TlsUpgraded(tlsCapable.NegotiatedTlsProtocol?.ToString() ?? "unknown",
                                tlsCapable.NegotiatedTlsCipherSuite?.ToString() ?? "unknown");
                        }

                        // After TLS, device sends CNXN on the encrypted channel; AUTH is no longer required
                        // because the cert in the TLS handshake already proved key ownership.
                        break;
                    }
                default:
                    throw new InvalidDataException($"Unexpected packet during connect: {pkt.Header.Command}");
            }
        }
    }

    /// <summary>
    /// Rents a buffer from the shared pool and fills it with the UTF-8 bytes of <paramref name="s"/>
    /// followed by a trailing NUL. The returned buffer's length may exceed <paramref name="length"/>;
    /// only the first <paramref name="length"/> bytes are meaningful.
    /// Caller MUST <see cref="ArrayPool{T}.Return"/> the buffer.
    /// </summary>
    private static byte[] RentNullTerminated(ReadOnlySpan<char> s, out int length)
    {
        length = Encoding.UTF8.GetByteCount(s) + 1;
        var buf = ArrayPool<byte>.Shared.Rent(length);
        var written = Encoding.UTF8.GetBytes(s, buf);
        buf[written] = 0;
        return buf;
    }

    private static AdbDeviceInfo ParseBanner(string banner)
    {
        // Format: "<systemtype>:<serial>:<key1=v1;key2=v2;...>"
        var firstColon = banner.IndexOf(':', StringComparison.Ordinal);
        if (firstColon < 0)
            return new AdbDeviceInfo(banner, "", banner, new Dictionary<string, string>(0, StringComparer.Ordinal));

        var secondColon = banner.IndexOf(':', firstColon + 1);
        var systemType = banner[..firstColon];
        if (secondColon < 0)
            return new AdbDeviceInfo(systemType, banner[(firstColon + 1)..], banner, new Dictionary<string, string>(0, StringComparer.Ordinal));

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

        var payloadBuf = RentNullTerminated(service, out var payloadLen);
        try
        {
            var payload = payloadBuf.AsMemory(0, payloadLen);
            var header = new AdbHeader(AdbCommand.Open, localId, 0, (uint)payloadLen,
                WriteChecksum ? AdbHeader.ComputeChecksum(payload.Span) : 0u);

            try
            {
                await _transport.WritePacketAsync(header, payload, cancellationToken);
                Logger.OpenSent(service, localId);
                var ok = await stream.OpenedTask.WaitAsync(cancellationToken);
                if (!ok)
                {
                    Logger.StreamRejected(service, localId);
                    throw new IOException($"ADB device rejected service: {service}");
                }
                Logger.StreamOpened(localId, stream.RemoteId, service);
                return stream;
            }
            catch
            {
                // Remove from the dispatch map first so CloseStreamAsync no-ops (we never got an
                // OKAY, so there is no remoteId to address a CLSE to), then dispose the stream
                // for deterministic cleanup of its Pipe / SemaphoreSlim instead of waiting on GC.
                _streams.TryRemove(localId, out _);
                await stream.DisposeAsync();
                throw;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(payloadBuf);
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
            await _transport.WritePacketAsync(header, ReadOnlyMemory<byte>.Empty, _shutdownCts.Token);
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
                using var pkt = await _transport.ReadPacketAsync(_shutdownCts.Token);
                await DispatchAsync(pkt);
            }
        }
        catch (OperationCanceledException)
        {
            // Ignore
        }
        catch (EndOfStreamException)
        {
            // Ignore
        }
        catch (Exception ex)
        {
            fault = ex;
            Logger.ReadLoopFaulted(ex);
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
                    else
                    {
                        Logger.UnknownStreamPacket(pkt.Header.Command, ourLocalId);
                    }
                    break;
                }
            case AdbCommand.Wrte:
                {
                    var remoteLocalId = pkt.Header.Arg0;
                    var ourLocalId = pkt.Header.Arg1;
                    if (_streams.TryGetValue(ourLocalId, out var s))
                    {
                        await s.OnDataAsync(pkt.Payload, _shutdownCts.Token);
                        var ack = new AdbHeader(AdbCommand.Okay, ourLocalId, remoteLocalId, 0, 0);
                        await _transport.WritePacketAsync(ack, ReadOnlyMemory<byte>.Empty, _shutdownCts.Token);
                    }
                    else
                        Logger.UnknownStreamPacket(pkt.Header.Command, ourLocalId);
                    break;
                }
            case AdbCommand.Clse:
                {
                    var ourLocalId = pkt.Header.Arg1;
                    if (_streams.TryRemove(ourLocalId, out var s))
                        s.OnClosed();
                    else
                        Logger.UnknownStreamPacket(pkt.Header.Command, ourLocalId);
                    break;
                }
            case AdbCommand.Auth:
                // Mid-session re-auth is not supported. Fault the connection so all blocked
                // stream operations surface a clear error instead of hanging indefinitely.
                throw new InvalidDataException($"Unexpected mid-session AUTH packet (arg0={pkt.Header.Arg0})");
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
        await _shutdownCts.CancelAsync();
        try
        {
            await _readLoop;
        }
        catch
        {
            // Don't throw in dispose
        }
        await _transport.DisposeAsync();
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
