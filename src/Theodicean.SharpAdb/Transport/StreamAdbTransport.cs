using System.Buffers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb.Transport;

/// <summary>
/// Packet transport over an arbitrary duplex <see cref="Stream"/> (TCP socket, USB tunnel, in-memory pipe).
/// Header reads use a fixed 24-byte buffer; payloads use <see cref="ArrayPool{Byte}"/>.
/// </summary>
public sealed class StreamAdbTransport : IAdbTransport
{
    private Stream _stream;
    private readonly bool _ownsStream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly byte[] _writeHeaderBuffer = new byte[AdbProtocolConstants.HeaderSize];
    private readonly byte[] _readHeaderBuffer = new byte[AdbProtocolConstants.HeaderSize];
    private readonly bool _verifyChecksum;
    private int _disposed;

    /// <summary>
    /// <see langword="true"/> after a successful <see cref="UpgradeToTlsAsync"/>.
    /// </summary>
    // ReSharper disable once MemberCanBePrivate.Global
    public bool IsTls { get; private set; }

    /// <summary>
    /// Negotiated TLS protocol version after <see cref="UpgradeToTlsAsync"/>; <see langword="null"/> before upgrade.
    /// </summary>
    public System.Security.Authentication.SslProtocols? NegotiatedTlsProtocol { get; private set; }

    /// <summary>
    /// Negotiated TLS cipher suite after <see cref="UpgradeToTlsAsync"/>; <see langword="null"/> before upgrade.
    /// </summary>
    public TlsCipherSuite? NegotiatedTlsCipherSuite { get; private set; }

    /// <summary>
    /// Initializes a new instance that wraps an existing duplex stream as an ADB transport.
    /// </summary>
    /// <param name="stream">Stream to read/write ADB packets on.</param>
    /// <param name="ownsStream">When <see langword="true"/>, disposing this transport disposes the inner stream.</param>
    /// <param name="verifyChecksum">When <see langword="true"/>, validate the legacy sum-of-bytes checksum on inbound payloads.</param>
    public StreamAdbTransport(Stream stream, in bool ownsStream = true, in bool verifyChecksum = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _ownsStream = ownsStream;
        _verifyChecksum = verifyChecksum;
    }

    /// <summary>
    /// Builds a transport over a connected TCP socket. Disables Nagle's algorithm.
    /// </summary>
    public static StreamAdbTransport CreateTcp(Socket socket, in bool verifyChecksum = false)
    {
        socket.NoDelay = true;
        return new StreamAdbTransport(new NetworkStream(socket, ownsSocket: true), ownsStream: true, verifyChecksum);
    }

    /// <summary>
    /// Upgrade the underlying stream to TLS after exchanging STLS packets. Caller must guarantee
    /// no extra packet bytes are pending — protocol enforces this since both sides wait for the
    /// TLS ClientHello before sending more ADB frames.
    /// </summary>
    public async ValueTask UpgradeToTlsAsync(X509Certificate2 clientCertificate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientCertificate);
        if (IsTls)
            throw new InvalidOperationException("Transport already upgraded to TLS");

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            var ssl = new SslStream(_stream, leaveInnerStreamOpen: false);

            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = "adb",
                ClientCertificates = [clientCertificate],
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12,
                CertificateChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck },
                RemoteCertificateValidationCallback = static (_, _, _, _) => true /* device uses self-signed cert */
            };

            await ssl.AuthenticateAsClientAsync(opts, cancellationToken);

            _stream = ssl;
            IsTls = true;
            NegotiatedTlsProtocol = ssl.SslProtocol;
            NegotiatedTlsCipherSuite = ssl.NegotiatedCipherSuite;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc/>
    public async ValueTask<AdbPacket> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _stream.ReadExactlyAsync(_readHeaderBuffer.AsMemory(0, AdbProtocolConstants.HeaderSize), cancellationToken);
        }
        catch (EndOfStreamException)
        {
            throw new EndOfStreamException("ADB peer closed before header completed");
        }

        var header = AdbHeader.Read(_readHeaderBuffer);

        if (header.DataLength == 0)
            return new AdbPacket(header, rented: null, payloadLength: 0);

        if (header.DataLength > AdbProtocolConstants.MaxPayload)
            throw new InvalidDataException($"ADB payload exceeds max ({header.DataLength} > {AdbProtocolConstants.MaxPayload})");

        var len = (int)header.DataLength;
        var rented = ArrayPool<byte>.Shared.Rent(len);
        try
        {
            await _stream.ReadExactlyAsync(rented.AsMemory(0, len), cancellationToken);

            if (_verifyChecksum && header.DataChecksum != 0)
            {
                var actual = AdbHeader.ComputeChecksum(rented.AsSpan(0, len));
                if (actual != header.DataChecksum)
                    throw new InvalidDataException($"ADB payload checksum mismatch: expected {header.DataChecksum}, got {actual}");
            }
        }
        catch (EndOfStreamException)
        {
            ArrayPool<byte>.Shared.Return(rented);
            throw new EndOfStreamException("ADB peer closed during payload");
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(rented);
            throw;
        }

        return new AdbPacket(header, rented, len);
    }

    /// <inheritdoc/>
    public async ValueTask WritePacketAsync(AdbHeader header, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        if (payload.Length != header.DataLength)
            throw new ArgumentException($"Payload length {payload.Length} != header.DataLength {header.DataLength}", nameof(payload));

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            header.WriteTo(_writeHeaderBuffer);
            await _stream.WriteAsync(_writeHeaderBuffer.AsMemory(0, AdbProtocolConstants.HeaderSize), cancellationToken);
            if (!payload.IsEmpty)
                await _stream.WriteAsync(payload, cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc/>
    public ValueTask FlushAsync(CancellationToken cancellationToken = default) =>
        new(_stream.FlushAsync(cancellationToken));

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        if (_ownsStream)
            await _stream.DisposeAsync();

        _writeLock.Dispose();
    }
}
