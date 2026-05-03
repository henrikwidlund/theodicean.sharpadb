using SharpAdb.Protocol;

namespace SharpAdb.Transport;

/// <summary>
/// Bidirectional packet pipe to an ADB peer. Implementations must be safe for one concurrent reader and one concurrent writer.
/// </summary>
public interface IAdbTransport : IAsyncDisposable
{
    /// <summary>
    /// Reads the next ADB packet from the peer. The caller must dispose the returned packet to return its payload buffer.
    /// </summary>
    ValueTask<AdbPacket> ReadPacketAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes an ADB packet to the peer. The length of <paramref name="payload"/> must equal <c>header.DataLength</c>.
    /// </summary>
    ValueTask WritePacketAsync(AdbHeader header, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default);

    /// <summary>
    /// Flushes any pending writes to the underlying transport.
    /// </summary>
    ValueTask FlushAsync(CancellationToken cancellationToken = default);
}
