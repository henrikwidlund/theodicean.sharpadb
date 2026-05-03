using SharpAdb.Protocol;

namespace SharpAdb.Transport;

/// <summary>
/// Bidirectional packet pipe to an ADB peer. Implementations must be safe for one concurrent reader and one concurrent writer.
/// </summary>
public interface IAdbTransport : IAsyncDisposable
{
    ValueTask<AdbPacket> ReadPacketAsync(CancellationToken cancellationToken = default);
    ValueTask WritePacketAsync(AdbHeader header, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default);
    ValueTask FlushAsync(CancellationToken cancellationToken = default);
}
