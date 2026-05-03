using System.Buffers;

namespace Theodicean.SharpAdb.Protocol;

/// <summary>
/// Header + optional pooled payload. Caller must <see cref="Dispose"/> to return rented memory.
/// </summary>
public readonly struct AdbPacket : IDisposable
{
    /// <summary>
    /// Decoded header.
    /// </summary>
    public readonly AdbHeader Header;

    private readonly byte[]? _rented;
    private readonly int _payloadLength;

    internal AdbPacket(in AdbHeader header, byte[]? rented, in int payloadLength)
    {
        Header = header;
        _rented = rented;
        _payloadLength = payloadLength;
    }

    /// <summary>
    /// Pooled payload memory; valid only until <see cref="Dispose"/> is called.
    /// </summary>
    public ReadOnlyMemory<byte> Payload => _rented?.AsMemory(0, _payloadLength) ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Pooled payload span; valid only until <see cref="Dispose"/> is called.
    /// </summary>
    public ReadOnlySpan<byte> PayloadSpan => _rented is null ? ReadOnlySpan<byte>.Empty : _rented.AsSpan(0, _payloadLength);

    /// <summary>
    /// Returns the rented payload buffer to the shared <see cref="ArrayPool{Byte}"/>.
    /// </summary>
    public void Dispose()
    {
        if (_rented is not null)
            ArrayPool<byte>.Shared.Return(_rented);
    }
}
