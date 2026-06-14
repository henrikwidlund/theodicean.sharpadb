using System.Buffers;

namespace Theodicean.SharpAdb.Protocol;

/// <summary>
/// Header + optional pooled payload. Caller must <see cref="Dispose"/> to return rented memory
/// — unless ownership has been transferred away via <see cref="TakePayloadBuffer"/>.
/// </summary>
public struct AdbPacket : IDisposable
{
    /// <summary>
    /// Decoded header.
    /// </summary>
    public readonly AdbHeader Header;

    private byte[]? _rented;
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
    public readonly ReadOnlyMemory<byte> Payload => _rented?.AsMemory(0, _payloadLength) ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Pooled payload span; valid only until <see cref="Dispose"/> is called.
    /// </summary>
    public readonly ReadOnlySpan<byte> PayloadSpan => _rented is null ? ReadOnlySpan<byte>.Empty : _rented.AsSpan(0, _payloadLength);

    /// <summary>
    /// Detaches the pooled payload buffer from this packet. The returned array is the
    /// underlying rented buffer (length &gt;= <paramref name="length"/>); the new owner is
    /// responsible for returning it to <see cref="ArrayPool{T}.Shared"/>. <see cref="Dispose"/>
    /// becomes a no-op after this call. Returns <see langword="null"/> for empty payloads.
    /// </summary>
    internal byte[]? TakePayloadBuffer(out int length)
    {
        var buf = _rented;
        _rented = null;
        length = _payloadLength;
        return buf;
    }

    /// <summary>
    /// Returns the rented payload buffer to the shared <see cref="ArrayPool{Byte}"/>.
    /// </summary>
    public void Dispose()
    {
        if (_rented is not null)
            ArrayPool<byte>.Shared.Return(_rented);
        _rented = null;
    }
}
