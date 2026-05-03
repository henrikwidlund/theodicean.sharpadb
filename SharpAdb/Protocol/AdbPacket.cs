using System.Buffers;

namespace SharpAdb.Protocol;

/// <summary>
/// Header + optional pooled payload. Caller must <see cref="Dispose"/> to return rented memory.
/// </summary>
public readonly struct AdbPacket : IDisposable
{
    public readonly AdbHeader Header;
    private readonly byte[]? _rented;
    private readonly int _payloadLength;

    internal AdbPacket(in AdbHeader header, byte[]? rented, in int payloadLength)
    {
        Header = header;
        _rented = rented;
        _payloadLength = payloadLength;
    }

    public ReadOnlyMemory<byte> Payload => _rented?.AsMemory(0, _payloadLength) ?? ReadOnlyMemory<byte>.Empty;
    public ReadOnlySpan<byte> PayloadSpan => _rented is null ? ReadOnlySpan<byte>.Empty : _rented.AsSpan(0, _payloadLength);

    public void Dispose()
    {
        if (_rented is not null)
            ArrayPool<byte>.Shared.Return(_rented);
    }
}
