namespace SharpAdb.Protocol;

/// <summary>ADB wire commands. Value = ASCII-encoded little-endian 4-byte tag.</summary>
public enum AdbCommand : uint
{
    Cnxn = 0x4e584e43, // "CNXN"
    Auth = 0x48545541, // "AUTH"
    Open = 0x4e45504f, // "OPEN"
    Okay = 0x59414b4f, // "OKAY"
    Clse = 0x45534c43, // "CLSE"
    Wrte = 0x45545257, // "WRTE"
    Stls = 0x534c5453  // "STLS" (TLS upgrade, ADB v1.0.41+)
}

public enum AdbAuthType : uint
{
    Token = 1,
    Signature = 2,
    RsaPublicKey = 3
}

public static class AdbProtocolConstants
{
    /// <summary>Wire protocol version negotiated by CNXN. ADB uses 0x01000001 since v34, 0x01000000 earlier.</summary>
    public const uint Version = 0x01000001;

    /// <summary>Largest payload an ADB peer is required to accept (post-handshake max_data).</summary>
    public const uint MaxPayload = 1024 * 1024;

    public const int HeaderSize = 24;

    public const int AuthTokenSize = 20;
}
