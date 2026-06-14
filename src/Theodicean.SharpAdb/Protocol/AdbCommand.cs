namespace Theodicean.SharpAdb.Protocol;

/// <summary>
/// ADB wire commands. Value = ASCII-encoded little-endian 4-byte tag.
/// </summary>
public enum AdbCommand : uint
{
    /// <summary>
    /// Initial handshake packet ("CNXN") carrying version, max payload, and identity banner.
    /// </summary>
    Cnxn = 0x4e584e43,

    /// <summary>
    /// Authentication packet ("AUTH"), carrying TOKEN, SIGNATURE, or RSAPUBLICKEY.
    /// </summary>
    Auth = 0x48545541,

    /// <summary>
    /// Opens a service stream ("OPEN"). Payload is a NUL-terminated service string.
    /// </summary>
    Open = 0x4e45504f,

    /// <summary>
    /// Acknowledges an open or write ("OKAY").
    /// </summary>
    Okay = 0x59414b4f,

    /// <summary>
    /// Closes a stream ("CLSE"). Sent in either direction or in response to a rejected OPEN.
    /// </summary>
    Clse = 0x45534c43,

    /// <summary>
    /// Writes data to a stream ("WRTE"). Must be acknowledged by an OKAY before the next WRTE.
    /// </summary>
    Wrte = 0x45545257,

    /// <summary>
    /// Requests a TLS upgrade ("STLS"). Available since ADB v1.0.41.
    /// </summary>
    Stls = 0x534c5453
}

/// <summary>
/// Type of AUTH packet, carried in <c>arg0</c>.
/// </summary>
public enum AdbAuthType : uint
{
    /// <summary>
    /// Device-issued challenge token (20 random bytes) the client must sign.
    /// </summary>
    Token = 1,

    /// <summary>
    /// Client-side RSA-PKCS#1 v1.5 SHA-1 signature of the most recent TOKEN.
    /// </summary>
    Signature = 2,

    /// <summary>
    /// Client public key in Android mincrypt format, sent so the device can prompt the user to authorize it.
    /// </summary>
    RsaPublicKey = 3
}

/// <summary>
/// Wire protocol constants shared by codec, transport, and connection layers.
/// </summary>
public static class AdbProtocolConstants
{
    /// <summary>
    /// Legacy ADB wire protocol version. Both sides compute and verify the sum-of-bytes payload checksum.
    /// </summary>
    public const uint VersionLegacy = 0x01000000;

    /// <summary>
    /// ADB wire protocol version since v34 (2021). Peers advertising this version agree to send
    /// <see cref="AdbHeader.DataChecksum"/>=0 and skip verification.
    /// </summary>
    public const uint VersionSkipChecksum = 0x01000001;

    /// <summary>
    /// Default version advertised by this client (<see cref="VersionSkipChecksum"/>).
    /// </summary>
    public const uint Version = VersionSkipChecksum;

    /// <summary>
    /// Minimum supported wire protocol version. CNXN responses below this value are rejected.
    /// </summary>
    public const uint MinSupportedVersion = VersionLegacy;

    /// <summary>
    /// Largest payload an ADB peer is required to accept (post-handshake max_data).
    /// </summary>
    public const uint MaxPayload = 1024 * 1024;

    /// <summary>
    /// Minimum payload size we will accept as a CNXN-advertised max_data. Matches the legacy
    /// ADB protocol max_data limit — a peer advertising anything smaller is treated as broken
    /// and has its advertisement clamped up to this floor so write fragmentation still works.
    /// </summary>
    public const uint MinPayload = 4096;

    /// <summary>
    /// Size of the fixed-layout ADB packet header in bytes.
    /// </summary>
    public const int HeaderSize = 24;

    /// <summary>
    /// Size of the SHA-1 challenge token sent in AUTH(TOKEN, ...).
    /// </summary>
    public const int AuthTokenSize = 20;
}
