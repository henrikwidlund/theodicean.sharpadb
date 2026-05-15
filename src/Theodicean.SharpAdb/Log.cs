using Microsoft.Extensions.Logging;

using Theodicean.SharpAdb.Protocol;

namespace Theodicean.SharpAdb;

internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "ADB CNXN sent (banner={Banner}, maxPayload={MaxPayload})")]
    public static partial void CnxnSent(this ILogger logger, string banner, uint maxPayload);

    [LoggerMessage(EventId = 2, Level = LogLevel.Trace, Message = "ADB AUTH(TOKEN) received from device")]
    public static partial void AuthTokenReceived(this ILogger logger);

    [LoggerMessage(EventId = 3, Level = LogLevel.Debug, Message = "Signing AUTH token with key {Fingerprint} (attempt {Attempt} of {KeyCount})")]
    public static partial void SigningToken(this ILogger logger, string fingerprint, int attempt, int keyCount);

    [LoggerMessage(EventId = 4, Level = LogLevel.Information, Message = "All {KeyCount} signatures rejected; pushing public key {Fingerprint} (device may prompt for approval)")]
    public static partial void PushingPublicKey(this ILogger logger, int keyCount, string fingerprint);

    [LoggerMessage(EventId = 5, Level = LogLevel.Information, Message = "ADB STLS upgrade requested by device; using key {Fingerprint} as client cert")]
    public static partial void StlsUpgrade(this ILogger logger, string fingerprint);

    [LoggerMessage(EventId = 6, Level = LogLevel.Information, Message = "ADB connection established via {AuthMethod} (systemType={SystemType}, serial={Serial}, negotiatedMaxPayload={MaxPayload})")]
    public static partial void ConnectionEstablished(this ILogger logger, AdbAuthenticationMethod authMethod, string systemType, string serial, uint maxPayload);

    [LoggerMessage(EventId = 7, Level = LogLevel.Warning, Message = "OnBeforePublicKeyPush callback threw; swallowing and continuing handshake")]
    public static partial void CallbackThrew(this ILogger logger, Exception exception);

    [LoggerMessage(EventId = 8, Level = LogLevel.Error, Message = "ADB read loop terminated unexpectedly")]
    public static partial void ReadLoopFaulted(this ILogger logger, Exception exception);

    [LoggerMessage(EventId = 9, Level = LogLevel.Debug, Message = "Sending OPEN service={Service} localId={LocalId}")]
    public static partial void OpenSent(this ILogger logger, string service, uint localId);

    [LoggerMessage(EventId = 10, Level = LogLevel.Debug, Message = "Stream opened localId={LocalId} remoteId={RemoteId} service={Service}")]
    public static partial void StreamOpened(this ILogger logger, uint localId, uint remoteId, string service);

    [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "Device rejected service={Service} (CLSE in response to OPEN) localId={LocalId}")]
    public static partial void StreamRejected(this ILogger logger, string service, uint localId);

    [LoggerMessage(EventId = 12, Level = LogLevel.Debug, Message = "Dropping packet for unknown stream id: command={Command} localId={LocalId}")]
    public static partial void UnknownStreamPacket(this ILogger logger, AdbCommand command, uint localId);

    [LoggerMessage(EventId = 13, Level = LogLevel.Debug, Message = "Stream closed localId={LocalId} remoteId={RemoteId}")]
    public static partial void StreamClosed(this ILogger logger, uint localId, uint remoteId);

    [LoggerMessage(EventId = 14, Level = LogLevel.Warning, Message = "Stream faulted localId={LocalId} remoteId={RemoteId}")]
    public static partial void StreamFaulted(this ILogger logger, uint localId, uint remoteId, Exception exception);

    [LoggerMessage(EventId = 15, Level = LogLevel.Information, Message = "TLS upgrade complete: protocol={Protocol} cipher={Cipher}")]
    public static partial void TlsUpgraded(this ILogger logger, string protocol, string cipher);
}
