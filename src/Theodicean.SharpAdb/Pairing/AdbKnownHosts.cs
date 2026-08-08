using System.Text;
using System.Text.Json;

namespace Theodicean.SharpAdb.Pairing;

/// <summary>
/// Persists device GUIDs (<see cref="PeerInfoType.AdbDeviceGuid"/>) returned by successful
/// <see cref="AdbPairing.PairAsync"/> calls, so a caller watching mDNS for <c>_adb-tls-connect._tcp</c>
/// can tell which discovered service belongs to an already-paired device before dialing it.
/// </summary>
/// <remarks>
/// Real <c>adb</c> matches the <em>mDNS instance name</em> of a <c>_adb-tls-connect._tcp</c>
/// announcement directly against the device GUID it received during pairing — there is no
/// fuzzier correlation, and the check happens before any TLS/AUTH attempt. This type only stores
/// that lookup set; the mDNS watching itself is out of scope for this library (bring your own
/// mDNS client — <c>net-dns</c> or otherwise — and call <see cref="ContainsAsync"/> on each
/// discovered instance name).
/// </remarks>
public static class AdbKnownHosts
{
    /// <summary>
    /// Default path: <c>~/.android/sharpadb_known_hosts.json</c>, mirroring the <c>~/.android</c>
    /// convention <see cref="AdbConnection.ConnectTcpAsync(string, int, AdbConnectOptions?, CancellationToken)"/>
    /// already uses for the ADB key. A distinct filename from real adb's own <c>adb_known_hosts.pb</c>
    /// — this is not intended to be wire/format-compatible with it.
    /// </summary>
    // ReSharper disable once MemberCanBePrivate.Global
    public static string DefaultPath => field ??= Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".android", "sharpadb_known_hosts.json");

    /// <summary>
    /// Loads the known-host GUID set from <paramref name="path"/> (or <see cref="DefaultPath"/>).
    /// Returns an empty set if the file does not exist yet.
    /// </summary>
    public static async Task<IReadOnlySet<string>> LoadAsync(string? path = null, CancellationToken cancellationToken = default)
    {
        path ??= DefaultPath;
        if (!File.Exists(path))
            return new HashSet<string>(0, StringComparer.Ordinal);

        await using var stream = File.OpenRead(path);
        var guids = await JsonSerializer.DeserializeAsync<HashSet<string>>(stream, cancellationToken: cancellationToken);
        return guids ?? new HashSet<string>(0, StringComparer.Ordinal);
    }

    /// <summary>Checks whether <paramref name="guidOrInstanceName"/> is a known, previously-paired device GUID.</summary>
    public static async Task<bool> ContainsAsync(
        string guidOrInstanceName, string? path = null, CancellationToken cancellationToken = default) =>
        (await LoadAsync(path, cancellationToken)).Contains(guidOrInstanceName);

    /// <summary>
    /// Records <paramref name="result"/>'s device GUID as known, for later mDNS instance-name matching.
    /// A no-op if the device sent back its public key instead of a GUID (some devices/ADB versions
    /// may not send a GUID at all) — nothing to persist in that case.
    /// </summary>
    public static Task AddAsync(AdbPairingResult result, string? path = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.PeerInfoType != PeerInfoType.AdbDeviceGuid
            ? Task.CompletedTask
            : AddAsync(Encoding.UTF8.GetString(result.PeerInfoData), path, cancellationToken);
    }

    /// <summary>Records <paramref name="guid"/> as a known, previously-paired device GUID.</summary>
    public static async Task AddAsync(string guid, string? path = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(guid);
        path ??= DefaultPath;

        // Read-modify-write with no locking: concurrent pairings racing to update this file
        // could lose an update, same as real adb's own known-hosts file has no cross-process
        // locking either. Acceptable for a low-frequency, human-mediated operation.
        var guids = new HashSet<string>(await LoadAsync(path, cancellationToken), StringComparer.Ordinal) { guid };

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, guids, cancellationToken: cancellationToken);
    }
}
