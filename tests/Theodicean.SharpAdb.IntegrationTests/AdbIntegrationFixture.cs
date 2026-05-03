using Theodicean.SharpAdb.Auth;

namespace Theodicean.SharpAdb.IntegrationTests;

/// <summary>
/// Live-device integration test fixture. Reads target + key from environment so CI / local runs can opt in.
///
/// Required:
///   ADB_HOST       host:port of an adbd listening over TCP (e.g. "192.168.1.42:5555").
///                  Set up via: <c>adb tcpip 5555</c> then disconnect USB.
///
/// Optional:
///   ADB_KEY_PATH   path to an existing PEM RSA-2048 private key. Defaults to
///                  "$HOME/.android/adbkey" (the key adb itself uses). If neither exists, a fresh
///                  key is generated and saved at ADB_KEY_PATH (or ./sharpadb-test-key.pem); first
///                  run requires user to tap "Allow" on the device.
/// </summary>
public sealed class AdbIntegrationFixture : IAsyncDisposable
{
    public const string SkipReason =
        "Set ADB_HOST=host:port (e.g. ADB_HOST=192.168.1.42:5555) to run integration tests.";

    public string? Host { get; }
    public int Port { get; }
    public AdbAuthKey? Key { get; }
    public bool Available => Host is not null && Key is not null;

    public AdbIntegrationFixture()
    {
        var hostPort = Environment.GetEnvironmentVariable("ADB_HOST");
        if (string.IsNullOrWhiteSpace(hostPort))
            return;

        var colon = hostPort.LastIndexOf(':');
        if (colon < 0)
        {
            Host = hostPort;
            Port = 5555;
        }
        else
        {
            Host = hostPort[..colon];
            Port = int.Parse(hostPort[(colon + 1)..]);
        }

        var defaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".android", "adbkey2");
        if (!Directory.Exists(defaultPath))
            Directory.CreateDirectory(defaultPath);

        var keyPath = Environment.GetEnvironmentVariable("ADB_KEY_PATH") ?? Path.Combine(defaultPath, "sharpadb-test-key.pem");

        if (File.Exists(keyPath))
        {
            Key = AdbAuthKey.LoadFromPem(File.ReadAllText(keyPath));
        }
        else
        {
            Key = AdbAuthKey.Generate();
            File.WriteAllText(keyPath, Key.ExportPrivateKeyPem());
        }
    }

    public async Task<AdbConnection> ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (!Available)
            throw new InvalidOperationException(SkipReason);
        return await AdbConnection.ConnectTcpAsync(Host!, Port, [Key!], cancellationToken: cancellationToken);
    }

    public async Task<AdbConnection> ConnectWithAsync(
        IReadOnlyList<AdbAuthKey> keys,
        AdbConnectOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (Host is null)
            throw new InvalidOperationException(SkipReason);
        return await AdbConnection.ConnectTcpAsync(Host, Port, keys, options, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        Key?.Dispose();
        return ValueTask.CompletedTask;
    }
}
