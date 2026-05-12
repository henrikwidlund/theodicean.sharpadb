namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Information about an installed package returned by <c>pm list packages</c>.
/// </summary>
/// <param name="PackageName">Application id (e.g. <c>com.example.app</c>).</param>
/// <param name="Path">APK path on device, populated only when listed with <c>includePath: <see langword="true"/></c>.</param>
public sealed record AdbPackageInfo(string PackageName, string? Path = null);

/// <summary>
/// Thrown when <c>pm install</c> or <c>pm uninstall</c> reports a non-success result.
/// </summary>
public sealed class AdbPackageException : Exception
{
    /// <summary>
    /// Initializes a new instance with the given diagnostic message.
    /// </summary>
    public AdbPackageException(string message) : base(message) { }
}

/// <summary>
/// Extension methods for installing, removing, and listing packages on a device.
/// </summary>
public static class PackageExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Installs an APK by streaming it to /data/local/tmp and invoking <c>pm install</c>.
        /// </summary>
        // ReSharper disable once MemberCanBePrivate.Global
        public async Task InstallAsync(Stream apk, bool replaceExisting = true, bool grantAllPermissions = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(apk);

            var remotePath = $"/data/local/tmp/sharpadb_install_{Guid.NewGuid():N}.apk";
            await using (var sync = await SyncSession.OpenAsync(connection, cancellationToken))
            {
                await sync.PushAsync(apk, remotePath, cancellationToken: cancellationToken);
            }

            try
            {
                var args = new List<string>(4) { "install" };
                if (replaceExisting)
                    args.Add("-r");

                if (grantAllPermissions)
                    args.Add("-g");

                args.Add(remotePath);

                var result = await connection.ExecuteAsync($"pm {string.Join(' ', args)}", cancellationToken);
                // pm install prints "Success" on a line; otherwise contains "Failure [REASON]".
                if (!result.Contains("Success", StringComparison.Ordinal))
                    throw new AdbPackageException($"pm install failed: {result.Trim()}");
            }
            finally
            {
                try
                {
                    await connection.ExecuteAsync($"rm -f {remotePath}", CancellationToken.None);
                }
                catch { /* best effort */ }
            }
        }

        /// <summary>
        /// Installs an APK from a local file path.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task InstallAsync(string apkPath, bool replaceExisting = true, bool grantAllPermissions = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(apkPath);
            await using var fs = File.OpenRead(apkPath);
            await connection.InstallAsync(fs, replaceExisting, grantAllPermissions, cancellationToken);
        }

        /// <summary>
        /// Uninstalls a package by id. Set <paramref name="keepData"/> to preserve the app's data directory.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task UninstallAsync(string packageName, bool keepData = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);

            var flag = keepData ? "-k " : "";
            var result = await connection.ExecuteAsync($"pm uninstall {flag}{packageName}", cancellationToken);
            if (!result.Contains("Success", StringComparison.Ordinal))
                throw new AdbPackageException($"pm uninstall failed: {result.Trim()}");
        }

        /// <summary>
        /// Lists installed packages. Set <paramref name="includePath"/> to also populate <see cref="AdbPackageInfo.Path"/>.
        /// </summary>
        public async Task<IReadOnlyList<AdbPackageInfo>> ListPackagesAsync(bool includePath = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var args = includePath ? "list packages -f" : "list packages";
            var output = await connection.ExecuteAsync($"pm {args}", cancellationToken);
            return PackageParser.Parse(output);
        }

        /// <summary>
        /// Returns <see langword="true"/> when a package with this exact id is installed on the device.
        /// </summary>
        public async Task<bool> IsInstalledAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var output = await connection.ExecuteAsync($"pm list packages {packageName}", cancellationToken);
            // Match "package:exact.name\n" anywhere in output.
            var needle = $"package:{packageName}";
            var outputSpan = output.AsSpan();
            foreach (var range in outputSpan.Split('\n'))
            {
                if (outputSpan[range].TrimEnd('\r').Equals(needle, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static void ValidatePackage(string name)
        {
            foreach (var c in name)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_'))
                    throw new ArgumentException($"Invalid package name '{name}'", nameof(name));
            }
        }
    }
}

internal static class PackageParser
{
    public static List<AdbPackageInfo> Parse(string output)
    {
        var list = new List<AdbPackageInfo>();
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.AsSpan().TrimEnd('\r');
            if (!line.StartsWith("package:"))
                continue;

            line = line["package:".Length..];

            // Two formats:
            //   package:NAME
            //   package:/path/to/base.apk=NAME
            var eq = line.LastIndexOf('=');
            if (eq < 0)
            {
                list.Add(new AdbPackageInfo(line.ToString()));
            }
            else
            {
                var path = line[..eq].ToString();
                var name = line[(eq + 1)..].ToString();
                list.Add(new AdbPackageInfo(name, Path: path));
            }
        }
        return list;
    }
}
