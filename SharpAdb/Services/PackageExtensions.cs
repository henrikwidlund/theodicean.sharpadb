namespace SharpAdb.Services;

public sealed record AdbPackageInfo(string PackageName, string? Path = null);

public sealed class AdbPackageException : Exception
{
    public AdbPackageException(string message) : base(message) { }
}

public static class PackageExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>Install an APK by streaming it to /data/local/tmp and invoking <c>pm install</c>.</summary>
        public async Task InstallAsync(Stream apk, bool replaceExisting = true, bool grantAllPermissions = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(apk);

            var remotePath = $"/data/local/tmp/sharpadb_install_{Guid.NewGuid():N}.apk";
            await using (var sync = await SyncSession.OpenAsync(connection, cancellationToken).ConfigureAwait(false))
            {
                await sync.PushAsync(apk, remotePath, cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            try
            {
                var args = new List<string>(4) { "install" };
                if (replaceExisting)
                    args.Add("-r");

                if (grantAllPermissions)
                    args.Add("-g");

                args.Add(remotePath);

                var result = await connection.ExecuteAsync($"pm {string.Join(' ', args)}", cancellationToken).ConfigureAwait(false);
                // pm install prints "Success" on a line; otherwise contains "Failure [REASON]".
                if (!result.Contains("Success", StringComparison.Ordinal))
                    throw new AdbPackageException($"pm install failed: {result.Trim()}");
            }
            finally
            {
                try
                {
                    await connection.ExecuteAsync($"rm -f {remotePath}", CancellationToken.None).ConfigureAwait(false);
                }
                catch { /* best effort */ }
            }
        }

        /// <summary>Install an APK from a local file path.</summary>
        public async Task InstallAsync(string apkPath, bool replaceExisting = true, bool grantAllPermissions = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(apkPath);
            await using var fs = File.OpenRead(apkPath);
            await connection.InstallAsync(fs, replaceExisting, grantAllPermissions, cancellationToken).ConfigureAwait(false);
        }

        public async Task UninstallAsync(string packageName, bool keepData = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);

            var flag = keepData ? "-k " : "";
            var result = await connection.ExecuteAsync($"pm uninstall {flag}{packageName}", cancellationToken).ConfigureAwait(false);
            if (!result.Contains("Success", StringComparison.Ordinal))
                throw new AdbPackageException($"pm uninstall failed: {result.Trim()}");
        }

        public async Task<IReadOnlyList<AdbPackageInfo>> ListPackagesAsync(bool includePath = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var args = includePath ? "list packages -f" : "list packages";
            var output = await connection.ExecuteAsync($"pm {args}", cancellationToken).ConfigureAwait(false);
            return PackageParser.Parse(output);
        }

        public async Task<bool> IsInstalledAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var output = await connection.ExecuteAsync($"pm list packages {packageName}", cancellationToken).ConfigureAwait(false);
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
