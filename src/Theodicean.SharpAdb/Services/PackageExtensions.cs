namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Information about an installed package returned by <c>pm list packages</c>.
/// </summary>
/// <param name="PackageName">Application id (e.g. <c>com.example.app</c>).</param>
/// <param name="Path">APK path on device, populated only when listed with <c>includePath: <see langword="true"/></c>.</param>
public sealed record AdbPackageInfo(string PackageName, string? Path = null);

/// <summary>
/// Result of a package management operation that emits <c>"Success"</c> / <c>"Failure [REASON]"</c>
/// on stdout (currently <c>pm install</c> and <c>pm uninstall</c>). Encapsulates the success
/// parsing so callers don't have to grep stdout themselves.
/// </summary>
/// <param name="IsSuccess">
/// <see langword="true"/> when the device reported <c>"Success"</c> and exited 0.
/// </param>
/// <param name="FailureReason">
/// On failure, the bracketed reason code (e.g. <c>"INSTALL_FAILED_INSUFFICIENT_STORAGE"</c>)
/// extracted from the <c>"Failure [REASON]"</c> line, or <see langword="null"/> if the device
/// did not print one. Always <see langword="null"/> on success.
/// </param>
/// <param name="Raw">The underlying shell result, in case the caller needs the unparsed output.</param>
// ReSharper disable NotAccessedPositionalProperty.Global
public sealed record AdbPackageOperationResult(bool IsSuccess, string? FailureReason, AdbShellResult Raw)
// ReSharper restore NotAccessedPositionalProperty.Global
{
    internal static AdbPackageOperationResult Parse(AdbShellResult raw)
    {
        // Happy path: pm prints "Success" on stdout and exits 0.
        if (raw.IsSuccess && raw.Stdout.Contains("Success", StringComparison.Ordinal))
            return new AdbPackageOperationResult(true, null, raw);

        // Failure: pm prints "Failure [REASON]" on stdout (some Android builds route it to
        // stderr instead). Extract the bracketed reason if present.
        return new AdbPackageOperationResult(
            IsSuccess: false,
            FailureReason: ExtractBracketed(raw.Stdout) ?? ExtractBracketed(raw.Stderr),
            Raw: raw);
    }

    private static string? ExtractBracketed(string s)
    {
        var open = s.IndexOf('[', StringComparison.Ordinal);
        if (open < 0) return null;
        var close = s.IndexOf(']', open + 1);
        return close > open + 1 ? s[(open + 1)..close] : null;
    }
}

/// <summary>
/// Extension methods for installing, removing, and listing packages on a device.
/// </summary>
public static class PackageExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Installs an APK by streaming it to <c>/data/local/tmp</c> and invoking
        /// <c>pm install</c>. The temporary file is always cleaned up, even if the install
        /// itself fails.
        /// </summary>
        /// <returns>
        /// An <see cref="AdbPackageOperationResult"/> with <c>IsSuccess</c> reflecting whether
        /// the device reported <c>"Success"</c>; on failure, <c>FailureReason</c> carries the
        /// parsed reason code (e.g. <c>INSTALL_FAILED_INSUFFICIENT_STORAGE</c>) when one was
        /// emitted.
        /// </returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public async Task<AdbPackageOperationResult> InstallAsync(Stream apk, bool replaceExisting = true, bool grantAllPermissions = false,
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

                args.Add(ShellEscape.SingleQuote(remotePath));

                var raw = await connection.ExecuteAsync($"pm {string.Join(' ', args)}", cancellationToken);
                return AdbPackageOperationResult.Parse(raw);
            }
            finally
            {
                try
                {
                    await connection.ExecuteAsync($"rm -f {ShellEscape.SingleQuote(remotePath)}", CancellationToken.None);
                }
                catch { /* best effort */ }
            }
        }

        /// <summary>
        /// Installs an APK from a local file path.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task<AdbPackageOperationResult> InstallAsync(string apkPath, bool replaceExisting = true, bool grantAllPermissions = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(apkPath);
            await using var fs = File.OpenRead(apkPath);
            return await connection.InstallAsync(fs, replaceExisting, grantAllPermissions, cancellationToken);
        }

        /// <summary>
        /// Uninstalls a package by id. Set <paramref name="keepData"/> to preserve the app's
        /// data directory.
        /// </summary>
        /// <returns>
        /// An <see cref="AdbPackageOperationResult"/> with <c>IsSuccess</c> reflecting whether
        /// the device reported <c>"Success"</c>; on failure, <c>FailureReason</c> carries the
        /// parsed reason code when one was emitted (e.g. when the package was not installed).
        /// </returns>
        // ReSharper disable once UnusedMember.Global
        public async Task<AdbPackageOperationResult> UninstallAsync(string packageName, bool keepData = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);

            var flag = keepData ? "-k " : "";
            var raw = await connection.ExecuteAsync($"pm uninstall {flag}{ShellEscape.SingleQuote(packageName)}", cancellationToken);
            return AdbPackageOperationResult.Parse(raw);
        }

        /// <summary>
        /// Lists installed packages. Set <paramref name="includePath"/> to also populate <see cref="AdbPackageInfo.Path"/>.
        /// </summary>
        public async Task<IReadOnlyList<AdbPackageInfo>> ListPackagesAsync(bool includePath = false, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var args = includePath ? "list packages -f" : "list packages";
            var result = await connection.ExecuteAsync($"pm {args}", cancellationToken);
            return PackageParser.Parse(result.Stdout);
        }

        /// <summary>
        /// Returns <see langword="true"/> when a package with this exact id is installed on the device.
        /// </summary>
        public async Task<bool> IsInstalledAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var result = await connection.ExecuteAsync($"pm list packages {ShellEscape.SingleQuote(packageName)}", cancellationToken);
            // Match "package:exact.name\n" anywhere in output.
            var needle = $"package:{packageName}";
            var outputSpan = result.Stdout.AsSpan();
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
        var outputSpan = output.AsSpan();
        foreach (var lineRange in outputSpan.Split('\n'))
        {
            var line = outputSpan[lineRange].TrimEnd('\r');
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
