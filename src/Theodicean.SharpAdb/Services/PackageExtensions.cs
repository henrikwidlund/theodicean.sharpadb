using System.Buffers;
using System.Globalization;
using System.Text;

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
        // Happy path: pm prints "Success" as its own line on stdout and exits 0. Match the
        // exact line (after trim) — a substring search would false-positive on commands
        // that mention "Success" elsewhere in their output.
        if (raw.IsSuccess && ContainsSuccessLine(raw.Stdout))
            return new AdbPackageOperationResult(true, null, raw);

        // Failure: pm prints "Failure [REASON]" on stdout (some Android builds route it to
        // stderr instead). Extract the bracketed reason if present.
        return new AdbPackageOperationResult(
            IsSuccess: false,
            FailureReason: ExtractBracketed(raw.Stdout) ?? ExtractBracketed(raw.Stderr),
            Raw: raw);
    }

    private static bool ContainsSuccessLine(string s)
    {
        foreach (var line in s.AsSpan().EnumerateLines())
        {
            if (line.Trim() is "Success")
                return true;
        }
        return false;
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
        /// Installs an APK by streaming it through <c>cmd package install</c> over a shell_v2
        /// stdin channel. No temporary file is written to the device — the APK bytes go
        /// straight from <paramref name="apk"/> into the installer.
        /// </summary>
        /// <param name="apk">APK contents. Must be seekable so the size can be passed to
        /// <c>cmd package install -S &lt;size&gt;</c>; <see cref="ArgumentException"/> is thrown
        /// otherwise.</param>
        /// <param name="replaceExisting">Pass <c>-r</c> to replace an already-installed package.</param>
        /// <param name="grantAllPermissions">Pass <c>-g</c> to grant all runtime permissions on install.</param>
        /// <param name="cancellationToken">Cancels the install.</param>
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
            if (!apk.CanRead)
                throw new ArgumentException("APK stream must be readable.", nameof(apk));
            if (!apk.CanSeek)
                throw new ArgumentException("APK stream must be seekable so its size can be advertised to cmd package install.", nameof(apk));

            // Stream.Position is settable past Length on writable streams; guard so we don't
            // hand cmd package install a negative -S value (it would refuse the install with a
            // confusing diagnostic at best, undefined behavior at worst).
            var size = apk.Length - apk.Position;
            if (size <= 0)
                throw new ArgumentException(
                    string.Create(CultureInfo.InvariantCulture, $"APK stream has {size} bytes remaining from its current position ({apk.Position} / {apk.Length})."),
                    nameof(apk));

            var args = new List<string>(8) { "cmd", "package", "install" };
            if (replaceExisting)
                args.Add("-r");
            if (grantAllPermissions)
                args.Add("-g");
            args.Add("-S");
            args.Add(size.ToString(CultureInfo.InvariantCulture));
            args.Add("-");
            var command = string.Join(' ', args);

            await using var session = await connection.OpenShellAsync(command, cancellationToken);
            using var stdoutMs = new MemoryStream();
            using var stderrMs = new MemoryStream();

            var stdinPump = PumpStdinAsync(session, apk, size, cancellationToken);
            var stdoutCopy = session.Stdout.CopyToAsync(stdoutMs, cancellationToken);
            var stderrCopy = session.Stderr.CopyToAsync(stderrMs, cancellationToken);
            await Task.WhenAll(stdinPump, stdoutCopy, stderrCopy);

            var exitCode = await session.ExitCodeTask.WaitAsync(cancellationToken);

            var raw = new AdbShellResult(
                Encoding.UTF8.GetString(stdoutMs.GetBuffer(), 0, (int)stdoutMs.Length),
                Encoding.UTF8.GetString(stderrMs.GetBuffer(), 0, (int)stderrMs.Length),
                exitCode);
            return AdbPackageOperationResult.Parse(raw);
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

    private static async Task PumpStdinAsync(ShellSession session, Stream apk, long size, CancellationToken cancellationToken)
    {
        // Stream the APK in 256 KiB chunks. ADB's WRTE flow control is OKAY-per-WRTE, so over
        // TCP the achievable throughput is bounded by `chunk size / round-trip-time`. At a
        // typical Wi-Fi RTT of ~10 ms, 64 KiB caps at ~6 MB/s; 256 KiB gives ~25 MB/s. Larger
        // chunks help further (up to the negotiated MaxPayload, usually 1 MiB) at the cost
        // of bigger ArrayPool rentals inside WriteStdinAsync. 256 KiB is the balance point.
        const int chunkSize = 256 * 1024;
        var buf = ArrayPool<byte>.Shared.Rent(chunkSize);
        var remaining = size;
        try
        {
            while (remaining > 0)
            {
                // Cap each read at the bytes we still owe the device. `cmd package install -S N`
                // reads exactly N bytes; anything we ship past N would back up in the kernel
                // TCP buffer (the server stopped reading), hanging the next WriteStdinAsync.
                var toRead = (int)Math.Min(remaining, chunkSize);
                var n = await apk.ReadAsync(buf.AsMemory(0, toRead), cancellationToken);
                if (n == 0)
                {
                    // Source stream ended before producing the advertised size — the device
                    // is still waiting for the remaining bytes, so just CloseStdin would
                    // leave it to fail with a vaguer diagnostic. Surface the truncation
                    // explicitly so the caller knows their input lied about its length.
                    throw new IOException(string.Create(CultureInfo.InvariantCulture,
                        $"APK stream ended after {size - remaining} bytes; advertised size was {size}."));
                }

                try
                {
                    await session.WriteStdinAsync(buf.AsMemory(0, n), cancellationToken);
                }
                catch (IOException)
                {
                    // Stdin write failed: either the device closed our stream after emitting
                    // a Failure (race — EXIT may not yet have arrived through the read loop)
                    // or the transport itself is dying. In both cases the concurrent
                    // stdoutCopy / stderrCopy / ExitCodeTask will surface the real outcome —
                    // a parsed Failure on the device-side error path, or a genuine fault on
                    // the transport-failure path. Swallow here so the install result isn't
                    // masked by a broken-pipe IOException from this pump.
                    return;
                }

                remaining -= n;
            }

            try
            {
                await session.CloseStdinAsync(cancellationToken);
            }
            catch (IOException)
            {
                // Same race as above: server may already have closed the stream after EXIT.
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
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
