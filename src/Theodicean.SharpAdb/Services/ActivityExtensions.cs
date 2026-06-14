using System.Globalization;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Result of an app-launch attempt via <c>monkey</c>. Encodes monkey's "exits 0 even when
/// nothing was launched" quirk by detecting the <c>"No activities found"</c> diagnostic.
/// </summary>
/// <param name="IsLaunched">
/// <see langword="true"/> when monkey actually launched the requested activity. A POSIX-clean
/// exit alone is not enough — see <see cref="AdbShellResult.IsSuccess"/> remarks.
/// </param>
/// <param name="FailureReason">
/// Diagnostic message extracted from monkey's output on failure (e.g.
/// <c>"No activities found"</c>), or <see langword="null"/> on success.
/// </param>
/// <param name="Raw">The underlying shell result.</param>
public sealed record AdbAppLaunchResult(bool IsLaunched, string? FailureReason, AdbShellResult Raw)
{
    internal static AdbAppLaunchResult Parse(AdbShellResult raw)
    {
        // monkey writes "No activities found" (sometimes "** No activities found ...") to one
        // of the standard streams when the package has no matching launcher activity. Treat
        // that as a hard failure regardless of the (zero) exit code.
        if (Contains(raw.Stdout, "No activities found") || Contains(raw.Stderr, "No activities found"))
            return new AdbAppLaunchResult(false, "No activities found", raw);

        if (!raw.IsSuccess)
            return new AdbAppLaunchResult(false, $"monkey exited with code {raw.ExitCode}", raw);

        return new AdbAppLaunchResult(true, null, raw);

        static bool Contains(string s, string needle) => s.Contains(needle, StringComparison.Ordinal);
    }
}

/// <summary>
/// Extension methods for input injection (key/touch) and app/activity lifecycle via <c>input</c>, <c>am</c>, <c>monkey</c>, and <c>pm</c>.
/// </summary>
public static class ActivityExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Sends a single key event via <c>input keyevent</c>.
        /// </summary>
        public async Task SendKeyEventAsync(KeyCode key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            await connection.ExecuteAsync(string.Create(CultureInfo.InvariantCulture, $"input keyevent {(int)key}"), cancellationToken);
        }

        /// <summary>
        /// Sends a long-press key event via <c>input keyevent --longpress</c>.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task SendLongPressAsync(KeyCode key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            await connection.ExecuteAsync(string.Create(CultureInfo.InvariantCulture, $"input keyevent --longpress {(int)key}"), cancellationToken);
        }

        /// <summary>
        /// Injects typed text via <c>input text</c>. Spaces become %s; quotes are escaped.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task SendTextAsync(string text, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(text);
            // input text expects spaces encoded as %s.
            var escaped = ShellEscape.SingleQuote(text.Replace(" ", "%s", StringComparison.Ordinal));
            await connection.ExecuteAsync($"input text {escaped}", cancellationToken);
        }

        /// <summary>
        /// Injects a tap at screen coordinates.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task TapAsync(int x, int y, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            await connection.ExecuteAsync(string.Create(CultureInfo.InvariantCulture, $"input tap {x} {y}"), cancellationToken);
        }

        /// <summary>
        /// Injects a swipe.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task SwipeAsync(int x1, int y1, int x2, int y2, int durationMs = 300, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            await connection.ExecuteAsync(string.Create(CultureInfo.InvariantCulture, $"input swipe {x1} {y1} {x2} {y2} {durationMs}"), cancellationToken);
        }

        /// <summary>
        /// Launches the default launcher activity for an installed package via <c>monkey</c>.
        /// </summary>
        /// <returns>
        /// An <see cref="AdbAppLaunchResult"/> with <c>IsLaunched</c> reflecting whether the
        /// activity actually started. The <c>monkey</c> tool exits 0 even when no launcher
        /// activity is found, so <see cref="AdbShellResult.IsSuccess"/> is not sufficient on
        /// its own — the wrapper checks for the <c>"No activities found"</c> diagnostic too.
        /// </returns>
        public async Task<AdbAppLaunchResult> StartAppAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var raw = await connection.ExecuteAsync(
                $"monkey -p {ShellEscape.SingleQuote(packageName)} -c android.intent.category.LAUNCHER 1", cancellationToken);
            return AdbAppLaunchResult.Parse(raw);
        }

        /// <summary>
        /// Launches a specific activity via <c>am start</c>. <paramref name="component"/> is
        /// <c>"pkg/.Activity"</c> or <c>"pkg/full.Activity"</c>.
        /// </summary>
        /// <remarks>
        /// On modern Android, <c>am start</c> returns a non-zero exit code when the launch
        /// fails, so <see cref="AdbShellResult.IsSuccess"/> is the primary check.
        /// <see cref="AdbShellResult.Stderr"/> carries the human-readable
        /// <c>"Error: ..."</c> message when launch fails (e.g. missing component or permission
        /// denied).
        /// </remarks>
        // ReSharper disable once UnusedMember.Global
        public Task<AdbShellResult> StartActivityAsync(string component, string? action = null, string? data = null,
            IReadOnlyDictionary<string, string>? extras = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(component);

            var args = new List<string>(8) { "am", "start", "-n", ShellEscape.SingleQuote(component) };
            if (action is not null)
            {
                args.Add("-a");
                args.Add(ShellEscape.SingleQuote(action));
            }

            if (data is not null)
            {
                args.Add("-d");
                args.Add(ShellEscape.SingleQuote(data));
            }

            if (extras is not null)
            {
                foreach ((string k, string v) in extras)
                {
                    args.Add("--es");
                    args.Add(ShellEscape.SingleQuote(k));
                    args.Add(ShellEscape.SingleQuote(v));
                }
            }

            return connection.ExecuteAsync(string.Join(' ', args), cancellationToken);
        }

        /// <summary>
        /// Force-stops an app: equivalent to <c>am force-stop</c>.
        /// </summary>
        public Task<AdbShellResult> StopAppAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            return connection.ExecuteAsync($"am force-stop {ShellEscape.SingleQuote(packageName)}", cancellationToken);
        }

        /// <summary>
        /// Clears all data for an installed package via <c>pm clear</c>.
        /// </summary>
        /// <remarks>
        /// <c>pm clear</c> reports the result on stdout: <c>"Success"</c> on the happy path,
        /// <c>"Failed"</c> followed by a reason otherwise. Use
        /// <see cref="AdbShellResult.IsSuccess"/> as the primary check and inspect
        /// <see cref="AdbShellResult.Stdout"/> if you need the reason text.
        /// </remarks>
        // ReSharper disable once UnusedMember.Global
        public Task<AdbShellResult> ClearAppDataAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            return connection.ExecuteAsync($"pm clear {packageName}", cancellationToken);
        }

        private static void ValidatePackage(string name)
        {
            foreach (var c in name)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '/'))
                    throw new ArgumentException($"Invalid package/component '{name}'", nameof(name));
            }
        }
    }
}
