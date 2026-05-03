namespace Theodicean.SharpAdb.Services;

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
        public Task SendKeyEventAsync(KeyCode key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            return connection.ExecuteAsync($"input keyevent {(int)key}", cancellationToken);
        }

        /// <summary>
        /// Sends a long-press key event via <c>input keyevent --longpress</c>.
        /// </summary>
        public Task SendLongPressAsync(KeyCode key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            return connection.ExecuteAsync($"input keyevent --longpress {(int)key}", cancellationToken);
        }

        /// <summary>
        /// Injects typed text via <c>input text</c>. Spaces become %s; quotes are escaped.
        /// </summary>
        public Task SendTextAsync(string text, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(text);
            // input text expects spaces encoded as %s.
            var escaped = ShellEscape.SingleQuote(text.Replace(" ", "%s"));
            return connection.ExecuteAsync($"input text {escaped}", cancellationToken);
        }

        /// <summary>
        /// Injects a tap at screen coordinates.
        /// </summary>
        public Task TapAsync(int x, int y, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            return connection.ExecuteAsync($"input tap {x} {y}", cancellationToken);
        }

        /// <summary>
        /// Injects a swipe.
        /// </summary>
        public Task SwipeAsync(int x1, int y1, int x2, int y2, int durationMs = 300, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            return connection.ExecuteAsync($"input swipe {x1} {y1} {x2} {y2} {durationMs}", cancellationToken);
        }

        /// <summary>
        /// Launches the default activity for an installed package via monkey.
        /// </summary>
        public async Task StartAppAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var output = await connection.ExecuteAsync(
                $"monkey -p {packageName} -c android.intent.category.LAUNCHER 1",
                cancellationToken).ConfigureAwait(false);
            if (output.Contains("No activities found", StringComparison.Ordinal))
                throw new InvalidOperationException($"No launcher activity for package '{packageName}'");
        }

        /// <summary>
        /// Launches a specific activity. <paramref name="component"/> is "pkg/.Activity" or "pkg/full.Activity".
        /// </summary>
        public async Task StartActivityAsync(string component, string? action = null, string? data = null,
            IReadOnlyDictionary<string, string>? extras = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(component);

            var args = new List<string>(8) { "am", "start", "-n", component };
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
                foreach (var (k, v) in extras)
                {
                    args.Add("--es");
                    args.Add(ShellEscape.SingleQuote(k));
                    args.Add(ShellEscape.SingleQuote(v));
                }
            }

            var result = await connection.ExecuteAsync(string.Join(' ', args), cancellationToken).ConfigureAwait(false);
            if (result.Contains("Error:", StringComparison.Ordinal))
                throw new InvalidOperationException($"am start failed: {result.Trim()}");
        }

        /// <summary>
        /// Force-stops an app: equivalent to <c>am force-stop</c>.
        /// </summary>
        public Task StopAppAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            return connection.ExecuteAsync($"am force-stop {packageName}", cancellationToken);
        }

        /// <summary>
        /// Clears app data: equivalent to <c>pm clear</c>.
        /// </summary>
        public async Task ClearAppDataAsync(string packageName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(packageName);
            AdbConnection.ValidatePackage(packageName);
            var result = await connection.ExecuteAsync($"pm clear {packageName}", cancellationToken).ConfigureAwait(false);
            if (!result.Contains("Success", StringComparison.Ordinal))
                throw new InvalidOperationException($"pm clear failed: {result.Trim()}");
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
