namespace SharpAdb.Services;

public static class PropertiesExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>Get a single property value, or null if missing/empty.</summary>
        public async Task<string?> GetPropertyAsync(string name, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(name);

            AdbConnection.ValidatePropName(name);
            var output = (await connection.ExecuteAsync($"getprop {name}", cancellationToken).ConfigureAwait(false)).TrimEnd('\r', '\n');
            return string.IsNullOrEmpty(output) ? null : output;
        }

        /// <summary>Set a property via setprop. Requires appropriate device permissions for the prop.</summary>
        public Task SetPropertyAsync(string name, string value, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(name);
            ArgumentNullException.ThrowIfNull(value);
            AdbConnection.ValidatePropName(name);

            var escaped = ShellEscape.SingleQuote(value);
            return connection.ExecuteAsync($"setprop {name} {escaped}", cancellationToken);
        }

        /// <summary>Read all device properties via <c>getprop</c>.</summary>
        public async Task<IReadOnlyDictionary<string, string>> GetAllPropertiesAsync(CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var output = await connection.ExecuteAsync("getprop", cancellationToken).ConfigureAwait(false);
            return PropertiesParser.Parse(output);
        }

        private static void ValidatePropName(string name)
        {
            // Properties match [a-zA-Z0-9._-]+ — reject anything that could allow shell injection.
            foreach (var c in name)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))
                    throw new ArgumentException($"Invalid property name '{name}'", nameof(name));
            }
        }
    }
}

internal static class PropertiesParser
{
    public static Dictionary<string, string> Parse(string output)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        var alternateLookup = dict.GetAlternateLookup<ReadOnlySpan<char>>();
        // Format: "[key]: [value]" per line.
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.AsSpan().TrimEnd('\r');
            if (line.Length < 6 || line[0] != '[')
                continue;

            var keyEnd = line.IndexOf(']');
            if (keyEnd < 1)
                continue;

            var key = line[1..keyEnd];

            // After "]: [" comes value, ending in "]".
            var valueStart = line[keyEnd..].IndexOf('[');
            if (valueStart < 0)
                continue;

            valueStart += keyEnd + 1;

            var valueEnd = line.LastIndexOf(']');
            if (valueEnd <= valueStart) continue;

            alternateLookup[key] = line[valueStart..valueEnd].ToString();
        }
        return dict;
    }
}

internal static class ShellEscape
{
    /// <summary>Wrap a string in single quotes for safe inclusion in a shell command.</summary>
    public static string SingleQuote(string value)
    {
        // POSIX trick: close-quote, escaped single quote, reopen-quote.
        return "'" + value.Replace("'", "'\\''") + "'";
    }
}
