namespace SharpAdb.Services;

/// <summary>
/// One row from <c>ps -A -o USER,PID,PPID,NAME</c>.
/// </summary>
/// <param name="Pid">Process id.</param>
/// <param name="Ppid">Parent process id, or null if the column couldn't be parsed.</param>
/// <param name="User">Owning username as reported by <c>ps</c> (e.g. <c>root</c>, <c>system</c>, <c>u0_a123</c>).</param>
/// <param name="Name">Process name (the <c>NAME</c> column from <c>ps</c>).</param>
public sealed record AdbProcess(int Pid, int? Ppid, string User, string Name);

/// <summary>
/// Extension methods for inspecting and signaling device processes.
/// </summary>
public static class ProcessExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Lists running processes via <c>ps -A -o USER,PID,PPID,NAME</c>.
        /// </summary>
        public async Task<IReadOnlyList<AdbProcess>> GetProcessesAsync(CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var output = await connection.ExecuteAsync("ps -A -o USER,PID,PPID,NAME", cancellationToken).ConfigureAwait(false);
            return ProcessParser.Parse(output);
        }

        /// <summary>
        /// Sends signal <paramref name="signal"/> (default SIGKILL) to the given pid via <c>kill</c>.
        /// </summary>
        public async Task KillAsync(int pid, int signal = 9, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            if (pid <= 1)
                throw new ArgumentOutOfRangeException(nameof(pid), "pid must be > 1");
            await connection.ExecuteAsync($"kill -{signal} {pid}", cancellationToken).ConfigureAwait(false);
        }
    }
}

internal static class ProcessParser
{
    public static List<AdbProcess> Parse(string output)
    {
        var list = new List<AdbProcess>();
        var first = true;
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();
            if (string.IsNullOrEmpty(line)) continue;
            if (first)
            {
                first = false;
                if (line.StartsWith("USER", StringComparison.Ordinal))
                    continue;
            }

            // Whitespace-separated columns: USER PID PPID NAME[...]
            var parts = line.Split([' ', '\t'], 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;
            if (!int.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out var pid)) continue;
            int? ppid = int.TryParse(parts[2], System.Globalization.CultureInfo.InvariantCulture, out var p) ? p : null;
            list.Add(new AdbProcess(pid, ppid, parts[0], parts[3]));
        }
        return list;
    }
}
