using System.Runtime.CompilerServices;

namespace SharpAdb.Services;

public enum LogcatPriority
{
    Verbose, Debug, Info, Warn, Error, Fatal, Silent
}

public sealed record LogcatEntry(in LogcatPriority Priority, string Tag, in int Pid, in int Tid, string Message, string Raw);

public static class LogcatExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>Stream raw logcat lines until canceled.</summary>
        public IAsyncEnumerable<string> LogcatRawAsync(string? filterSpec = null, bool dumpAndExit = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var args = new List<string>(4)
            {
                "logcat"
            };

            if (dumpAndExit)
                args.Add("-d");

            args.Add("-v");
            args.Add("threadtime");

            if (!string.IsNullOrEmpty(filterSpec))
                args.Add(filterSpec);

            return connection.ExecuteLinesAsync(string.Join(' ', args), cancellationToken);
        }

        /// <summary>Stream parsed logcat entries (threadtime format) until cancelled.</summary>
        public async IAsyncEnumerable<LogcatEntry> LogcatAsync(string? filterSpec = null, bool dumpAndExit = false,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await foreach (var line in connection.LogcatRawAsync(filterSpec, dumpAndExit, cancellationToken).ConfigureAwait(false))
            {
                if (LogcatParser.TryParseThreadTime(line, out var entry))
                    yield return entry;
            }
        }
    }
}

internal static class LogcatParser
{
    /// <summary>
    /// Parse a single line in threadtime format:
    /// <code>MM-DD HH:MM:SS.mmm  PID  TID PRIO TAG: MESSAGE</code>
    /// </summary>
    public static bool TryParseThreadTime(string line, out LogcatEntry entry)
    {
        entry = null!;
        if (string.IsNullOrEmpty(line)) return false;

        // Skip optional date+time (everything up to the first run that contains a digit followed by space-then-digit pattern).
        // Simpler: trim leading whitespace, find tokens.
        var s = line.AsSpan().TrimStart();
        // Format: "MM-DD HH:MM:SS.mmm  PID  TID L TAG: MESSAGE"
        // We need to skip 2 whitespace-separated tokens (date, time), then read pid, tid, priority, "tag: msg".
        if (!Skip(ref s, 2))
            return false;

        if (!ReadInt(ref s, out var pid))
            return false;
        if (!ReadInt(ref s, out var tid))
            return false;
        if (!ReadChar(ref s, out var prio))
            return false;

        s = s.TrimStart();
        var colon = s.IndexOf(':');
        if (colon < 0)
            return false;

        var tag = s[..colon].TrimEnd().ToString();
        var message = s[(colon + 1)..].TrimStart().ToString();

        entry = new LogcatEntry(MapPriority(prio), tag, pid, tid, message, line);
        return true;
    }

    private static bool Skip(ref ReadOnlySpan<char> s, in int tokenCount)
    {
        for (var i = 0; i < tokenCount; i++)
        {
            s = s.TrimStart();
            var sp = s.IndexOf(' ');
            if (sp < 0)
                return false;

            s = s[sp..];
        }

        s = s.TrimStart();
        return true;
    }

    private static bool ReadInt(ref ReadOnlySpan<char> s, out int value)
    {
        s = s.TrimStart();
        var end = 0;
        while (end < s.Length && char.IsAsciiDigit(s[end]))
            end++;

        if (end == 0)
        {
            value = 0;
            return false;
        }

        var ok = int.TryParse(s[..end], out value);
        s = s[end..];
        return ok;
    }

    private static bool ReadChar(ref ReadOnlySpan<char> s, out char value)
    {
        s = s.TrimStart();
        if (s.IsEmpty)
        {
            value = '\0';
            return false;
        }

        value = s[0];
        s = s[1..];
        return true;
    }

    private static LogcatPriority MapPriority(in char c) => c switch
    {
        'V' => LogcatPriority.Verbose,
        'D' => LogcatPriority.Debug,
        'I' => LogcatPriority.Info,
        'W' => LogcatPriority.Warn,
        'E' => LogcatPriority.Error,
        'F' => LogcatPriority.Fatal,
        'S' => LogcatPriority.Silent,
        _ => LogcatPriority.Verbose
    };
}
