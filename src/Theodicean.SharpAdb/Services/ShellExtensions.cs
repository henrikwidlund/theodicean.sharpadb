using System.Runtime.CompilerServices;
using System.Text;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Captured output of a shell_v2 command: separate stdout / stderr buffers plus the device's
/// exit code.
/// </summary>
/// <param name="Stdout">Bytes received on the stdout packet stream, decoded as UTF-8.</param>
/// <param name="Stderr">Bytes received on the stderr packet stream, decoded as UTF-8.</param>
/// <param name="ExitCode">Exit code reported by the device's EXIT packet.</param>
public sealed record AdbShellResult(string Stdout, string Stderr, int ExitCode)
{
    /// <summary>
    /// <see langword="true"/> when the remote command exited with status 0 (POSIX success).
    /// A few Android tools — notably <c>monkey</c> — exit 0 even when they did not do what
    /// was asked; consult the specific wrapper's documentation for any extra checks worth
    /// running against <see cref="Stdout"/> / <see cref="Stderr"/>.
    /// </summary>
    public bool IsSuccess => ExitCode == 0;
}

/// <summary>
/// Extension methods for running shell commands on an <see cref="AdbConnection"/>. All paths
/// use the shell_v2 sub-protocol (Android 7+) which gives proper exit codes, separate stderr,
/// and binary-clean output. Connections targeting devices without the <c>shell_v2</c> feature
/// in their CNXN banner will throw <see cref="NotSupportedException"/>.
/// </summary>
public static class ShellExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Runs a shell command via shell_v2, capturing stdout, stderr, and the exit code.
        /// </summary>
        public async Task<AdbShellResult> ExecuteAsync(string command, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(command);
            EnsureShellV2(connection);

            await using var session = await OpenShellInternal(connection, command, cancellationToken);
            using var stdoutMs = new MemoryStream();
            using var stderrMs = new MemoryStream();

            var stdoutCopy = session.Stdout.CopyToAsync(stdoutMs, cancellationToken);
            var stderrCopy = session.Stderr.CopyToAsync(stderrMs, cancellationToken);
            await Task.WhenAll(stdoutCopy, stderrCopy);

            var exitCode = await session.ExitCodeTask.WaitAsync(cancellationToken);

            return new AdbShellResult(
                Encoding.UTF8.GetString(stdoutMs.GetBuffer(), 0, (int)stdoutMs.Length),
                Encoding.UTF8.GetString(stderrMs.GetBuffer(), 0, (int)stderrMs.Length),
                exitCode);
        }

        /// <summary>
        /// Opens an interactive shell_v2 session for streaming I/O.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public Task<ShellSession> OpenShellAsync(string? command = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            EnsureShellV2(connection);
            return OpenShellInternal(connection, command, cancellationToken);
        }

        /// <summary>
        /// Runs a shell command and yields each stdout line. Lines are split on LF; trailing CR
        /// is stripped. Stderr is discarded; use <see cref="ExecuteAsync"/> or
        /// <see cref="OpenShellAsync"/> if you need it. The enumeration ends when the device
        /// sends EXIT — the exit code itself is not surfaced through this API.
        /// </summary>
        public IAsyncEnumerable<string> ExecuteLinesAsync(string command, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(command);
            EnsureShellV2(connection);

            return ExecuteLines(connection, command, cancellationToken);

            static async IAsyncEnumerable<string> ExecuteLines(AdbConnection conn, string command, [EnumeratorCancellation] CancellationToken cancellationToken)
            {
                await using var session = await OpenShellInternal(conn, command, cancellationToken);
                // Drain stderr in the background. The ShellSession's read loop blocks when
                // either pipe applies backpressure, so leaving stderr unread would stall
                // stdout (and the EXIT packet) the moment a command emits enough stderr to
                // fill its pipe — hanging this iterator. Discarding the bytes is the right
                // behavior for ExecuteLinesAsync; callers wanting stderr should use
                // ExecuteAsync or OpenShellAsync directly.
                var stderrDrain = session.Stderr.CopyToAsync(Stream.Null, cancellationToken);

                // Observe any drain fault even if the consumer abandons the enumerator early
                // (in which case code after the loop below never runs). Without this the
                // exception would surface only at GC time as an unobserved-task exception.
                _ = stderrDrain.ContinueWith(static t => _ = t.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);

                try
                {
                    using var reader = new StreamReader(session.Stdout, Encoding.UTF8, leaveOpen: true);
                    while (await reader.ReadLineAsync(cancellationToken) is { } line)
                        yield return line;
                }
                finally
                {
                    // Normal-completion path: surface a drain fault to the caller. Early-break
                    // path: the ContinueWith above already observed it; this await throws but
                    // is invoked from disposal so the original break is preserved.
                    try
                    {
                        await stderrDrain;
                    }
                    catch
                    {
                        // Swallow inside finally so we don't replace the user's own exception.
                    }
                }
            }
        }
    }

    private static async Task<ShellSession> OpenShellInternal(AdbConnection conn, string? command, CancellationToken cancellationToken)
    {
        // shell,v2,raw: opts into the packetized protocol with no PTY. PTY allocation would
        // wrap stdout in line-discipline (LF→CRLF) — undesirable for programmatic use and
        // unusable for binary output. Callers wanting a PTY can OpenAsync directly with the
        // verbatim service string.
        var service = string.IsNullOrEmpty(command) ? "shell,v2,raw:" : $"shell,v2,raw:{command}";
        var stream = await conn.OpenAsync(service, cancellationToken);
        return new ShellSession(stream);
    }

    private static void EnsureShellV2(AdbConnection conn)
    {
        if (!conn.DeviceInfo.Features.Contains(ShellV2Protocol.FeatureFlag))
            throw new NotSupportedException(
                $"Device does not advertise the '{ShellV2Protocol.FeatureFlag}' feature in its CNXN banner. " +
                "This library targets Android 7+ devices that speak shell_v2.");
    }
}
