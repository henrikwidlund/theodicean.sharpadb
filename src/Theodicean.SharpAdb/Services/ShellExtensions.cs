using System.Runtime.CompilerServices;
using System.Text;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Extension methods for running shell commands on an <see cref="AdbConnection"/>.
/// </summary>
public static class ShellExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Runs a shell command and captures combined stdout/stderr as a string.
        /// </summary>
        public async Task<string> ExecuteAsync(string command, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(command);

            await using var stream = await connection.OpenAsync($"shell:{command}", cancellationToken).ConfigureAwait(false);
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        }

        /// <summary>
        /// Runs a shell command and pipes output bytes to <paramref name="destination"/>.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public async Task ExecuteAsync(string command, Stream destination, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(destination);
            ArgumentException.ThrowIfNullOrEmpty(command);

            await using var stream = await connection.OpenAsync($"shell:{command}", cancellationToken).ConfigureAwait(false);
            await stream.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Opens an interactive shell stream for streaming I/O.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public Task<AdbStream> OpenShellAsync(string? command = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            var svc = string.IsNullOrEmpty(command) ? "shell:" : $"shell:{command}";
            return connection.OpenAsync(svc, cancellationToken);
        }

        /// <summary>
        /// Runs a shell command and yields each output line. Lines are split on LF; trailing CR is stripped.
        /// </summary>
        public IAsyncEnumerable<string> ExecuteLinesAsync(string command, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentException.ThrowIfNullOrEmpty(command);

            return ExecuteLines(connection, command, cancellationToken);

            static async IAsyncEnumerable<string> ExecuteLines(AdbConnection connection, string command, [EnumeratorCancellation] CancellationToken cancellationToken)
            {
                await using var stream = await connection.OpenAsync($"shell:{command}", cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
                    yield return line;
            }
        }
    }
}
