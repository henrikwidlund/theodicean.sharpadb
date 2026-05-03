namespace SharpAdb.Services;

public static class ScreenExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Capture a PNG screenshot via <c>screencap -p</c>. Uses the <c>exec:</c> service which,
        /// unlike <c>shell:</c>, does not allocate a PTY — so binary output is not corrupted by
        /// LF→CRLF translation.
        /// </summary>
        public async Task<byte[]> CaptureScreenAsync(CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);

            await using var stream = await connection.OpenAsync("exec:screencap -p", cancellationToken).ConfigureAwait(false);
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);

            var bytes = ms.ToArray();
            if (bytes.Length < 8 || bytes[0] != 0x89 || bytes[1] != 0x50 || bytes[2] != 0x4E || bytes[3] != 0x47)
                throw new InvalidDataException("screencap output did not start with a PNG signature");
            return bytes;
        }

        /// <summary>Capture a PNG screenshot and write to <paramref name="destination"/>.</summary>
        public async Task CaptureScreenAsync(Stream destination, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(destination);
            var png = await connection.CaptureScreenAsync(cancellationToken).ConfigureAwait(false);
            await destination.WriteAsync(png, cancellationToken).ConfigureAwait(false);
        }
    }
}
