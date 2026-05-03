namespace SharpAdb.Services;

public enum RebootMode
{
    Normal,
    Bootloader,
    Recovery,
    Sideload,
    SideloadAutoReboot,
    Fastboot
}

public static class RebootExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>Reboot the device. Stream closes immediately; the device drops the connection while restarting.</summary>
        public async Task RebootAsync(RebootMode mode = RebootMode.Normal, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(connection);

            var suffix = mode switch
            {
                RebootMode.Normal => "",
                RebootMode.Bootloader => "bootloader",
                RebootMode.Recovery => "recovery",
                RebootMode.Sideload => "sideload",
                RebootMode.SideloadAutoReboot => "sideload-auto-reboot",
                RebootMode.Fastboot => "fastboot",
                _ => throw new ArgumentOutOfRangeException(nameof(mode))
            };

            await using var stream = await connection.OpenAsync($"reboot:{suffix}", cancellationToken).ConfigureAwait(false);
            // Drain anything the device sends before it goes down.
            var buf = new byte[64];
            try
            {
                while (await stream.ReadAsync(buf, cancellationToken).ConfigureAwait(false) > 0)
                { }
            }
            catch (IOException) { /* device disappeared as expected */ }
        }
    }
}
