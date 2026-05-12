namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Target mode for <c>RebootAsync</c>. Maps to the suffix of the ADB <c>reboot:</c> service.
/// </summary>
public enum RebootMode
{
    /// <summary>
    /// Reboots to normal Android.
    /// </summary>
    Normal,

    /// <summary>
    /// Reboots into the device bootloader (fastboot/download mode on most devices).
    /// </summary>
    Bootloader,

    /// <summary>
    /// Reboots into the recovery partition.
    /// </summary>
    Recovery,

    /// <summary>
    /// Reboots into sideload mode (recovery image accepting an OTA over <c>adb sideload</c>).
    /// </summary>
    Sideload,

    /// <summary>
    /// Reboots into sideload mode and automatically reboot once sideload completes.
    /// </summary>
    SideloadAutoReboot,

    /// <summary>
    /// Reboots directly into fastbootd (userspace fastboot, Android 10+).
    /// </summary>
    Fastboot
}

/// <summary>
/// Extension methods for rebooting a device via the <c>reboot:</c> service.
/// </summary>
// ReSharper disable once UnusedType.Global
public static class RebootExtensions
{
    // ReSharper disable once UnusedType.Global
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Reboots the device. Stream closes immediately; the device drops the connection while restarting.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
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

            await using var stream = await connection.OpenAsync($"reboot:{suffix}", cancellationToken);
            // Drain anything the device sends before it goes down. Any of these is expected when
            // the device tears the connection down: pipe completion (IOException), already-disposed
            // stream during shutdown (ObjectDisposedException), or caller-driven cancellation.
            var buf = new byte[64];
            try
            {
                while (await stream.ReadAsync(buf, cancellationToken) > 0)
                {
                    // Loop while we get data back
                }
            }
            catch (IOException)
            {
                // Ignore
            }
            catch (ObjectDisposedException)
            {
                // Ignore
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Ignore
            }
        }
    }
}
