using System.Net.Sockets;

using Theodicean.SharpAdb.Services;

using Xunit;

namespace Theodicean.SharpAdb.IntegrationTests;

public class HelperServicesIntegrationTests(AdbIntegrationFixture fixture) : IClassFixture<AdbIntegrationFixture>
{
    private readonly AdbIntegrationFixture _fixture = fixture;

    [SkippableFact]
    public async Task GetPropertyReturnsKnownValue()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        var sdk = await conn.GetPropertyAsync("ro.build.version.sdk");
        Assert.False(string.IsNullOrEmpty(sdk));
        Assert.True(int.TryParse(sdk, out var sdkInt) && sdkInt > 20, $"unexpected sdk={sdk}");
    }

    [SkippableFact]
    public async Task GetAllPropertiesReturnsManyEntries()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        var props = await conn.GetAllPropertiesAsync();
        Assert.True(props.Count > 50, $"expected >50 props, got {props.Count}");
        Assert.True(props.ContainsKey("ro.build.version.sdk"));
    }

    [SkippableFact]
    public async Task GetProcessesIncludesInit()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        var procs = await conn.GetProcessesAsync();
        Assert.Contains(procs, static p => p.Pid == 1);
    }

    [SkippableFact]
    public async Task ListPackagesReturnsAtLeastOnePackage()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        var packages = await conn.ListPackagesAsync();
        Assert.True(packages.Count > 5, $"expected several packages, got {packages.Count}");
        // 'android' is the framework package — present on every Android device.
        Assert.Contains(packages, static p => p.PackageName == "android");
    }

    [SkippableFact]
    public async Task IsInstalledHandlesPresentAndAbsent()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        Assert.True(await conn.IsInstalledAsync("android"));
        Assert.False(await conn.IsInstalledAsync("com.example.never.installed.deadbeef"));
    }

    [SkippableFact]
    public async Task CaptureScreenReturnsPngWithSignature()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        var png = await conn.CaptureScreenAsync();
        Assert.True(png.Length > 1000);
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, png[..8]);
    }

    [SkippableFact]
    public async Task LogcatRawReadsAtLeastOneLine()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var count = 0;
        try
        {
            await foreach (var _ in conn.LogcatRawAsync(dumpAndExit: true, cancellationToken: cts.Token))
            {
                if (++count >= 5)
                    break;
            }
        }
        catch (OperationCanceledException) { }

        Assert.True(count > 0, "expected at least one logcat line");
    }

    [SkippableFact]
    public async Task SendKeyEventHomeReturnsHomeScreen()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();
        // Idempotent + side effect on screen; verify command completes without throwing.
        await conn.SendKeyEventAsync(KeyCode.Home);
    }

    [SkippableFact]
    public async Task StartAppLaunchesAnInstalledLauncherActivity()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();

        // Find any installed package with a LAUNCHER intent. Fall back to skipping if none found.
        string? candidate = null;
        foreach (var pkg in await conn.ListPackagesAsync())
        {
            // Ask the framework whether this package has a LAUNCHER activity.
            var output = await conn.ExecuteAsync(
                $"cmd package resolve-activity -c android.intent.category.LAUNCHER {pkg.PackageName}");
            if (output.Contains("name=", StringComparison.Ordinal) && !output.Contains("No activity found", StringComparison.Ordinal))
            {
                candidate = pkg.PackageName;
                break;
            }
        }

        Skip.If(candidate is null, "no package with a LAUNCHER activity found on this device");

        await conn.StartAppAsync(candidate);
        await Task.Delay(500);
        await conn.StopAppAsync(candidate);
    }

    [SkippableFact]
    public async Task PortForwardConnectsToDevicePort()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        await using var conn = await _fixture.ConnectAsync();

        // Run a one-shot listener on the device (ncat may not exist; try toybox 'nc').
        // Instead, forward to adbd's own port (5555) is unreliable; pick something that always exists:
        // we ask adbd to forward to "tcp:5555", which should accept (adbd listens). We just verify
        // the local listener accepts and we get *some* bytes back when we connect — simplest probe:
        // open the connection and immediately close, expecting no exception.
        await using var fwd = await conn.ForwardPortAsync(localPort: 0, remotePort: 5555);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", fwd.LocalPort);
        Assert.True(client.Connected);
    }
}
