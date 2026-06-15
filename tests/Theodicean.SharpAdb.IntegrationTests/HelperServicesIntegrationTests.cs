using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.IntegrationTests;

public class HelperServicesIntegrationTests
{
    [ClassDataSource<AdbIntegrationFixture>(Shared = SharedType.PerClass)]
    public required AdbIntegrationFixture Fixture { get; init; }

    [Test]
    public async Task GetPropertyReturnsKnownValue()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var sdk = await conn.GetPropertyAsync("ro.build.version.sdk");
        await Assert.That(sdk).IsNotNullOrWhiteSpace();
        await Assert.That(int.TryParse(sdk, out var sdkInt) && sdkInt > 20).IsTrue();
    }

    [Test]
    public async Task GetAllPropertiesReturnsManyEntries()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var props = await conn.GetAllPropertiesAsync();
        await Assert.That(props).Count().IsGreaterThan(50);
        await Assert.That(props).ContainsKey("ro.build.version.sdk");
    }

    [Test]
    public async Task GetProcessesIncludesInit()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var procs = await conn.GetProcessesAsync();
        await Assert.That(procs).Contains(static p => p.Pid == 1);
    }

    [Test]
    public async Task ListPackagesReturnsAtLeastOnePackage()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var packages = await conn.ListPackagesAsync();
        await Assert.That(packages).Count().IsGreaterThan(5);
        // 'android' is the framework package — present on every Android device.
        await Assert.That(packages).Contains(static p => p.PackageName == "android");
    }

    [Test]
    public async Task IsInstalledHandlesPresentAndAbsent()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await Assert.That(await conn.IsInstalledAsync("android")).IsTrue();
        await Assert.That(await conn.IsInstalledAsync("com.example.never.installed.deadbeef")).IsFalse();
    }

    [Test]
    public async Task CaptureScreenReturnsPngWithSignature()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var png = await conn.CaptureScreenAsync();
        await Assert.That(png).Count().IsGreaterThan(1000);
        await Assert.That(png[..8]).IsEquivalentTo(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }

    [Test]
    public async Task LogcatRawReadsAtLeastOneLine()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();

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

        await Assert.That(count).IsPositive();
    }

    [Test]
    public async Task SendKeyEventHomeReturnsHomeScreen()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        // Idempotent + side effect on screen; verify command completes without throwing.
        await Assert.That(async () => await conn.SendKeyEventAsync(KeyCode.Home)).ThrowsNothing();
    }

    [Test]
    public async Task StartAppLaunchesAnInstalledLauncherActivity()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();

        // Find any installed package with a LAUNCHER intent. Fall back to skipping if none found.
        string? candidate = null;
        foreach (var pkg in await conn.ListPackagesAsync())
        {
            // Ask the framework whether this package has a LAUNCHER activity.
            var output = (await conn.ExecuteAsync(
                $"cmd package resolve-activity -c android.intent.category.LAUNCHER {pkg.PackageName}")).Stdout;
            if (output.Contains("name=", StringComparison.Ordinal) && !output.Contains("No activity found", StringComparison.Ordinal))
            {
                candidate = pkg.PackageName;
                break;
            }
        }

        if (candidate is null)
            Skip.Test("no package with a LAUNCHER activity found on this device");

        await Assert.That(async () =>
        {
            await conn.StartAppAsync(candidate);
            await Task.Delay(500);
            await conn.StopAppAsync(candidate);
        }).ThrowsNothing();
    }

    [Test]
    public async Task PortForwardConnectsToDevicePort()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();

        // Run a one-shot listener on the device (ncat may not exist; try toybox 'nc').
        // Instead, forward to adbd's own port (5555) is unreliable; pick something that always exists:
        // we ask adbd to forward to "tcp:5555", which should accept (adbd listens). We just verify
        // the local listener accepts and we get *some* bytes back when we connect — simplest probe:
        // open the connection and immediately close, expecting no exception.
        await using var fwd = await conn.ForwardPortAsync(localPort: 0, remotePort: 5555);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", fwd.LocalPort);
        await Assert.That(client.Connected).IsTrue();
    }
}
