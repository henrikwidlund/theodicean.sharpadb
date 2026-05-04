using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.IntegrationTests;

public class ShellIntegrationTests
{
    [ClassDataSource<AdbIntegrationFixture>(Shared = SharedType.PerClass)]
    public required AdbIntegrationFixture Fixture { get; init; }

    [Test]
    public async Task ConnectsAndReadsBanner()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await Assert.That(conn.DeviceInfo.SystemType).IsEqualTo("device");
        await Assert.That(conn.DeviceInfo.Banner).IsNotNullOrWhiteSpace();
    }

    [Test]
    public async Task EchoReturnsExpectedOutput()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var result = await conn.ExecuteAsync("echo sharpadb");
        await Assert.That(result).IsEqualTo("sharpadb\n");
    }

    [Test]
    public async Task GetPropReturnsModel()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        var model = (await conn.ExecuteAsync("getprop ro.product.model")).TrimEnd();
        await Assert.That(model).IsNotNullOrWhiteSpace();
    }

    [Test]
    public async Task LargeShellOutputDoesNotTruncate()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        // Generate ~256 KB of output to exercise multi-WRTE/OKAY chunking.
        var result = await conn.ExecuteAsync("dd if=/dev/zero bs=1024 count=256 2>/dev/null | base64 | tr -d '\\n'");
        await Assert.That(result).Length().IsGreaterThan(200_000);
    }

    [Test]
    public async Task ConcurrentShellsRunIndependently()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();

        var a = conn.ExecuteAsync("echo first");
        var b = conn.ExecuteAsync("echo second");
        var c = conn.ExecuteAsync("echo third");

        var results = await Task.WhenAll(a, b, c);
        await Assert.That(results[0]).IsEqualTo("first\n");
        await Assert.That(results[1]).IsEqualTo("second\n");
        await Assert.That(results[2]).IsEqualTo("third\n");
    }
}
