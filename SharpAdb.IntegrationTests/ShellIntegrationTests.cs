using SharpAdb.Services;

using Xunit;

namespace SharpAdb.IntegrationTests;

public class ShellIntegrationTests(AdbIntegrationFixture fixture) : IClassFixture<AdbIntegrationFixture>
{
    private readonly AdbIntegrationFixture _fixture = fixture;

    [SkippableFact]
    public async Task ConnectsAndReadsBanner()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        Assert.Equal("device", conn.DeviceInfo.SystemType);
        Assert.False(string.IsNullOrEmpty(conn.DeviceInfo.Banner));
    }

    [SkippableFact]
    public async Task EchoReturnsExpectedOutput()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        var result = await conn.ExecuteAsync("echo sharpadb");
        Assert.Equal("sharpadb\n", result);
    }

    [SkippableFact]
    public async Task GetPropReturnsModel()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        var model = (await conn.ExecuteAsync("getprop ro.product.model")).TrimEnd();
        Assert.False(string.IsNullOrWhiteSpace(model));
    }

    [SkippableFact]
    public async Task LargeShellOutputDoesNotTruncate()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        // Generate ~256 KB of output to exercise multi-WRTE/OKAY chunking.
        var result = await conn.ExecuteAsync("dd if=/dev/zero bs=1024 count=256 2>/dev/null | base64 | tr -d '\\n'");
        Assert.True(result.Length > 200_000, $"expected >200k chars, got {result.Length}");
    }

    [SkippableFact]
    public async Task ConcurrentShellsRunIndependently()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();

        var a = conn.ExecuteAsync("echo first");
        var b = conn.ExecuteAsync("echo second");
        var c = conn.ExecuteAsync("echo third");

        var results = await Task.WhenAll(a, b, c);
        Assert.Equal("first\n", results[0]);
        Assert.Equal("second\n", results[1]);
        Assert.Equal("third\n", results[2]);
    }
}