using System.Security.Cryptography;

using SharpAdb.Services;

using Xunit;

namespace SharpAdb.IntegrationTests;

public class SyncIntegrationTests(AdbIntegrationFixture fixture) : IClassFixture<AdbIntegrationFixture>
{
    private readonly AdbIntegrationFixture _fixture = fixture;

    [SkippableFact]
    public async Task StatOnExistingDirectoryReturnsDirMode()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var stat = await sync.StatAsync("/data/local/tmp");
        Assert.True(stat.Exists);
        Assert.True(stat.IsDirectory, $"expected dir, mode=0x{stat.Mode:X}");
    }

    [SkippableFact]
    public async Task StatOnMissingPathReturnsZeroMode()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var stat = await sync.StatAsync("/data/local/tmp/__sharpadb_definitely_missing__");
        Assert.False(stat.Exists);
    }

    [SkippableFact]
    public async Task ListDirectoryEnumeratesEntries()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var count = 0;
        await foreach (var entry in sync.ListAsync("/system"))
        {
            Assert.False(string.IsNullOrEmpty(entry.Name));
            count++;
        }
        Assert.True(count > 1, $"expected /system to contain multiple entries, got {count}");
    }

    [SkippableFact]
    public async Task PushPullRoundTripPreservesBytes()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        var payload = RandomNumberGenerator.GetBytes(192 * 1024);
        var remotePath = $"/data/local/tmp/sharpadb_rt_{Guid.NewGuid():N}.bin";

        await using var conn = await _fixture.ConnectAsync();
        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            using var src = new MemoryStream(payload);
            await sync.PushAsync(src, remotePath);
        }

        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            var stat = await sync.StatAsync(remotePath);
            Assert.True(stat.Exists);
            Assert.Equal((uint)payload.Length, stat.Size);
        }

        byte[] roundtripped;
        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            using var dst = new MemoryStream(payload.Length);
            await sync.PullAsync(remotePath, dst);
            roundtripped = dst.ToArray();
        }

        Assert.Equal(payload.Length, roundtripped.Length);
        Assert.True(payload.AsSpan().SequenceEqual(roundtripped));

        // Cleanup.
        await conn.ExecuteAsync($"rm -f {remotePath}");
    }

    [SkippableFact]
    public async Task PullOfMissingFileFails()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await using var conn = await _fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        using var dst = new MemoryStream();
        await Assert.ThrowsAsync<IOException>(async () =>
            await sync.PullAsync("/data/local/tmp/__sharpadb_missing__", dst));
    }
}