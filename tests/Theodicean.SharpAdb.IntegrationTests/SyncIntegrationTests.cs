using System.Security.Cryptography;

using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.IntegrationTests;

public class SyncIntegrationTests
{
    [ClassDataSource<AdbIntegrationFixture>(Shared = SharedType.PerClass)]
    public required AdbIntegrationFixture Fixture { get; init; }

    [Test]
    public async Task StatOnExistingDirectoryReturnsDirMode()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var stat = await sync.StatAsync("/data/local/tmp");
        await Assert.That(stat.Exists).IsTrue();
        await Assert.That(stat.IsDirectory).IsTrue();
    }

    [Test]
    public async Task StatOnMissingPathReturnsZeroMode()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var stat = await sync.StatAsync("/data/local/tmp/__sharpadb_definitely_missing__");
        await Assert.That(stat.Exists).IsFalse();
    }

    [Test]
    public async Task ListDirectoryEnumeratesEntries()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        var count = 0;
        await foreach (var entry in sync.ListAsync("/system"))
        {
            await Assert.That(entry.Name).IsNotNullOrWhiteSpace();
            count++;
        }
        await Assert.That(count).IsGreaterThan(1);
    }

    [Test]
    public async Task PushPullRoundTripPreservesBytes()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        var payload = RandomNumberGenerator.GetBytes(192 * 1024);
        var remotePath = $"/data/local/tmp/sharpadb_rt_{Guid.NewGuid():N}.bin";

        await using var conn = await Fixture.ConnectAsync();
        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            using var src = new MemoryStream(payload);
            await sync.PushAsync(src, remotePath);
        }

        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            var stat = await sync.StatAsync(remotePath);
            await Assert.That(stat.Exists).IsTrue();
            await Assert.That(stat.Size).IsEqualTo((uint)payload.Length);
        }

        byte[] roundTripped;
        await using (var sync = await SyncSession.OpenAsync(conn))
        {
            using var dst = new MemoryStream(payload.Length);
            await sync.PullAsync(remotePath, dst);
            roundTripped = dst.ToArray();
        }

        await Assert.That(roundTripped).Count().IsEqualTo(payload.Length);
        await Assert.That(payload.AsSpan().SequenceEqual(roundTripped)).IsTrue();

        // Cleanup.
        await conn.ExecuteAsync($"rm -f {remotePath}");
    }

    [Test]
    public async Task PullOfMissingFileFails()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await using var conn = await Fixture.ConnectAsync();
        await using var sync = await SyncSession.OpenAsync(conn);

        using var dst = new MemoryStream();
        await Assert.That(async () =>
            await sync.PullAsync("/data/local/tmp/__sharpadb_missing__", dst)).ThrowsExactly<IOException>();
    }
}
