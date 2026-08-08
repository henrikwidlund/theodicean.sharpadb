using System;
using System.IO;
using System.Threading.Tasks;

using Theodicean.SharpAdb.Pairing;

namespace Theodicean.SharpAdb.Tests;

public class AdbKnownHostsTests
{
    private static string TempPath() => Path.Combine(Path.GetTempPath(), $"sharpadb_known_hosts_test_{Guid.NewGuid():N}.json");

    [Test]
    public async Task LoadReturnsEmptySetWhenFileDoesNotExist()
    {
        var path = TempPath();
        var hosts = await AdbKnownHosts.LoadAsync(path);
        await Assert.That(hosts).IsEmpty();
    }

    [Test]
    public async Task AddThenContainsRoundTrips()
    {
        var path = TempPath();
        try
        {
            await Assert.That(await AdbKnownHosts.ContainsAsync("device-guid-1", path)).IsFalse();

            await AdbKnownHosts.AddAsync("device-guid-1", path);

            await Assert.That(await AdbKnownHosts.ContainsAsync("device-guid-1", path)).IsTrue();
            await Assert.That(await AdbKnownHosts.ContainsAsync("some-other-guid", path)).IsFalse();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task AddIsIdempotentAndPreservesOtherEntries()
    {
        var path = TempPath();
        try
        {
            await AdbKnownHosts.AddAsync("guid-a", path);
            await AdbKnownHosts.AddAsync("guid-b", path);
            await AdbKnownHosts.AddAsync("guid-a", path);

            var hosts = await AdbKnownHosts.LoadAsync(path);
            await Assert.That(hosts.Count).IsEqualTo(2);
            await Assert.That(hosts.Contains("guid-a")).IsTrue();
            await Assert.That(hosts.Contains("guid-b")).IsTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task AddFromPairingResultSkipsWhenPeerInfoIsNotDeviceGuid()
    {
        var path = TempPath();
        var result = new AdbPairingResult(PeerInfoType.AdbRsaPublicKey, "not-a-guid"u8.ToArray());

        await AdbKnownHosts.AddAsync(result, path);

        await Assert.That(File.Exists(path)).IsFalse();
    }

    [Test]
    public async Task AddFromPairingResultDecodesGuidFromPeerInfoData()
    {
        var path = TempPath();
        try
        {
            var result = new AdbPairingResult(PeerInfoType.AdbDeviceGuid, "abc-123-guid"u8.ToArray());

            await AdbKnownHosts.AddAsync(result, path);

            await Assert.That(await AdbKnownHosts.ContainsAsync("abc-123-guid", path)).IsTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task AddCreatesParentDirectoryIfMissing()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sharpadb_known_hosts_dir_{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "known_hosts.json");
        try
        {
            await AdbKnownHosts.AddAsync("guid-x", path);
            await Assert.That(await AdbKnownHosts.ContainsAsync("guid-x", path)).IsTrue();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
