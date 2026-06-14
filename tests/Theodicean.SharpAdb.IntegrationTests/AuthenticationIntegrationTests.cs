using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.IntegrationTests;

public class AuthenticationIntegrationTests
{
    [ClassDataSource<AdbIntegrationFixture>(Shared = SharedType.PerClass)]
    public required AdbIntegrationFixture Fixture { get; init; }

    /// <summary>
    /// One-time bootstrap: pushes the configured key to the device so the user can tap "Allow" +
    /// "Always allow from this computer". After this passes once, all other auth tests will
    /// succeed via the signature path. Skipped from CI by default — set ADB_RUN_BOOTSTRAP=1 to opt in.
    /// </summary>
    [Test]
    public async Task BootstrapKeyOnDevice()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        var opts = new AdbConnectOptions
        {
            SendPublicKeyOnAuthFailure = true,
            AuthTimeout = TimeSpan.FromMinutes(2) // user has to tap Allow
        };

        await using var conn = await Fixture.ConnectWithAsync([Fixture.Key!], opts);

        // Either the device already trusted the key (Signature) or the user just tapped Allow (PublicKey).
        await Assert.That([
            AdbAuthenticationMethod.Signature,
            AdbAuthenticationMethod.PublicKey
        ]).Contains(conn.AuthenticationMethod);
    }

    [Test]
    public async Task ConfiguredKeyAuthenticatesViaSignature()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        // SendPublicKeyOnAuthFailure=false guarantees that a successful connect proves the device
        // recognized our key and accepted the AUTH(SIGNATURE) packet — not that it fell back to a
        // user-prompt + RSAPUBLICKEY add. Distinguishes "really authenticated" from "user tapped Allow".
        var opts = new AdbConnectOptions { SendPublicKeyOnAuthFailure = false };
        await using var conn = await Fixture.ConnectWithAsync([Fixture.Key!], opts);

        await Assert.That(conn.AuthenticationMethod).IsEqualTo(AdbAuthenticationMethod.Signature);
        await Assert.That(conn.DeviceInfo.SystemType).IsEqualTo("device");
    }

    [Test]
    public async Task ConnectWithNoKeysThrowsAuthenticationException()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        await Assert.That(async () =>
        {
            await using var conn = await Fixture.ConnectWithAsync([]);
        }).ThrowsExactly<AdbAuthenticationException>();
    }

    [Test]
    public async Task ConnectWithUnknownKeyFailsWhenPubkeyPushDisabled()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        // Fresh ephemeral key the device has never seen. Without pubkey push, the device will keep
        // sending AUTH(TOKEN) and we abort after the single signature attempt is rejected.
        using var stranger = AdbAuthKey.Generate("stranger@host");
        var opts = new AdbConnectOptions
        {
            SendPublicKeyOnAuthFailure = false,
            AuthTimeout = TimeSpan.FromSeconds(10)
        };

        await Assert.That(async () =>
        {
            await using var conn = await Fixture.ConnectWithAsync([stranger], opts);
        }).Throws<Exception>();
    }

    [Test]
    public async Task PostAuthShellRoundtripWorks()
    {
        if (!Fixture.Available)
            Skip.Test(AdbIntegrationFixture.SkipReason);

        // Confirms the auth path produced a usable session, not just a banner read.
        var opts = new AdbConnectOptions { SendPublicKeyOnAuthFailure = false };
        await using var conn = await Fixture.ConnectWithAsync([Fixture.Key!], opts);

        await Assert.That(conn.AuthenticationMethod).IsEqualTo(AdbAuthenticationMethod.Signature);
        // Confirms the shell roundtrip works post-auth: `id -u` prints the numeric UID on
        // stdout (e.g. "2000" for the shell user) and exits 0. Assert both — null/whitespace
        // would mean the command never produced output, which is the opposite of success.
        var output = await conn.ExecuteAsync("id -u");
        await Assert.That(output.IsSuccess).IsTrue();
        await Assert.That(int.TryParse(output.Stdout.Trim(), out _)).IsTrue();
    }
}
