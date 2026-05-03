using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Services;

using Xunit;

namespace Theodicean.SharpAdb.IntegrationTests;

public class AuthenticationIntegrationTests(AdbIntegrationFixture fixture) : IClassFixture<AdbIntegrationFixture>
{
    private readonly AdbIntegrationFixture _fixture = fixture;

    /// <summary>
    /// One-time bootstrap: pushes the configured key to the device so the user can tap "Allow" +
    /// "Always allow from this computer". After this passes once, all other auth tests will
    /// succeed via the signature path. Skipped from CI by default — set ADB_RUN_BOOTSTRAP=1 to opt in.
    /// </summary>
    [SkippableFact]
    public async Task BootstrapKeyOnDevice()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);
        // Skip.IfNot(Environment.GetEnvironmentVariable("ADB_RUN_BOOTSTRAP") == "1",
        //     "Set ADB_RUN_BOOTSTRAP=1 to run the one-time on-device key authorization. Tap 'Always allow' on device when prompted.");

        var opts = new AdbConnectOptions
        {
            SendPublicKeyOnAuthFailure = true,
            AuthTimeout = TimeSpan.FromMinutes(2) // user has to tap Allow
        };

        await using var conn = await _fixture.ConnectWithAsync([_fixture.Key!], opts);

        // Either the device already trusted the key (Signature) or the user just tapped Allow (PublicKey).
        Assert.Contains(conn.AuthenticationMethod, new[]
        {
            AdbAuthenticationMethod.Signature,
            AdbAuthenticationMethod.PublicKey
        });
    }

    [SkippableFact]
    public async Task ConfiguredKeyAuthenticatesViaSignature()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        // SendPublicKeyOnAuthFailure=false guarantees that a successful connect proves the device
        // recognized our key and accepted the AUTH(SIGNATURE) packet — not that it fell back to a
        // user-prompt + RSAPUBLICKEY add. Distinguishes "really authenticated" from "user tapped Allow".
        var opts = new AdbConnectOptions { SendPublicKeyOnAuthFailure = false };
        await using var conn = await _fixture.ConnectWithAsync([_fixture.Key!], opts);

        Assert.Equal(AdbAuthenticationMethod.Signature, conn.AuthenticationMethod);
        Assert.Equal("device", conn.DeviceInfo.SystemType);
    }

    [SkippableFact]
    public async Task ConnectWithNoKeysThrowsAuthenticationException()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        await Assert.ThrowsAsync<AdbAuthenticationException>(async () =>
        {
            await using var conn = await _fixture.ConnectWithAsync([]);
        });
    }

    [SkippableFact]
    public async Task ConnectWithUnknownKeyFailsWhenPubkeyPushDisabled()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        // Fresh ephemeral key the device has never seen. Without pubkey push, the device will keep
        // sending AUTH(TOKEN) and we abort after the single signature attempt is rejected.
        using var stranger = AdbAuthKey.Generate("stranger@host");
        var opts = new AdbConnectOptions
        {
            SendPublicKeyOnAuthFailure = false,
            AuthTimeout = TimeSpan.FromSeconds(10)
        };

        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using var conn = await _fixture.ConnectWithAsync([stranger], opts);
        });
    }

    [SkippableFact]
    public async Task PostAuthShellRoundtripWorks()
    {
        Skip.IfNot(_fixture.Available, AdbIntegrationFixture.SkipReason);

        // Confirms the auth path produced a usable session, not just a banner read.
        var opts = new AdbConnectOptions { SendPublicKeyOnAuthFailure = false };
        await using var conn = await _fixture.ConnectWithAsync([_fixture.Key!], opts);

        Assert.Equal(AdbAuthenticationMethod.Signature, conn.AuthenticationMethod);
        var output = await conn.ExecuteAsync("id -u");
        Assert.False(string.IsNullOrWhiteSpace(output));
    }
}
