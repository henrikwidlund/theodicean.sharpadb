# Theodicean.SharpAdb

[![Release](https://img.shields.io/github/actions/workflow/status/henrikwidlund/theodicean.sharpadb/github-release.yml?label=Release&logo=github)](https://github.com/henrikwidlund/theodicean.sharpadb/actions/workflows/github-release.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/henrikwidlund/theodicean.sharpadb/ci.yml?label=CI&logo=github)](https://github.com/henrikwidlund/theodicean.sharpadb/actions/workflows/ci.yml)
![Sonar Quality Gate](https://img.shields.io/sonar/quality_gate/henrikwidlund_theodicean.sharpadb?server=https%3A%2F%2Fsonarcloud.io&label=Sonar%20Quality%20Gate&logo=sonarqube)
[![Qodana](https://img.shields.io/github/actions/workflow/status/henrikwidlund/theodicean.sharpadb/qodana_code_quality.yml?branch=main&label=Qodana&logo=github)](https://github.com/henrikwidlund/theodicean.sharpadb/actions/workflows/qodana_code_quality.yml)
[![Version](https://img.shields.io/nuget/v/Theodicean.SharpAdb.svg)](https://www.nuget.org/packages/Theodicean.SharpAdb)

Managed .NET client for the Android Debug Bridge wire protocol. Talks directly to `adbd` on the remote device. No `adb` binary, no local adb-server, no native dependencies.

## Why

The published official `adb` binaries does not support all architectures and often has dependencies on native libraries.
Additionally, software that wants to use the ADB either needs to bundle the correct binary or rely on the end user to install it on their system.

Theodicean.SharpAdb implements the device protocol directly. Your process opens a TCP socket to the device, runs the CNXN/AUTH handshake,
and you get a multiplexed stream over which you can run shell commands, push and pull files, install APKs, and so on.

## Status

Minimum device versions, by feature:

- Shell + helpers (`ExecuteAsync`, install, properties, input, logcat, …): Android 7 (API 24), via the `shell_v2` adbd feature.
- File transfer (`SyncSession`): Android 9 (API 28), via the `sendrecv_v2` adbd feature.

`SyncSession.OpenAsync` throws `NotSupportedException` if the device does not advertise `sendrecv_v2`; everything else works against Android 7+.

Working:

- TCP transport (port 5555 after `adb tcpip`, or any IP:port the device is reachable on)
- CNXN handshake, banner parsing, max-payload negotiation
- RSA-2048 authentication (signature path + RSAPUBLICKEY enrollment)
- STLS upgrade for devices that require TLS on the debug socket
- Multiplexed `AdbStream` with the per-write OKAY ack the protocol requires
- `shell,v2,raw:` for interactive commands with separate stdout/stderr and exit code (`AdbShellResult`)
- `exec:` for raw byte-stream services (e.g. `screencap -p` → PNG bytes); no stdout/stderr split or exit code
- `sync:` v2 (LST2, LIS2, SND2, RCV2) for file transfer, with 64-bit sizes and full POSIX stat fields
- Streaming APK install via `cmd package install -S <size> -` — no `/data/local/tmp` staging
- Helpers: reboot, package install/uninstall/list, properties, processes, logcat (raw + parsed), screencap, key events, text input, taps/swipes, app start/stop, port forward
- Fault propagation from the read loop to open streams and to subsequent `OpenAsync` calls
- Wireless pairing with the 6-digit PIN (Android 11+, `AdbPairing.PairAsync`): SPAKE2 over Ed25519 (BoringSSL's construction, not the RFC 9382 P-256 variant) plus TLS 1.3 via BouncyCastle (needed for the RFC 5705 exported keying material .NET's own TLS stack doesn't expose). **Implemented but not validated against a real device** — I do not have a device which uses it; verified only via a loopback test against a hand-rolled TLS 1.3 peer in this repo, which exercises the wire protocol but can't confirm bit-for-bit compatibility with real adbd/BoringSSL. Treat as unverified until someone runs it against actual hardware. `AdbKnownHosts` persists the device GUID pairing returns, for matching against `_adb-tls-connect._tcp` mDNS instance names (mDNS discovery itself is out of scope for this library — bring your own client).

Not implemented:

- USB transport. The protocol layer is transport-agnostic (`IAdbTransport`), so a USB transport using libusb or a platform-specific API can plug in without touching the rest.
- mDNS device discovery.
- Sync v2 transparent compression (Brotli/LZ4/Zstd). Compression flag is sent as 0.

## Install

Available on NuGet as [`Theodicean.SharpAdb`](https://www.nuget.org/packages/Theodicean.SharpAdb).

```
dotnet add package Theodicean.SharpAdb
```

Or via PackageReference:

```xml
<PackageReference Include="Theodicean.SharpAdb" Version="*" />
```

## Quick start

```csharp
using Theodicean.SharpAdb;
using Theodicean.SharpAdb.Auth;
using Theodicean.SharpAdb.Services;

// Load the same key adb itself uses, so the device already trusts it.
var pem = File.ReadAllText(Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".android", "adbkey"));
using var key = AdbAuthKey.LoadFromPem(pem);

await using var conn = await AdbConnection.ConnectTcpAsync("192.168.1.42", 5555, [key]);

Console.WriteLine($"connected to {conn.DeviceInfo.Model} ({conn.DeviceInfo.Product})");

var result = await conn.ExecuteAsync("getprop ro.build.version.release");
if (result.IsSuccess)
    Console.WriteLine($"android {result.Stdout.Trim()}");
```

## Authentication

The first time a key is presented to a device, the user has to tap "Allow USB debugging from this computer" on the device screen. After that the device persists the public key in `/data/misc/adb/adb_keys` and subsequent connections authenticate silently.

```csharp
// Generate a new key and persist it for reuse
using var key = AdbAuthKey.Generate("alice@workstation");
File.WriteAllText("./mykey.pem", key.ExportPrivateKeyPem());

// First connect: device prompts user, AuthenticationMethod = PublicKey
// Subsequent connects: silent, AuthenticationMethod = Signature
await using var conn = await AdbConnection.ConnectTcpAsync(host, port, [key]);
```

If you want to fail fast instead of triggering the on-device prompt (useful in tests):

```csharp
var opts = new AdbConnectOptions { SendPublicKeyOnAuthFailure = false };
await using var conn = await AdbConnection.ConnectTcpAsync(host, port, [key], opts);
// Throws AdbAuthenticationException if the device doesn't already trust the key.
```

For Android 11+ devices that only support wireless debugging, pair using the 6-digit code shown under Developer Options → Wireless debugging → "Pair device with pairing code" (equivalent to `adb pair`, but **not yet validated against real hardware** — see Status above):

```csharp
using Theodicean.SharpAdb.Pairing;

// host:port and the 6-digit code come from the device's pairing screen; the pairing port is
// NOT the regular ADB debug port.
var result = await AdbPairing.PairAsync("192.168.1.42", 37123, "493719", key);
await AdbKnownHosts.AddAsync(result); // remembers the device GUID for later mDNS matching

// Successful pairing means the device now trusts `key`. Regular connects still go through
// ConnectTcpAsync against the (separate, frequently-changing) debug port shown on-device or
// found via _adb-tls-connect._tcp mDNS.
await using var conn = await AdbConnection.ConnectTcpAsync("192.168.1.42", 42891, [key]);
```

### Finding the debug port via mDNS

The debug port adbd advertises changes across reboots and each time wireless debugging is toggled, so a real app should resolve it fresh before connecting rather than hardcoding a value from setup. mDNS discovery itself is not part of this library — bring your own client (e.g. [`Theodicean.Makaretu.Dns.Multicast`](https://www.nuget.org/packages/Theodicean.Makaretu.Dns.Multicast) on NuGet) and query for the service type below. Match the mDNS *instance name* directly against the GUID `AdbKnownHosts` stored for that device — that is how real `adb` itself correlates a discovery result to an already-paired device, no other lookup involved:

```csharp
using Makaretu.Dns;

// _adb-tls-connect._tcp is the ongoing debug-port service; _adb-tls-pairing._tcp is only
// present while the device's pairing screen is open and isn't needed for regular reconnects.
var sd = await ServiceDiscovery.CreateInstance();
sd.ServiceInstanceDiscovered += async args =>
{
    var instanceName = args.ServiceInstanceName!.Labels[0]; // == the device GUID from pairing
    if (await AdbKnownHosts.ContainsAsync(instanceName))
    {
        // extract host/port from args.Message's SRV + address records, then ConnectTcpAsync
    }
};
await sd.QueryServiceInstances(new DomainName("_adb-tls-connect._tcp"));
```

## File transfer

```csharp
await using var sync = await SyncSession.OpenAsync(conn);

await using var src = File.OpenRead("./build/app.apk");
await sync.PushAsync(src, "/data/local/tmp/app.apk");

await using var dst = File.Create("./screenshot.png");
await sync.PullAsync("/sdcard/Pictures/screenshot.png", dst);

var stat = await sync.StatAsync("/data/local/tmp");
if (stat.IsDirectory) { /* ... */ }

await foreach (var entry in sync.ListAsync("/sdcard"))
    Console.WriteLine($"{entry.Name} ({entry.Size} bytes)");
```

## Helpers

```csharp
// Properties
var sdk = await conn.GetPropertyAsync("ro.build.version.sdk");
var all = await conn.GetAllPropertiesAsync();

// Packages — streams the APK through `cmd package install` rather than staging on /data/local/tmp.
// FailureReason can be null when adbd printed "Failure" without a bracketed reason; fall back to
// the raw shell output (Raw.Stdout + Raw.Stderr) so the diagnostic isn't empty.
var install = await conn.InstallAsync("./app.apk");
if (!install.IsSuccess)
    throw new InvalidOperationException(
        install.FailureReason ?? $"install failed: {install.Raw.Stdout}{install.Raw.Stderr}");
var packages = await conn.ListPackagesAsync();
await conn.UninstallAsync("com.example.app");

// Input
await conn.SendKeyEventAsync(KeyCode.Home);
await conn.SendTextAsync("hello world");
await conn.TapAsync(540, 1200);
await conn.SwipeAsync(100, 1500, 100, 500, durationMs: 250);

// App lifecycle
await conn.StartAppAsync("com.example.app");
await conn.StopAppAsync("com.example.app");

// Screencap (PNG bytes)
var png = await conn.CaptureScreenAsync();

// Logcat
await foreach (var entry in conn.LogcatAsync(filterSpec: "*:E"))
    Console.WriteLine($"{entry.Priority} {entry.Tag}: {entry.Message}");

// Port forward (local TCP -> device port). Local port 0 = auto-assign.
await using var fwd = await conn.ForwardPortAsync(localPort: 0, remotePort: 8080);
Console.WriteLine($"http://127.0.0.1:{fwd.LocalPort}/");

// Reboot
await conn.RebootAsync(RebootMode.Recovery);
```

## Tests

Unit tests run without a device:

```
dotnet test tests/Theodicean.SharpAdb.Tests
```

Integration tests connect to a real device. Set `ADB_HOST` (and optionally `ADB_KEY_PATH`):

```
ADB_HOST=192.168.1.42:5555 dotnet test tests/Theodicean.SharpAdb.IntegrationTests
```

If `ADB_KEY_PATH` is unset, the fixture defaults to `~/.android/adbkey` (the same file Google's `adb` uses). If neither path exists, a fresh key is generated and saved; the first connect will prompt the user to tap "Allow" on the device.

For one-time on-device key authorization, set `ADB_RUN_BOOTSTRAP=1` and run the `BootstrapKeyOnDevice` test.

## License

MIT License. See [LICENSE](LICENSE).