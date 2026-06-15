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

Minimum device: Android 9 (API 28). The library requires the `shell_v2` and `sendrecv_v2` adbd features, both of which were released in Android 7 and 9 respectively.

Working:

- TCP transport (port 5555 after `adb tcpip`, or any IP:port the device is reachable on)
- CNXN handshake, banner parsing, max-payload negotiation
- RSA-2048 authentication (signature path + RSAPUBLICKEY enrollment)
- STLS upgrade for devices that require TLS on the debug socket
- Multiplexed `AdbStream` with the per-write OKAY ack the protocol requires
- `shell,v2,raw:` and `exec:` services with separate stdout/stderr and exit code (`AdbShellResult`)
- `sync:` v2 (LST2, LIS2, SND2, RCV2) for file transfer, with 64-bit sizes and full POSIX stat fields
- Streaming APK install via `cmd package install -S <size> -` — no `/data/local/tmp` staging
- Helpers: reboot, package install/uninstall/list, properties, processes, logcat (raw + parsed), screencap, key events, text input, taps/swipes, app start/stop, port forward
- Fault propagation from the read loop to open streams and to subsequent `OpenAsync` calls

Not implemented:

- Wireless pairing with the 6-digit PIN (Android 11+). Requires SPAKE2 over Ed25519 with BoringSSL's specific M/N constants, and a real device to validate against (which I do not have). Workaround: pair once with Google's `adb pair`, then Theodicean.SharpAdb takes over.
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

For Android 11+ devices that only support wireless debugging, do the initial pairing once with Google's binary:

```
adb pair 192.168.1.42:37123 493719
adb connect 192.168.1.42:42891
```

After that, Theodicean.SharpAdb connects to the debug port (the second one, not the pairing port) using the key in `~/.android/adbkey`.

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
var install = await conn.InstallAsync("./app.apk");
if (!install.IsSuccess)
    throw new InvalidOperationException(install.FailureReason);
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