using System.Globalization;
using System.Net;
using System.Net.Sockets;

using Microsoft.Extensions.Logging;

namespace Theodicean.SharpAdb.Services;

/// <summary>
/// Local TCP listener that, for each incoming connection, opens a <c>tcp:&lt;remotePort&gt;</c> stream
/// to the device and bidirectionally relays bytes. Equivalent to <c>adb forward tcp:LP tcp:RP</c>
/// but implemented entirely client-side: no server needed.
/// </summary>
public sealed class AdbPortForward : IAsyncDisposable
{
    private readonly AdbConnection _connection;
    private readonly TcpListener _listener;
    private readonly int _remotePort;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly Task _acceptLoop;

    /// <summary>
    /// Local port the forwarder is listening on. Useful when <c>localPort: 0</c> was passed (auto-assigned).
    /// </summary>
    public int LocalPort { get; }

    private AdbPortForward(AdbConnection connection, TcpListener listener, in int remotePort, ILogger logger)
    {
        _connection = connection;
        _listener = listener;
        _remotePort = remotePort;
        _logger = logger;
        LocalPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync, _shutdownCts.Token);
    }

    /// <summary>
    /// Forwards a local TCP port to a port on the device. Pass <paramref name="localPort"/>=0 to auto-assign.
    /// </summary>
    public static Task<AdbPortForward> StartAsync(AdbConnection connection, int localPort, int remotePort,
        IPAddress? bindAddress = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var listener = new TcpListener(bindAddress ?? IPAddress.Loopback, localPort);
        listener.Start();
        return Task.FromResult(new AdbPortForward(connection, listener, remotePort, connection.Logger));
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_shutdownCts.IsCancellationRequested)
            {
                var sock = await _listener.AcceptSocketAsync(_shutdownCts.Token);
                _ = HandleAsync(sock);
            }
        }
        catch (OperationCanceledException)
        {
            // Ignore
        }
        catch (ObjectDisposedException)
        {
            // Ignore
        }
        catch (SocketException ex)
        {
            _logger.PortForwardAcceptFailed(LocalPort, _remotePort, ex);
        }
    }

    private async Task HandleAsync(Socket socket)
    {
        socket.NoDelay = true;
        await using var net = new NetworkStream(socket, ownsSocket: true);
        AdbStream? stream = null;
        using var pairCts = CancellationTokenSource.CreateLinkedTokenSource(_shutdownCts.Token);
        try
        {
            stream = await _connection.OpenAsync(string.Create(CultureInfo.InvariantCulture, $"tcp:{_remotePort}"), pairCts.Token);
            var t1 = stream.CopyToAsync(net, pairCts.Token);
            var t2 = net.CopyToAsync(stream, pairCts.Token);

            // Once either direction completes, the connection is effectively half-closed —
            // cancel the surviving copy task so we don't leak a relay until forwarder shutdown.
            await Task.WhenAny(t1, t2);
            await pairCts.CancelAsync();
            try
            {
                await Task.WhenAll(t1, t2);
            }
            catch
            {
                // Both halves are torn down — secondary failures are expected here.
            }
        }
        catch (OperationCanceledException) when (_shutdownCts.IsCancellationRequested)
        {
            // Forwarder shutting down — not a fault.
        }
        catch (Exception ex)
        {
            _logger.PortForwardRelayFailed(LocalPort, _remotePort, ex);
        }
        finally
        {
            if (stream is not null)
                await stream.DisposeAsync();
        }
    }

    /// <summary>
    /// Stops the local listener, drops in-flight relay tasks, and releases resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await _shutdownCts.CancelAsync();
        _listener.Stop();
        try { await _acceptLoop; }
        catch
        {
            // don't throw in dispose
        }
        _shutdownCts.Dispose();
    }
}

/// <summary>
/// Extension methods for opening a local-to-device TCP port forward.
/// </summary>
public static class PortForwardExtensions
{
    extension(AdbConnection connection)
    {
        /// <summary>
        /// Forwards a local TCP port to a TCP port on the device.
        /// </summary>
        public Task<AdbPortForward> ForwardPortAsync(int localPort, int remotePort, IPAddress? bindAddress = null)
            => AdbPortForward.StartAsync(connection, localPort, remotePort, bindAddress);
    }
}
