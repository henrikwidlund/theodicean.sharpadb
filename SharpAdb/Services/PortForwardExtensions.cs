using System.Net;
using System.Net.Sockets;

namespace SharpAdb.Services;

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
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    /// <summary>
    /// Local port the forwarder is listening on. Useful when <c>localPort: 0</c> was passed (auto-assigned).
    /// </summary>
    public int LocalPort { get; }

    private AdbPortForward(AdbConnection connection, TcpListener listener, in int remotePort)
    {
        _connection = connection;
        _listener = listener;
        _remotePort = remotePort;
        LocalPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync);
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
        return Task.FromResult(new AdbPortForward(connection, listener, remotePort));
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var sock = await _listener.AcceptSocketAsync(_cts.Token).ConfigureAwait(false);
                _ = HandleAsync(sock);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    private async Task HandleAsync(Socket socket)
    {
        socket.NoDelay = true;
        await using var net = new NetworkStream(socket, ownsSocket: true);
        AdbStream? stream = null;
        try
        {
            stream = await _connection.OpenAsync($"tcp:{_remotePort}", _cts.Token).ConfigureAwait(false);
            var t1 = stream.CopyToAsync(net, _cts.Token);
            var t2 = net.CopyToAsync(stream, _cts.Token);
            await Task.WhenAny(t1, t2).ConfigureAwait(false);
        }
        catch { /* peer disconnect, port unreachable, etc. */ }
        finally
        {
            if (stream is not null)
                await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Stops the local listener, drops in-flight relay tasks, and releases resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        try { await _acceptLoop.ConfigureAwait(false); }
        catch
        {
            // don't throw in dispose
        }
        _cts.Dispose();
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