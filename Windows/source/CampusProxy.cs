using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace CampusConnect;

public sealed record HaustSessionInfo(
    bool PortalReachable,
    bool Online,
    string Username,
    string Name,
    string Isp,
    string UserIpv4,
    string UserMac,
    string Traffic,
    string Duration,
    int OnlineDevices,
    string GatewayMessage);

// Loopback-only HTTP/CONNECT bridge that binds outbound connections to the active
// physical Wi-Fi or Ethernet interface so campus portals remain reachable even when
// a packet-tunnel VPN (e.g., Clash / FlClash TUN) captures the system default route.
internal sealed class CampusProxy : IDisposable
{
    private const int IpUnicastIf = 31;
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new();
    public int Port { get; }
    public Guid? PreferredInterfaceId { get; set; }

    public CampusProxy()
    {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync(stop.Token);
    }

    public static (IPAddress Address, int InterfaceIndex, string Mac)? ResolveCampusBinding(Guid? preferredInterfaceId = null)
    {
        try {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType is NetworkInterfaceType.Wireless80211
                                or NetworkInterfaceType.Ethernet
                                or NetworkInterfaceType.GigabitEthernet
                                or NetworkInterfaceType.FastEthernetFx
                                or NetworkInterfaceType.FastEthernetT)
                .OrderByDescending(n => preferredInterfaceId is not null && Guid.TryParse(n.Id, out var id) && id == preferredInterfaceId)
                .ThenByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);

            foreach (var adapter in interfaces) {
                var props = adapter.GetIPProperties();
                int? index = null;
                try { index = props.GetIPv4Properties()?.Index; } catch { }
                var unicast = props.UnicastAddresses
                    .Select(u => u.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork &&
                                         !IPAddress.IsLoopback(a) &&
                                         !a.ToString().StartsWith("169.254.", StringComparison.Ordinal) &&
                                         !a.ToString().StartsWith("198.18.", StringComparison.Ordinal));
                if (unicast is not null && index is not null) {
                    var macBytes = adapter.GetPhysicalAddress().GetAddressBytes();
                    var mac = macBytes.Length == 6
                        ? string.Join(":", macBytes.Select(b => b.ToString("x2")))
                        : "";
                    return (unicast, index.Value, mac);
                }
            }
        } catch { }
        return null;
    }

    public static async ValueTask<Socket> ConnectBoundSocketAsync(string host, int port, Guid? preferredInterfaceId, CancellationToken cancellationToken)
    {
        var addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken).ConfigureAwait(false);
        var target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
            ?? throw new SocketException((int)SocketError.HostNotFound);

        var binding = ResolveCampusBinding(preferredInterfaceId);
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try {
            if (binding is { } b) {
                try {
                    socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IpUnicastIf, IPAddress.HostToNetworkOrder(b.InterfaceIndex));
                    socket.Bind(new IPEndPoint(b.Address, 0));
                } catch {
                    // Fallback to unbound socket if the adapter changed mid-flight.
                }
            }
            await socket.ConnectAsync(new IPEndPoint(target, port), cancellationToken).ConfigureAwait(false);
            return socket;
        } catch {
            socket.Dispose();
            throw;
        }
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested) {
            try {
                var client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                _ = HandleClientAsync(client, token);
            } catch (OperationCanceledException) { break; }
            catch { await Task.Delay(50, token).ConfigureAwait(false); }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        using (client) {
            try {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(15));
                await using var clientStream = client.GetStream();
                var headerBuffer = new MemoryStream();
                var scratch = new byte[4096];
                int headerEnd = -1;
                while (headerBuffer.Length < 65536) {
                    var read = await clientStream.ReadAsync(scratch.AsMemory(0, scratch.Length), timeoutCts.Token).ConfigureAwait(false);
                    if (read <= 0) return;
                    headerBuffer.Write(scratch, 0, read);
                    var span = headerBuffer.GetBuffer().AsSpan(0, (int)headerBuffer.Length);
                    headerEnd = FindHeaderEnd(span);
                    if (headerEnd >= 0) break;
                }
                if (headerEnd < 0) return;
                var allBytes = headerBuffer.GetBuffer();
                var headerText = Encoding.ASCII.GetString(allBytes, 0, headerEnd);
                var tailLength = (int)headerBuffer.Length - (headerEnd + 4);
                var lines = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length == 0) return;
                var parts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) return;
                var method = parts[0];
                var rawTarget = parts[1];
                var version = parts[2];

                if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase)) {
                    var authority = rawTarget.Split(':', 2);
                    var host = authority[0];
                    var port = authority.Length > 1 && int.TryParse(authority[1], out var p) ? p : 443;
                    using var upstreamSocket = await ConnectBoundSocketAsync(host, port, PreferredInterfaceId, timeoutCts.Token).ConfigureAwait(false);
                    await using var upstreamStream = new NetworkStream(upstreamSocket, ownsSocket: false);
                    var established = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
                    await clientStream.WriteAsync(established, timeoutCts.Token).ConfigureAwait(false);
                    if (tailLength > 0)
                        await upstreamStream.WriteAsync(allBytes.AsMemory(headerEnd + 4, tailLength), timeoutCts.Token).ConfigureAwait(false);
                    await Task.WhenAny(
                        clientStream.CopyToAsync(upstreamStream, token),
                        upstreamStream.CopyToAsync(clientStream, token)).ConfigureAwait(false);
                } else if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var targetUri) &&
                           (targetUri.Scheme == "http" || targetUri.Scheme == "https")) {
                    var host = targetUri.Host;
                    var port = targetUri.IsDefaultPort ? 80 : targetUri.Port;
                    using var upstreamSocket = await ConnectBoundSocketAsync(host, port, PreferredInterfaceId, timeoutCts.Token).ConfigureAwait(false);
                    await using var upstreamStream = new NetworkStream(upstreamSocket, ownsSocket: false);
                    var pathAndQuery = string.IsNullOrEmpty(targetUri.PathAndQuery) ? "/" : targetUri.PathAndQuery;
                    var sb = new StringBuilder();
                    sb.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(version).Append("\r\n");
                    foreach (var line in lines.Skip(1)) {
                        if (line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase) ||
                            line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase)) continue;
                        sb.Append(line).Append("\r\n");
                    }
                    sb.Append("Connection: close\r\n\r\n");
                    var rewritten = Encoding.ASCII.GetBytes(sb.ToString());
                    await upstreamStream.WriteAsync(rewritten, timeoutCts.Token).ConfigureAwait(false);
                    if (tailLength > 0)
                        await upstreamStream.WriteAsync(allBytes.AsMemory(headerEnd + 4, tailLength), timeoutCts.Token).ConfigureAwait(false);
                    await Task.WhenAny(
                        clientStream.CopyToAsync(upstreamStream, token),
                        upstreamStream.CopyToAsync(clientStream, token)).ConfigureAwait(false);
                }
            } catch { }
        }
    }

    private static int FindHeaderEnd(ReadOnlySpan<byte> buffer)
    {
        for (var i = 0; i <= buffer.Length - 4; i++) {
            if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                return i;
        }
        return -1;
    }

    public void Dispose()
    {
        stop.Cancel();
        try { listener.Stop(); } catch { }
        stop.Dispose();
    }
}

internal static class HaustPortalTelemetry
{
    public const string DefaultAuthHost = "10.100.51.1";
    public const string DefaultPortalUrl = "http://10.100.51.1";
    public const string LegacyRuijieUrl = "http://10.10.10.111";
    public const string SelfServiceHost = "210.43.0.48";
    public const string DefaultSsid = "Haust-STU";

    private static HttpClient CreateBoundClient(Guid? preferredInterfaceId, TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = true,
            CookieContainer = new CookieContainer(),
            ConnectTimeout = timeout,
            SslOptions = {
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                    errors == System.Net.Security.SslPolicyErrors.None ||
                    (cert is not null && (cert.Subject.Contains("haust.edu.cn", StringComparison.OrdinalIgnoreCase) ||
                                          cert.Subject.Contains("河南科技大学", StringComparison.Ordinal)))
            },
            ConnectCallback = async (context, token) => {
                var socket = await CampusProxy.ConnectBoundSocketAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, preferredInterfaceId, token).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
        };
        return new HttpClient(handler) { Timeout = timeout };
    }

    public static async Task<HaustSessionInfo> ProbeAsync(Guid? preferredInterfaceId = null)
    {
        var binding = CampusProxy.ResolveCampusBinding(preferredInterfaceId);
        var localIp = binding?.Address.ToString() ?? "";
        var localMac = binding?.Mac ?? "";
        try {
            using var client = CreateBoundClient(preferredInterfaceId, TimeSpan.FromSeconds(3.5));
            using var csrfReq = new HttpRequestMessage(HttpMethod.Get, $"https://{DefaultAuthHost}/api/csrf-token");
            csrfReq.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            using var csrfResp = await client.SendAsync(csrfReq).ConfigureAwait(false);
            string csrfToken = "";
            if (csrfResp.IsSuccessStatusCode) {
                var csrfJson = await csrfResp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var csrfDoc = JsonDocument.Parse(csrfJson);
                if (csrfDoc.RootElement.TryGetProperty("csrf_token", out var tokenProp))
                    csrfToken = tokenProp.GetString() ?? "";
            }

            var statusUrl = $"https://{DefaultAuthHost}/api/account/status?username=&password=&switchip=&nasId=1&userIpv4={Uri.EscapeDataString(localIp)}&userMac={Uri.EscapeDataString(localMac)}&captcha=&captchaId=&isp=&timeLimit=";
            using var statusReq = new HttpRequestMessage(HttpMethod.Get, statusUrl);
            statusReq.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            if (!string.IsNullOrEmpty(csrfToken))
                statusReq.Headers.TryAddWithoutValidation("X-CSRF-Token", csrfToken);

            using var statusResp = await client.SendAsync(statusReq).ConfigureAwait(false);
            if (!statusResp.IsSuccessStatusCode)
                return new(false, false, "", "", "", localIp, localMac, "", "", 0, $"网关响应 HTTP {(int)statusResp.StatusCode}");

            var body = await statusResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var code = root.TryGetProperty("code", out var codeEl) && codeEl.TryGetInt32(out var c) ? c : -1;
            var ispRaw = root.TryGetProperty("isp", out var ispEl) ? ispEl.GetString() ?? "" : "";
            var macCount = root.TryGetProperty("macOnlineCount", out var mcEl) && mcEl.TryGetInt32(out var mc) ? mc : 0;

            if (code == 0 && root.TryGetProperty("online", out var online) && online.ValueKind == JsonValueKind.Object) {
                string Str(string key) => online.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";
                var username = Str("Username");
                var name = Str("Name");
                var ip4 = Str("UserIpv4");
                var mac = Str("UserMac");
                var in4 = Str("BytesIn4");
                var out4 = Str("BytesOut4");
                var addTime = Str("AddTime");
                return new(
                    PortalReachable: true,
                    Online: true,
                    Username: username,
                    Name: name,
                    Isp: FormatIsp(ispRaw),
                    UserIpv4: string.IsNullOrEmpty(ip4) ? localIp : ip4,
                    UserMac: string.IsNullOrEmpty(mac) ? localMac : mac,
                    Traffic: FormatTraffic(in4, out4),
                    Duration: FormatDuration(addTime),
                    OnlineDevices: macCount,
                    GatewayMessage: "已通过河科大网关 (10.100.51.1) 认证在线");
            }
            return new(
                PortalReachable: true,
                Online: false,
                Username: "",
                Name: "",
                Isp: FormatIsp(ispRaw),
                UserIpv4: localIp,
                UserMac: localMac,
                Traffic: "",
                Duration: "",
                OnlineDevices: macCount,
                GatewayMessage: "河科大认证网关可达 · 当前待认证登录");
        } catch {
            return new(false, false, "", "", "", localIp, localMac, "", "", 0, "未检测到河科大内网认证网关 (10.100.51.1)");
        }
    }

    public static async Task<(bool Success, string Message, HaustSessionInfo Session)> DirectAuthenticateOrVerifyAsync(
        CampusProfile profile, string password, Guid? preferredInterfaceId = null)
    {
        var initial = await ProbeAsync(preferredInterfaceId).ConfigureAwait(false);
        if (initial.Online) {
            return (true, $"河科大校园网已在线（学号：{initial.Username}{(string.IsNullOrEmpty(initial.Name) ? "" : " · " + initial.Name)}，IP：{initial.UserIpv4}）", initial);
        }
        if (!initial.PortalReachable) {
            return (false, "无法连接河科大认证服务器 (10.100.51.1)，请确认已连接 Haust-STU 或河科大校园网。", initial);
        }
        if (string.IsNullOrWhiteSpace(profile.Username) || string.IsNullOrEmpty(password)) {
            return (false, "河科大认证网关可达，但尚未保存学号或密码，请先在设置中填写。", initial);
        }

        try {
            // Keep-alive single HttpClient so CSRF token and POST /api/account/login share the TCP connection.
            using var client = CreateBoundClient(preferredInterfaceId, TimeSpan.FromSeconds(6));
            var loginPageUrl = $"https://{DefaultAuthHost}/tpl/stu-ky/login_account.html?ip={Uri.EscapeDataString(initial.UserIpv4)}&nasId=1";

            using var csrfReq = new HttpRequestMessage(HttpMethod.Get, $"https://{DefaultAuthHost}/api/csrf-token");
            csrfReq.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            csrfReq.Headers.TryAddWithoutValidation("Referer", loginPageUrl);
            using var csrfResp = await client.SendAsync(csrfReq).ConfigureAwait(false);
            var csrfJson = await csrfResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var csrfDoc = JsonDocument.Parse(csrfJson);
            var csrfToken = csrfDoc.RootElement.TryGetProperty("csrf_token", out var t) ? t.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(csrfToken))
                return (false, "未能从 10.100.51.1 获取 CSRF 令牌。", initial);

            var ispCode = NormalizeIspCode(profile.ServiceOption);
            var formBody = $"username={Uri.EscapeDataString(profile.Username.Trim())}" +
                           $"&password={Uri.EscapeDataString(password)}" +
                           $"&nasId=1" +
                           $"&userIpv4={Uri.EscapeDataString(initial.UserIpv4)}" +
                           $"&userMac={Uri.EscapeDataString(initial.UserMac)}" +
                           $"&isp={Uri.EscapeDataString(ispCode)}" +
                           $"&timeLimit=";

            using var loginReq = new HttpRequestMessage(HttpMethod.Post, $"https://{DefaultAuthHost}/api/account/login");
            loginReq.Headers.TryAddWithoutValidation("X-CSRF-Token", csrfToken);
            loginReq.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            loginReq.Headers.TryAddWithoutValidation("Origin", $"https://{DefaultAuthHost}");
            loginReq.Headers.TryAddWithoutValidation("Referer", loginPageUrl);
            loginReq.Content = new StringContent(formBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            using var loginResp = await client.SendAsync(loginReq).ConfigureAwait(false);
            var loginBody = await loginResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var loginDoc = JsonDocument.Parse(loginBody);
            var root = loginDoc.RootElement;
            var code = root.TryGetProperty("code", out var cEl) && cEl.TryGetInt32(out var c) ? c : -1;
            var msg = root.TryGetProperty("msg", out var mEl) ? mEl.GetString() ?? "" : "";

            if (code == 0) {
                await Task.Delay(400).ConfigureAwait(false);
                var after = await ProbeAsync(preferredInterfaceId).ConfigureAwait(false);
                return (true, $"河科大认证登录成功！（学号：{after.Username}，IP：{after.UserIpv4}）", after);
            }
            if (code == 2) {
                return (false, "认证服务器要求图形验证码，正在为您打开网页认证窗口完成验证码输入。", initial);
            }
            return (false, $"河科大网关返回认证失败：{(string.IsNullOrEmpty(msg) ? loginBody : msg)}", initial);
        } catch (Exception ex) {
            return (false, "直连认证请求异常：" + ex.Message, initial);
        }
    }

    public static string NormalizeIspCode(string? serviceOption)
    {
        var text = (serviceOption ?? "").Trim().ToLowerInvariant();
        return text switch {
            "" => "local",
            "校园网" or "校园网通用出口" or "local" => "local",
            "中国移动" or "移动" or "cmcc" or "wcmcc" => "cmcc",
            "中国联通" or "联通" or "cucc" or "unicom" => "cucc",
            "中国电信" or "电信" or "ctcc" or "wtelecom" or "telecom" => "ctcc",
            _ => text
        };
    }

    public static string FormatIsp(string? raw) => (raw ?? "").Trim().ToLowerInvariant() switch {
        "cmcc" or "wcmcc" => "中国移动",
        "cucc" or "unicom" => "中国联通",
        "ctcc" or "wtelecom" or "telecom" => "中国电信",
        "local" => "校园网",
        "" => "默认出口",
        var other => other
    };

    private static string FormatTraffic(string bytesIn, string bytesOut)
    {
        var down = FormatBytes(bytesIn);
        var up = FormatBytes(bytesOut);
        if (string.IsNullOrEmpty(down) && string.IsNullOrEmpty(up)) return "";
        return $"↓ {down} · ↑ {up}";
    }

    private static string FormatBytes(string raw)
    {
        if (!double.TryParse(raw, out var value) || value <= 0) return "0 B";
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) {
            value /= 1024;
            unit++;
        }
        return $"{value:0.##} {units[unit]}";
    }

    private static string FormatDuration(string addTime)
    {
        if (!DateTimeOffset.TryParse(addTime, out var start)) return "";
        var elapsed = DateTimeOffset.Now - start;
        if (elapsed < TimeSpan.Zero) elapsed = TimeSpan.Zero;
        if (elapsed.TotalDays >= 1) return $"{(int)elapsed.TotalDays}天 {elapsed.Hours}小时 {elapsed.Minutes}分钟";
        if (elapsed.TotalHours >= 1) return $"{(int)elapsed.TotalHours}小时 {elapsed.Minutes}分钟";
        return $"{Math.Max(1, (int)elapsed.TotalMinutes)}分钟";
    }
}
