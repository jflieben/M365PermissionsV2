using System.Net;
using System.Net.Sockets;
using M365Permissions.Engine.Http;
using Xunit;

namespace M365Permissions.Engine.Tests.Http;

/// <summary>
/// Verifies the localhost API security controls (S1): every /api/* call requires the
/// per-session token, cross-origin requests are rejected, no CORS wildcard is emitted,
/// and the token is injected into index.html so the same-origin GUI can authenticate.
/// </summary>
public sealed class WebServerSecurityTests : IDisposable
{
    private readonly string _root;

    public WebServerSecurityTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "m365-webtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "index.html"),
            "<!DOCTYPE html><html><head><title>t</title></head><body>hi</body></html>");
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private WebServer StartServer(int port)
    {
        var server = new WebServer(port, _root);
        server.Route("GET", "/api/ping", async (ctx, _) =>
            await WebServer.WriteJson(ctx.Response, 200, new { ok = true }));
        server.Start();
        return server;
    }

    [Fact]
    public async Task ApiCall_WithoutToken_Returns401()
    {
        var port = FreePort();
        using var server = StartServer(port);
        using var client = new HttpClient();

        var resp = await client.GetAsync($"http://localhost:{port}/api/ping");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.False(resp.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task ApiCall_WithValidToken_Returns200()
    {
        var port = FreePort();
        using var server = StartServer(port);
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("X-M365-Token", server.SessionToken);

        var resp = await client.GetAsync($"http://localhost:{port}/api/ping");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ApiCall_WithCrossOriginHeader_Returns403()
    {
        var port = FreePort();
        using var server = StartServer(port);
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("X-M365-Token", server.SessionToken);
        client.DefaultRequestHeaders.Add("Origin", "https://evil.example.com");

        var resp = await client.GetAsync($"http://localhost:{port}/api/ping");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task IndexHtml_ContainsInjectedToken()
    {
        var port = FreePort();
        using var server = StartServer(port);
        using var client = new HttpClient();

        var html = await client.GetStringAsync($"http://localhost:{port}/");

        Assert.Contains(server.SessionToken, html);
        Assert.Contains("X-M365-Token", html);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { /* best effort */ }
    }
}
