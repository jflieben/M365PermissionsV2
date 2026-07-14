using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace M365Permissions.Engine.Http;

/// <summary>
/// Lightweight embedded HTTP server using HttpListener.
/// Serves the GUI static files and REST API routes.
/// </summary>
public sealed class WebServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly Dictionary<string, RouteHandler> _routes = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _staticFilesPath;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public delegate Task RouteHandler(HttpListenerContext context, Dictionary<string, string> routeParams);

    public int Port { get; }
    public bool IsRunning => _listener.IsListening;

    /// <summary>
    /// Per-session random token. Required on every /api/* request via the X-M365-Token
    /// header. Injected into index.html at serve time so the same-origin GUI can send it,
    /// while cross-origin pages (which cannot read the localhost HTML body) cannot obtain it.
    /// </summary>
    public string SessionToken { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public WebServer(int port, string staticFilesPath)
    {
        Port = port;
        _staticFilesPath = staticFilesPath;
        _listener.Prefixes.Add($"http://localhost:{port}/");
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
    }

    /// <summary>Register a route handler. Pattern supports :param placeholders (e.g., /api/scans/:id/results).</summary>
    public void Route(string method, string pattern, RouteHandler handler)
    {
        var key = $"{method.ToUpperInvariant()} {pattern}";
        _routes[key] = handler;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listener.Start();
        _listenTask = Task.Run(() => ListenLoop(_cts.Token));
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        _listener.Stop();
        if (_listenTask != null)
            await _listenTask.ConfigureAwait(false);
    }

    private async Task ListenLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (HttpListenerException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            // Process request without blocking the listen loop
            _ = Task.Run(async () =>
            {
                try
                {
                    await HandleRequest(context).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    await WriteJson(context.Response, 500, Models.ApiResponse.Fail($"Internal error: {ex.Message}"));
                }
            }, CancellationToken.None);
        }
    }

    private async Task HandleRequest(HttpListenerContext context)
    {
        var request = context.Request;
        var path = request.Url?.AbsolutePath ?? "/";
        var method = request.HttpMethod.ToUpperInvariant();

        // Baseline hardening headers. No CORS is emitted: the GUI is same-origin, so no
        // Access-Control-Allow-Origin is needed, and its absence means a malicious website
        // cannot read any /api/* response (S1).
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";

        // Reject requests that don't originate from the local GUI origin. The Host header is
        // always present; the Origin header is present on state-changing/cross-origin fetches.
        if (!IsLocalRequest(request))
        {
            context.Response.StatusCode = 403;
            context.Response.Close();
            return;
        }

        if (method == "OPTIONS")
        {
            // Same-origin requests never preflight; respond harmlessly without CORS headers.
            context.Response.StatusCode = 204;
            context.Response.Close();
            return;
        }

        // Try API routes first
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            // Every /api/* call must carry the per-session token. This blocks CSRF and any
            // cross-origin read attempt (the token cannot be sent cross-origin without a
            // preflight, which we do not grant) (S1).
            if (!IsTokenValid(request))
            {
                await WriteJson(context.Response, 401, Models.ApiResponse.Fail("Missing or invalid session token"));
                return;
            }

            var (handler, routeParams) = MatchRoute(method, path);
            if (handler != null)
            {
                await handler(context, routeParams);
                return;
            }
            await WriteJson(context.Response, 404, Models.ApiResponse.Fail("Route not found"));
            return;
        }

        // Static files for GUI (index.html gets the session token injected)
        await StaticFiles.Serve(context, _staticFilesPath, SessionToken);
    }

    /// <summary>Validates Host (always) and Origin (when present) against the local GUI origin.</summary>
    private bool IsLocalRequest(HttpListenerRequest request)
    {
        var host = request.Headers["Host"];
        if (string.IsNullOrEmpty(host) || !IsAllowedAuthority(host))
            return false;

        var origin = request.Headers["Origin"];
        if (!string.IsNullOrEmpty(origin))
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
                return false;
            if (!originUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ||
                !IsAllowedAuthority(originUri.Authority))
                return false;
        }
        return true;
    }

    private bool IsAllowedAuthority(string authority) =>
        authority.Equals($"localhost:{Port}", StringComparison.OrdinalIgnoreCase) ||
        authority.Equals($"127.0.0.1:{Port}", StringComparison.OrdinalIgnoreCase);

    private bool IsTokenValid(HttpListenerRequest request)
    {
        var provided = request.Headers["X-M365-Token"];
        if (string.IsNullOrEmpty(provided)) return false;
        var a = Encoding.UTF8.GetBytes(provided);
        var b = Encoding.UTF8.GetBytes(SessionToken);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private (RouteHandler? handler, Dictionary<string, string> routeParams) MatchRoute(string method, string path)
    {
        var pathSegments = path.Trim('/').Split('/');

        foreach (var (key, handler) in _routes)
        {
            var parts = key.Split(' ', 2);
            if (parts[0] != method) continue;

            var patternSegments = parts[1].Trim('/').Split('/');
            if (patternSegments.Length != pathSegments.Length) continue;

            var routeParams = new Dictionary<string, string>();
            var match = true;

            for (int i = 0; i < patternSegments.Length; i++)
            {
                if (patternSegments[i].StartsWith(':'))
                {
                    routeParams[patternSegments[i][1..]] = pathSegments[i];
                }
                else if (!string.Equals(patternSegments[i], pathSegments[i], StringComparison.OrdinalIgnoreCase))
                {
                    match = false;
                    break;
                }
            }

            if (match) return (handler, routeParams);
        }

        return (null, new Dictionary<string, string>());
    }

    public static async Task WriteJson<T>(HttpListenerResponse response, int statusCode, T body)
    {
        response.StatusCode = statusCode;
        response.ContentType = "application/json; charset=utf-8";
        var json = JsonSerializer.SerializeToUtf8Bytes(body, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });
        response.ContentLength64 = json.Length;
        await response.OutputStream.WriteAsync(json).ConfigureAwait(false);
        response.Close();
    }

    public static async Task<T?> ReadJson<T>(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync().ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _listener.Close();
        // Wait briefly for listen loop to exit cleanly
        try { _listenTask?.Wait(TimeSpan.FromSeconds(2)); } catch { /* best effort */ }
        _cts?.Dispose();
    }
}
