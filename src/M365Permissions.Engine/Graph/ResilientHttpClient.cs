using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Graph;

/// <summary>
/// Shared HTTP client for the non-Graph resource APIs (Power BI, Power Platform/BAP, ARM,
/// Azure DevOps). Those APIs throttle aggressively but the scanners previously issued raw
/// HttpClient sends with no 429/Retry-After handling and no retry (P5). This centralises
/// token acquisition + resilient retry so every non-Graph scanner behaves consistently.
/// </summary>
public sealed class ResilientHttpClient : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = RetryPolicy.HttpTimeout };
    private readonly DelegatedAuth _auth;
    private const int MaxRetries = 5;

    public ResilientHttpClient(DelegatedAuth auth) => _auth = auth;

    /// <summary>
    /// Send a request with retry on 429 (honouring Retry-After), transient 5xx errors, network
    /// failures and HttpClient timeouts. The factory must build a fresh <see cref="HttpRequestMessage"/>
    /// each attempt because a sent request cannot be reused.
    /// </summary>
    public Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> requestFactory, CancellationToken ct)
        => SendAsync(_ => Task.FromResult(requestFactory()), ct);

    /// <summary>As <see cref="SendAsync(Func{HttpRequestMessage}, CancellationToken)"/> with an async factory (fresh token per attempt).</summary>
    public async Task<HttpResponseMessage> SendAsync(Func<CancellationToken, Task<HttpRequestMessage>> requestFactory, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            var last = attempt >= MaxRetries - 1;
            HttpResponseMessage resp;
            try
            {
                using var req = await requestFactory(ct).ConfigureAwait(false);
                resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (!last && (RetryPolicy.IsTimeout(ex, ct) || ex is HttpRequestException { StatusCode: null }))
            {
                await Task.Delay(RetryPolicy.Backoff(attempt), ct).ConfigureAwait(false);
                continue;
            }

            var isThrottled = resp.StatusCode == (HttpStatusCode)429;
            var isTransient = (int)resp.StatusCode >= 500;
            if ((isThrottled || isTransient) && !last)
            {
                var delay = RetryPolicy.RetryAfter(resp.Headers.RetryAfter)
                    ?? (isThrottled ? RetryPolicy.ThrottleBackoff(attempt) : RetryPolicy.Backoff(attempt));
                resp.Dispose();
                await Task.Delay(delay, ct).ConfigureAwait(false);
                continue;
            }
            return resp;
        }
    }

    /// <summary>
    /// Acquire a token for <paramref name="resourceKey"/>, GET <paramref name="url"/> with retry,
    /// and return the parsed root JSON. Returns null for 404; throws for other non-success codes
    /// (after retries) so callers can fall back or mark the category failed.
    /// </summary>
    public async Task<JsonElement?> GetJsonAsync(string url, string resourceKey, CancellationToken ct)
    {
        // Token per attempt: a long throttle wait can outlive the token acquired before it.
        using var resp = await SendAsync(async tok =>
        {
            var token = await _auth.GetAccessTokenAsync(resourceKey, tok).ConfigureAwait(false);
            var r = new HttpRequestMessage(HttpMethod.Get, url);
            r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return r;
        }, ct).ConfigureAwait(false);

        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        using var doc = await JsonDocument.ParseAsync(
            await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false), cancellationToken: ct).ConfigureAwait(false);
        return doc.RootElement.Clone();
    }

    public void Dispose() => _http.Dispose();
}
