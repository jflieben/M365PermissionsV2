using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Graph;

/// <summary>
/// HTTP client for Microsoft Graph API with automatic pagination, retry, throttling, and batch support.
/// Modeled after V1's new-GraphQuery.ps1 / new-GraphBatchQuery.ps1 patterns.
/// </summary>
public sealed class GraphClient
{
    private readonly DelegatedAuth _auth;
    private readonly HttpClient _http;
    private readonly AdaptiveThrottleManager _throttle;

    private const int DefaultMaxRetries = 5;
    private const int BatchSize = 20;
    private const string GraphBaseUrl = "https://graph.microsoft.com";
    private readonly int _defaultMaxRetries;

    public AdaptiveThrottleManager ThrottleManager => _throttle;

    public GraphClient(DelegatedAuth auth, int maxConcurrency = 5, int maxRetries = DefaultMaxRetries)
    {
        _auth = auth;
        _http = new HttpClient { Timeout = RetryPolicy.HttpTimeout };
        _throttle = new AdaptiveThrottleManager(maxConcurrency, maxConcurrency * 2);
        _defaultMaxRetries = maxRetries > 0 ? maxRetries : DefaultMaxRetries;
    }

    /// <summary>
    /// Execute a paginated GET query. Returns all pages of results.
    /// Handles @odata.nextLink pagination, 429 throttling with Retry-After, and exponential backoff.
    /// </summary>
    public async IAsyncEnumerable<JsonElement> GetPaginatedAsync(
        string url,
        string? version = "v1.0",
        bool eventualConsistency = false,
        int maxRetries = -1,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        if (maxRetries < 0) maxRetries = _defaultMaxRetries;
        var currentUrl = url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? url
            : $"{GraphBaseUrl}/{version}/{url.TrimStart('/')}";

        while (currentUrl != null)
        {
            ct.ThrowIfCancellationRequested();

            var (json, nextLink) = await ExecuteWithRetry(currentUrl, eventualConsistency, maxRetries, ct);
            if (json == null) yield break;

            if (json.Value.TryGetProperty("value", out var valueArray) && valueArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valueArray.EnumerateArray())
                    yield return item;
            }
            else
            {
                yield return json.Value;
            }

            currentUrl = nextLink;
        }
    }

    /// <summary>
    /// Execute a single GET request and return the full response JSON.
    /// </summary>
    public async Task<JsonElement?> GetAsync(string url, string? version = "v1.0",
        bool eventualConsistency = false,
        int maxRetries = -1, CancellationToken ct = default)
    {
        if (maxRetries < 0) maxRetries = _defaultMaxRetries;
        var fullUrl = url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? url
            : $"{GraphBaseUrl}/{version}/{url.TrimStart('/')}";

        var (json, _) = await ExecuteWithRetry(fullUrl, eventualConsistency, maxRetries, ct);
        return json;
    }

    /// <summary>
    /// POST a JSON body (e.g. directoryObjects/getByIds) with the same retry and throttling as GETs.
    /// Returns null for 404.
    /// </summary>
    public async Task<JsonElement?> PostAsync(string url, object body, string? version = "v1.0",
        int maxRetries = -1, CancellationToken ct = default)
    {
        if (maxRetries < 0) maxRetries = _defaultMaxRetries;
        var fullUrl = url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? url
            : $"{GraphBaseUrl}/{version}/{url.TrimStart('/')}";

        var (json, _) = await ExecuteWithRetry(fullUrl, false, maxRetries, ct, HttpMethod.Post, JsonSerializer.Serialize(body));
        return json;
    }

    /// <summary>
    /// Resolve directory object ids via directoryObjects/getByIds (1000 per call). Ids absent from the
    /// result do not exist (deleted). Throws when a call fails, so callers can tell "deleted" from "unknown".
    /// </summary>
    public async Task<Dictionary<string, JsonElement>> GetDirectoryObjectsByIdsAsync(
        IEnumerable<string> ids, string[] types, CancellationToken ct = default)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        var distinct = ids.Where(i => !string.IsNullOrEmpty(i)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        for (int i = 0; i < distinct.Count; i += 1000)
        {
            var chunk = distinct.Skip(i).Take(1000).ToList();
            var json = await PostAsync("directoryObjects/getByIds", new { ids = chunk, types }, ct: ct);
            if (json is { } root && root.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                foreach (var obj in val.EnumerateArray())
                    if (obj.TryGetProperty("id", out var oid) && oid.GetString() is { Length: > 0 } id)
                        result[id] = obj;
        }
        return result;
    }

    /// <summary>
    /// Execute a batch of requests (up to 20 per batch, per Graph API limits).
    /// Returns responses indexed by the request ID. 404 sub-responses are omitted (like GetAsync's null);
    /// any other failure, or a sub-request still throttled after all retries, throws so data loss is never silent.
    /// </summary>
    public async Task<Dictionary<string, JsonElement>> BatchAsync(
        List<BatchRequest> requests,
        string? version = "v1.0",
        int maxRetries = -1,
        CancellationToken ct = default)
    {
        if (maxRetries < 0) maxRetries = _defaultMaxRetries;
        var results = new Dictionary<string, JsonElement>();

        // Process in chunks of BatchSize; each chunk may itself re-issue throttled sub-requests.
        for (int i = 0; i < requests.Count; i += BatchSize)
        {
            ct.ThrowIfCancellationRequested();
            var chunk = requests.Skip(i).Take(BatchSize)
                .Select((r, idx) => new BatchRequest
                {
                    Id = r.Id ?? (i + idx).ToString(),
                    Method = r.Method,
                    RelativeUrl = r.RelativeUrl,
                    Headers = r.Headers
                }).ToList();

            await ExecuteBatchChunkAsync(chunk, version, maxRetries, results, ct);
        }

        return results;
    }

    /// <summary>
    /// Send one batch of at most 20, re-issuing sub-requests that came back 429 or 5xx until they succeed
    /// or retries run out (B11). Handles batch-level and per-sub-request throttling with Retry-After.
    /// </summary>
    private async Task ExecuteBatchChunkAsync(
        List<BatchRequest> chunk, string? version, int maxRetries,
        Dictionary<string, JsonElement> results, CancellationToken ct)
    {
        var batchUrl = $"{GraphBaseUrl}/{version}/$batch";
        var pending = chunk;
        var failures = new List<string>();

        for (int attempt = 0; attempt < maxRetries && pending.Count > 0; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            var batchBody = new
            {
                requests = pending.Select(r => new
                {
                    id = r.Id,
                    method = r.Method,
                    url = r.RelativeUrl,
                    headers = r.Headers
                }).ToArray()
            };

            HttpResponseMessage response;
            await _throttle.WaitAsync(ct);
            try
            {
                var token = await _auth.GetAccessTokenAsync("graph", ct);
                using var request = new HttpRequestMessage(HttpMethod.Post, batchUrl);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Content = new StringContent(JsonSerializer.Serialize(batchBody), Encoding.UTF8, "application/json");
                _throttle.RecordRequest();
                response = await _http.SendAsync(request, ct);
            }
            catch (Exception ex) when (RetryPolicy.IsTimeout(ex, ct) || ex is HttpRequestException { StatusCode: null })
            {
                _throttle.Release();
                await Task.Delay(RetryPolicy.Backoff(attempt), ct);
                continue;
            }
            catch
            {
                _throttle.Release();
                throw;
            }
            _throttle.Release();

            // Batch-level throttling or server error: back off and retry all.
            if (response.StatusCode == (HttpStatusCode)429 || (int)response.StatusCode >= 500)
            {
                var throttled = response.StatusCode == (HttpStatusCode)429;
                if (throttled) _throttle.ReportThrottle();
                var retryAfter = RetryPolicy.RetryAfter(response.Headers.RetryAfter)
                    ?? (throttled ? RetryPolicy.ThrottleBackoff(attempt) : RetryPolicy.Backoff(attempt));
                response.Dispose();
                await Task.Delay(retryAfter, ct);
                continue;
            }

            using (response)
            {
                response.EnsureSuccessStatusCode();
                using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

                if (!doc.RootElement.TryGetProperty("responses", out var responses))
                    throw new HttpRequestException("Graph $batch response had no 'responses' array.");

                var byId = pending.ToDictionary(r => r.Id!, r => r);
                var retryNext = new List<BatchRequest>();
                var maxRetryAfter = TimeSpan.Zero;

                foreach (var resp in responses.EnumerateArray())
                {
                    var id = resp.GetProperty("id").GetString()!;
                    var status = resp.GetProperty("status").GetInt32();
                    byId.Remove(id, out var original);

                    if (status is >= 200 and < 300)
                    {
                        if (resp.TryGetProperty("body", out var body)) results[id] = body.Clone();
                    }
                    else if ((status == 429 || status >= 500) && original != null)
                    {
                        if (status == 429) _throttle.ReportThrottle();
                        retryNext.Add(original);
                        if (resp.TryGetProperty("headers", out var h) && h.TryGetProperty("Retry-After", out var ra)
                            && int.TryParse(ra.GetString(), out var secs))
                            maxRetryAfter = TimeSpan.FromSeconds(Math.Max(maxRetryAfter.TotalSeconds, secs));
                    }
                    else if (status != 404)
                    {
                        failures.Add($"{id}: HTTP {status}");
                    }
                }

                // A sub-request missing from the response is retried rather than dropped.
                retryNext.AddRange(byId.Values);

                _throttle.ReportSuccess();
                pending = retryNext;
                if (pending.Count > 0)
                    await Task.Delay(maxRetryAfter > TimeSpan.Zero ? maxRetryAfter : RetryPolicy.ThrottleBackoff(attempt), ct);
            }
        }

        if (pending.Count > 0)
            throw new GraphRetryExhaustedException(
                $"Graph $batch: {pending.Count} sub-request(s) still throttled or failing after {maxRetries} attempts.");
        if (failures.Count > 0)
            throw new HttpRequestException($"Graph $batch: {failures.Count} sub-request(s) failed ({string.Join(", ", failures.Take(5))}).");
    }

    private async Task<(JsonElement? json, string? nextLink)> ExecuteWithRetry(
        string url, bool eventualConsistency, int maxRetries, CancellationToken ct,
        HttpMethod? method = null, string? jsonBody = null)
    {
        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            var last = attempt == maxRetries - 1;
            TimeSpan delay;

            // The slot is held for the request only; backoff waits happen after it is released.
            await _throttle.WaitAsync(ct);
            try
            {
                var token = await _auth.GetAccessTokenAsync("graph", ct);
                using var request = new HttpRequestMessage(method ?? HttpMethod.Get, url);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                if (jsonBody != null)
                    request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                if (eventualConsistency)
                {
                    request.Headers.Add("ConsistencyLevel", "eventual");
                    // Append $count=true if not already in URL
                    if (!url.Contains("$count", StringComparison.OrdinalIgnoreCase))
                    {
                        var separator = url.Contains('?') ? "&" : "?";
                        request.RequestUri = new Uri($"{url}{separator}$count=true");
                    }
                }

                _throttle.RecordRequest();
                using var response = await _http.SendAsync(request, ct);

                if (response.StatusCode == (HttpStatusCode)429)
                {
                    _throttle.ReportThrottle();
                    delay = RetryPolicy.RetryAfter(response.Headers.RetryAfter) ?? RetryPolicy.ThrottleBackoff(attempt);
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return (null, null);
                }
                else if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync(ct);
                    throw new HttpRequestException(
                        $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(errorBody, 500)}",
                        null, response.StatusCode);
                }
                else
                {
                    _throttle.ReportSuccess();

                    // Disposed after Clone() so the pooled parse buffers go back to the pool.
                    using var doc = await JsonDocument.ParseAsync(
                        await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                    var root = doc.RootElement;

                    string? nextLink = null;
                    if (root.TryGetProperty("@odata.nextLink", out var nl))
                        nextLink = nl.GetString();
                    else if (root.TryGetProperty("odata.nextLink", out var nl2))
                        nextLink = nl2.GetString();

                    return (root.Clone(), nextLink);
                }
            }
            catch (HttpRequestException ex) when (!last && IsTransientError(ex))
            {
                delay = RetryPolicy.Backoff(attempt);
            }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
            {
                // HttpClient.Timeout surfaces as a TaskCanceledException: transient, not a cancellation.
                if (last)
                    throw new GraphRetryExhaustedException($"Graph request timed out after {maxRetries} attempts: {url}", ex);
                delay = RetryPolicy.Backoff(attempt);
            }
            finally
            {
                _throttle.Release();
            }

            await Task.Delay(delay, ct);
        }

        // Retries exhausted (sustained 429s or transient errors). Throw instead of returning
        // null: a silent null makes GetPaginatedAsync stop mid-pagination and the scan gets
        // marked Completed with a truncated dataset (B6). Let the category be marked Failed.
        throw new GraphRetryExhaustedException(
            $"Graph request failed after {maxRetries} attempts (throttling or transient errors): {url}");
    }

    private static bool IsTransientError(HttpRequestException ex)
    {
        // Only retry on server errors (5xx) and network failures (no status code).
        // Client errors (4xx) like 400, 403, etc. are permanent and should not be retried.
        return ex.StatusCode == null || (int)ex.StatusCode >= 500;
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "...";
}

/// <summary>
/// Thrown when a Graph request exhausts all retry attempts (sustained throttling or transient
/// failures). Signals that scan data would be incomplete, so the category must be marked Failed
/// rather than silently truncated.
/// </summary>
public sealed class GraphRetryExhaustedException : Exception
{
    public GraphRetryExhaustedException(string message) : base(message) { }
    public GraphRetryExhaustedException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Shared retry timing for the Graph, Exchange and resource clients.</summary>
public static class RetryPolicy
{
    /// <summary>Per-attempt HttpClient timeout; the default 100 s is too short for large admin pages.</summary>
    public static readonly TimeSpan HttpTimeout = TimeSpan.FromMinutes(4);

    private const double MaxBackoffSeconds = 60;

    /// <summary>Retry-After as a delay, whether sent as seconds or as an HTTP date. Null when absent.</summary>
    public static TimeSpan? RetryAfter(RetryConditionHeaderValue? header, DateTimeOffset? now = null)
    {
        if (header == null) return null;
        if (header.Delta is { } delta) return delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
        if (header.Date is { } date)
        {
            var wait = date - (now ?? DateTimeOffset.UtcNow);
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
        }
        return null;
    }

    /// <summary>Throttle fallback when no Retry-After was sent: min(5 * 2^attempt, 60) s plus up to 1 s jitter.</summary>
    public static TimeSpan ThrottleBackoff(int attempt)
        => TimeSpan.FromSeconds(Math.Min(5 * Math.Pow(2, attempt), MaxBackoffSeconds) + Random.Shared.NextDouble());

    /// <summary>Transient-error backoff: min(2^(attempt+1), 60) s plus up to 1 s jitter.</summary>
    public static TimeSpan Backoff(int attempt)
        => TimeSpan.FromSeconds(Math.Min(Math.Pow(2, attempt + 1), MaxBackoffSeconds) + Random.Shared.NextDouble());

    /// <summary>True for an HttpClient timeout (as opposed to the caller cancelling).</summary>
    public static bool IsTimeout(Exception ex, CancellationToken ct)
        => ex is TaskCanceledException && !ct.IsCancellationRequested;
}

public sealed class BatchRequest
{
    public string? Id { get; set; }
    public string Method { get; set; } = "GET";
    public string RelativeUrl { get; set; } = string.Empty;
    public Dictionary<string, string>? Headers { get; set; }
}
