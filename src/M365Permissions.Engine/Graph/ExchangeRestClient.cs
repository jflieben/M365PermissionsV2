using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Graph;

/// <summary>
/// REST client for Exchange Online admin API.
/// Uses the InvokeCommand pattern (POST to /adminapi/beta/{org}/InvokeCommand)
/// matching V1's new-ExOQuery.ps1.
/// </summary>
public sealed class ExchangeRestClient
{
    private readonly DelegatedAuth _auth;
    private readonly HttpClient _http;
    private readonly string _baseUrl = "https://outlook.office365.com";

    private const int MaxRetries = 3;
    private const int MaxPageSize = 1000;

    // Exchange Online transient error codes that should be retried even on HTTP 400
    private static readonly string[] TransientErrorCodes = new[]
    {
        "CmdletProxyNotAvailableFailure",
        "ServerBusyException",
        "TransientException",
        "BackendCommunicationException"
    };

    public ExchangeRestClient(DelegatedAuth auth)
    {
        _auth = auth;
        _http = new HttpClient();
    }

    /// <summary>
    /// Execute an Exchange cmdlet via REST API.
    /// Returns all pages of results.
    /// </summary>
    public async Task<List<JsonElement>> InvokeCommandAsync(
        string organization,
        string cmdletName,
        Dictionary<string, object>? parameters = null,
        CancellationToken ct = default)
    {
        var results = new List<JsonElement>();
        string? nextLink = null;
        var url = $"{_baseUrl}/adminapi/beta/{organization}/InvokeCommand";

        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                var currentUrl = nextLink ?? url;

                do
                {
                    ct.ThrowIfCancellationRequested();

                    var body = new Dictionary<string, object>
                    {
                        ["CmdletInput"] = new
                        {
                            CmdletName = cmdletName,
                            Parameters = parameters ?? new Dictionary<string, object>()
                        }
                    };

                    var token = await _auth.GetAccessTokenAsync("exchange", ct);
                    using var request = new HttpRequestMessage(HttpMethod.Post, currentUrl);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    request.Headers.Add("X-CmdletName", cmdletName);
                    request.Headers.Add("Prefer", $"odata.maxpagesize={MaxPageSize}");
                    request.Headers.Add("X-SerializationLevel", "Partial");
                    request.Content = new StringContent(
                        JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

                    var response = await _http.SendAsync(request, ct);

                    if (!response.IsSuccessStatusCode)
                    {
                        var errorBody = await response.Content.ReadAsStringAsync(ct);
                        var statusCode = response.StatusCode;

                        if (statusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden)
                        {
                            var hint = statusCode == System.Net.HttpStatusCode.Unauthorized
                                ? "Exchange mailbox access is unauthorized. Exchange Administrator role or admin consent for Exchange.ManageAsApp may be missing."
                                : "Exchange mailbox access is forbidden. Exchange Administrator role or admin consent for Exchange.ManageAsApp may be missing.";

                            throw new HttpRequestException(
                                $"EXO {(int)statusCode} {response.ReasonPhrase} [{cmdletName}]: {hint} {Truncate(errorBody, 500)}",
                                null, statusCode);
                        }

                        // Non-auth failure: throw so the outer retry loop handles it. Previously a
                        // transient error broke out of pagination and fell through to `return
                        // results`, returning partial data as success. Now transient Exchange errors
                        // (even on HTTP 400) are matched by the catch filter below, which resets all
                        // pagination state and retries from scratch (B7).
                        throw new HttpRequestException(
                            $"EXO {(int)response.StatusCode} {response.ReasonPhrase} [{cmdletName}]: {Truncate(errorBody, 500)}",
                            null, response.StatusCode);
                    }

                    var doc = await JsonDocument.ParseAsync(
                        await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

                    var root = doc.RootElement;

                    if (root.TryGetProperty("value", out var valueArray) && valueArray.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in valueArray.EnumerateArray())
                            results.Add(item.Clone());
                    }

                    // Check for pagination
                    nextLink = null;
                    if (root.TryGetProperty("@odata.nextLink", out var nl))
                        nextLink = nl.GetString();
                    else if (root.TryGetProperty("odata.nextLink", out var nl2))
                        nextLink = nl2.GetString();

                    currentUrl = nextLink;

                } while (currentUrl != null);

                return results; // Success, exit retry loop

            }
            catch (HttpRequestException ex) when (
                attempt < MaxRetries - 1 &&
                (ex.StatusCode == null || (int)ex.StatusCode >= 500 ||
                 (ex.Message != null && TransientErrorCodes.Any(code => ex.Message.Contains(code, StringComparison.OrdinalIgnoreCase)))))
            {
                // Reset ALL pagination state before retrying from scratch: both the accumulated
                // results and the nextLink cursor. Otherwise the retry resumed mid-pagination
                // having discarded pages 1..n-1 (B7).
                results.Clear();
                nextLink = null;
                await Task.Delay(TimeSpan.FromSeconds((attempt + 1) * 2), ct);
            }
        }

        return results;
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "...";

    /// <summary>Get all mailboxes in the tenant.</summary>
    public Task<List<JsonElement>> GetMailboxesAsync(string organization, CancellationToken ct = default)
    {
        return InvokeCommandAsync(organization, "Get-Mailbox",
            new Dictionary<string, object>
            {
                ["ResultSize"] = "Unlimited"
            }, ct);
    }

    /// <summary>Get mailbox permissions for a specific mailbox.</summary>
    public Task<List<JsonElement>> GetMailboxPermissionsAsync(string organization, string identity, CancellationToken ct = default)
    {
        return InvokeCommandAsync(organization, "Get-MailboxPermission",
            new Dictionary<string, object>
            {
                ["Identity"] = identity
            }, ct);
    }

    /// <summary>Get recipient permissions (SendAs).</summary>
    public Task<List<JsonElement>> GetRecipientPermissionsAsync(string organization, string identity, CancellationToken ct = default)
    {
        return InvokeCommandAsync(organization, "Get-RecipientPermission",
            new Dictionary<string, object>
            {
                ["Identity"] = identity
            }, ct);
    }

    /// <summary>Get mailbox folder statistics to enumerate all folders.</summary>
    public Task<List<JsonElement>> GetMailboxFolderStatisticsAsync(string organization, string identity, CancellationToken ct = default)
    {
        return InvokeCommandAsync(organization, "Get-MailboxFolderStatistics",
            new Dictionary<string, object>
            {
                ["Identity"] = identity
            }, ct);
    }

    /// <summary>Get folder-level permissions for a specific mailbox folder.</summary>
    public Task<List<JsonElement>> GetMailboxFolderPermissionsAsync(string organization, string folderIdentity, CancellationToken ct = default)
    {
        return InvokeCommandAsync(organization, "Get-MailboxFolderPermission",
            new Dictionary<string, object>
            {
                ["Identity"] = folderIdentity
            }, ct);
    }
}
