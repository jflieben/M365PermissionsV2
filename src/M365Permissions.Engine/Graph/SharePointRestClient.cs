using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Text.Json;
using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Graph;

/// <summary>A site collection from the tenant admin API or Graph search.</summary>
public sealed class SiteTarget
{
    public string Url { get; set; } = "";
    public string Title { get; set; } = "";
    public string Template { get; set; } = "";
    public string SiteId { get; set; } = "";       // site collection GUID
    public string GraphSiteId { get; set; } = "";  // hostname,siteCollectionId,webId when known
    public string LockState { get; set; } = "";
    public string ArchiveStatus { get; set; } = "";
    public string Owner { get; set; } = "";

    public bool IsNoAccess => LockState.Equals("NoAccess", StringComparison.OrdinalIgnoreCase);
    public bool IsArchived => !string.IsNullOrEmpty(ArchiveStatus) && !ArchiveStatus.Equals("NotArchived", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Client for SharePoint REST, the SharePoint tenant admin API and the Graph Sites API.
/// Replaces PnP.PowerShell; all calls are pure HTTP.
/// </summary>
public sealed class SharePointRestClient
{
    private readonly DelegatedAuth _auth;
    private readonly GraphClient _graphClient;
    private readonly HttpClient _http;

    // Microsoft prioritises decorated traffic when throttling SharePoint.
    private static readonly string UserAgent = $"NONISV|JSolve|M365Permissions/{Engine.ModuleVersion}";

    public SharePointRestClient(DelegatedAuth auth, GraphClient graphClient)
    {
        _auth = auth;
        _graphClient = graphClient;
        _http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
    }

    // ─── Site enumeration ───

    /// <summary>
    /// Every site collection via the tenant admin API (GetSitePropertiesFromSharePointByFilters), regardless of
    /// the signed-in account's own site access. Needs an active SharePoint Administrator role.
    /// </summary>
    public async Task<List<SiteTarget>> GetTenantSitesAsync(bool includePersonalSites, string template = "", CancellationToken ct = default)
    {
        var adminUrl = _auth.GetSharePointAdminUrl();
        var sites = new List<SiteTarget>();
        string? startIndex = null;
        for (int page = 0; page < 1000; page++)
        {
            var body = JsonSerializer.Serialize(new
            {
                speFilter = new { IncludePersonalSite = includePersonalSites ? 1 : 0, IncludeDetail = false, Template = template, StartIndex = startIndex }
            });
            var data = await SendAsync(HttpMethod.Post, "sharepointadmin", adminUrl,
                "_api/SPO.Tenant/GetSitePropertiesFromSharePointByFilters", body, "Admin REST POST", ct,
                mediaType: "application/json;odata=nometadata");
            if (data == null) break;

            var items = data.Value.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array ? v : default;
            if (items.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in items.EnumerateArray())
                {
                    var url = ReadString(s, "Url").TrimEnd('/');
                    if (string.IsNullOrEmpty(url)) continue;
                    sites.Add(new SiteTarget
                    {
                        Url = url,
                        Title = ReadString(s, "Title"),
                        Template = ReadString(s, "Template"),
                        SiteId = ReadString(s, "SiteId"),
                        LockState = ReadString(s, "LockState"),
                        ArchiveStatus = ReadString(s, "ArchiveStatus"),
                        Owner = ReadString(s, "Owner")
                    });
                }
            }

            var next = ReadString(data.Value, "NextStartIndexFromSharePoint");
            if (string.IsNullOrEmpty(next) || next == "0" || next == startIndex) break;
            startIndex = next;
        }
        return sites;
    }

    /// <summary>
    /// Site collections found through Graph search, trimmed to what the signed-in account can see.
    /// Search also returns subsites and SharePoint Embedded containers: webs are folded into their
    /// collection (shortest URL per siteCollectionId), containers are dropped.
    /// </summary>
    public async Task<List<SiteTarget>> SearchSitesAsync(CancellationToken ct = default)
    {
        var byCollection = new Dictionary<string, SiteTarget>(StringComparer.OrdinalIgnoreCase);
        await foreach (var site in _graphClient.GetPaginatedAsync(
            "sites?search=*&$select=id,displayName,webUrl", ct: ct))
        {
            var id = site.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
            var webUrl = site.TryGetProperty("webUrl", out var w) ? w.GetString() ?? "" : "";
            var collectionId = TryExtractSiteCollectionId(id);
            if (string.IsNullOrEmpty(webUrl) || collectionId == null) continue;

            // Graph percent-encodes URLs; the admin API returns them decoded.
            var url = Uri.UnescapeDataString(webUrl).TrimEnd('/');
            if (url.Contains("/contentstorage/", StringComparison.OrdinalIgnoreCase)) continue;

            if (!byCollection.TryGetValue(collectionId, out var existing) || url.Length < existing.Url.Length)
            {
                byCollection[collectionId] = new SiteTarget
                {
                    Url = url,
                    Title = site.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "",
                    SiteId = collectionId,
                    GraphSiteId = id
                };
            }
        }
        return byCollection.Values.ToList();
    }

    /// <summary>Graph composite site id (hostname,siteCollectionId,webId) for a site URL.</summary>
    public async Task<string> ResolveGraphSiteIdAsync(string siteUrl, CancellationToken ct)
    {
        var uri = new Uri(siteUrl);
        var path = uri.AbsolutePath.TrimEnd('/');
        var response = string.IsNullOrEmpty(path) || path == "/"
            ? await _graphClient.GetAsync($"sites/{uri.Host}?$select=id", ct: ct)
            : await _graphClient.GetAsync($"sites/{uri.Host}:{path}?$select=id", ct: ct);
        return response?.TryGetProperty("id", out var id) == true ? id.GetString() ?? "" : "";
    }

    /// <summary>Get site permissions (app registrations with Sites.Selected style grants).</summary>
    public IAsyncEnumerable<JsonElement> GetSitePermissionsAsync(string graphSiteId, CancellationToken ct = default)
        => _graphClient.GetPaginatedAsync($"sites/{graphSiteId}/permissions", ct: ct);

    /// <summary>One site permission; the list call can omit roles.</summary>
    public Task<JsonElement?> GetSitePermissionAsync(string graphSiteId, string permissionId, CancellationToken ct = default)
        => _graphClient.GetAsync($"sites/{graphSiteId}/permissions/{permissionId}", ct: ct);

    // ─── Site REST ───

    /// <summary>GET a SharePoint REST endpoint and return the parsed body.</summary>
    public Task<JsonElement?> CallSpRestAsync(string siteUrl, string apiPath, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "sharepoint", siteUrl, apiPath, null, "SPO REST", ct);

    /// <summary>GET a SharePoint REST collection, following odata.nextLink.</summary>
    public async Task<List<JsonElement>> GetCollectionAsync(string siteUrl, string apiPath, CancellationToken ct = default)
    {
        var result = new List<JsonElement>();
        var url = $"{siteUrl.TrimEnd('/')}/{apiPath.TrimStart('/')}";
        for (int page = 0; page < 10000 && !string.IsNullOrEmpty(url); page++)
        {
            var json = await SendAsync(HttpMethod.Get, "sharepoint", url, "", null, "SPO REST", ct);
            if (json == null) break;
            if (json.Value.TryGetProperty("value", out var items) && items.ValueKind == JsonValueKind.Array)
                foreach (var item in items.EnumerateArray())
                    result.Add(item.Clone());
            url = ReadString(json.Value, "odata.nextLink");
            if (string.IsNullOrEmpty(url)) url = ReadString(json.Value, "@odata.nextLink");
        }
        return result;
    }

    /// <summary>Site collection admins of a site.</summary>
    public Task<List<JsonElement>> GetSiteAdminsAsync(string siteUrl, CancellationToken ct = default)
        => GetCollectionAsync(siteUrl, "_api/web/siteusers?$filter=IsSiteAdmin eq true", ct);

    /// <summary>Role assignments of a web (apiBase "_api/web") or list (apiBase "_api/web/lists(guid'...')").</summary>
    public Task<List<JsonElement>> GetRoleAssignmentsAsync(string webUrl, string apiBase = "_api/web", CancellationToken ct = default)
        => GetCollectionAsync(webUrl, $"{apiBase}/roleassignments?$expand=Member,RoleDefinitionBindings&$top=5000", ct);

    /// <summary>All SharePoint groups of the site collection with their members (one call per site).</summary>
    public Task<List<JsonElement>> GetSiteGroupsWithUsersAsync(string siteUrl, CancellationToken ct = default)
        => GetCollectionAsync(siteUrl, "_api/web/sitegroups?$expand=Users&$top=5000", ct);

    /// <summary>Direct subsites of a web.</summary>
    public Task<List<JsonElement>> GetSubwebsAsync(string webUrl, CancellationToken ct = default)
        => GetCollectionAsync(webUrl, "_api/web/webs?$select=Url,Title,HasUniqueRoleAssignments&$top=5000", ct);

    /// <summary>Lists and libraries of a web with their inheritance flag.</summary>
    public Task<List<JsonElement>> GetListsAsync(string webUrl, CancellationToken ct = default)
        => GetCollectionAsync(webUrl,
            "_api/web/lists?$select=Id,Title,Hidden,BaseType,HasUniqueRoleAssignments,RootFolder/ServerRelativeUrl&$expand=RootFolder&$top=5000", ct);

    /// <summary>Server-relative URL and kind of a file or folder by its UniqueId, or null when not found in this web.</summary>
    public async Task<(string Path, string Kind)?> ResolveItemAsync(string webUrl, string uniqueId, CancellationToken ct)
    {
        foreach (var (api, kind) in new[] { ("GetFileById", "File"), ("GetFolderById", "Folder") })
        {
            try
            {
                var json = await CallSpRestAsync(webUrl, $"_api/web/{api}('{uniqueId}')?$select=ServerRelativeUrl", ct);
                var path = json == null ? "" : ReadString(json.Value, "ServerRelativeUrl");
                if (!string.IsNullOrEmpty(path)) return (path, kind);
            }
            catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest or HttpStatusCode.InternalServerError)
            {
                // Not a file (or not in this web): try the next kind.
            }
        }
        return null;
    }

    /// <summary>
    /// Whether the signed-in account is site collection admin of the site. Null when it cannot read the
    /// site at all (401/403), which also means it is not an admin there.
    /// </summary>
    public async Task<bool?> IsCurrentUserSiteAdminAsync(string siteUrl, CancellationToken ct)
    {
        try
        {
            var json = await CallSpRestAsync(siteUrl, "_api/web/currentuser?$select=IsSiteAdmin", ct);
            return json?.TryGetProperty("IsSiteAdmin", out var a) == true && a.ValueKind == JsonValueKind.True;
        }
        catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
        {
            return null;
        }
    }

    /// <summary>
    /// Add or remove one site collection admin through the tenant admin API (CSOM Tenant.SetSiteAdmin, as
    /// Set-PnPTenantSite -Owners uses). Unlike SetSiteSecondaryAdministrators it never touches other admins.
    /// </summary>
    public async Task SetSiteAdminViaTenantAsync(string siteUrl, string userUpn, bool isSiteAdmin, CancellationToken ct)
    {
        var adminUrl = _auth.GetSharePointAdminUrl();
        var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<Request xmlns=\"http://schemas.microsoft.com/sharepoint/clientquery/2009\" SchemaVersion=\"15.0.0.0\" LibraryVersion=\"16.0.0.0\" ApplicationName=\"M365Permissions\">" +
            "<Actions><Method Name=\"SetSiteAdmin\" Id=\"1\" ObjectPathId=\"2\"><Parameters>" +
            $"<Parameter Type=\"String\">{SecurityElement.Escape(siteUrl)}</Parameter>" +
            $"<Parameter Type=\"String\">{SecurityElement.Escape("i:0#.f|membership|" + userUpn)}</Parameter>" +
            $"<Parameter Type=\"Boolean\">{(isSiteAdmin ? "true" : "false")}</Parameter>" +
            "</Parameters></Method></Actions>" +
            "<ObjectPaths><Constructor Id=\"2\" TypeId=\"{268004ae-ef6b-4e9b-8425-127220d84719}\" /></ObjectPaths></Request>";

        var response = await SendAsync(HttpMethod.Post, "sharepointadmin", adminUrl, "_vti_bin/client.svc/ProcessQuery",
            xml, "Admin CSOM SetSiteAdmin", ct, mediaType: "text/xml");

        // CSOM reports failures as 200 with ErrorInfo in the first array element.
        if (response is { ValueKind: JsonValueKind.Array } arr && arr.GetArrayLength() > 0
            && arr[0].TryGetProperty("ErrorInfo", out var err) && err.ValueKind == JsonValueKind.Object)
        {
            var message = ReadString(err, "ErrorMessage");
            var code = err.TryGetProperty("ErrorCode", out var c) ? c.ToString() : "";
            // -2147024891 = E_ACCESSDENIED
            throw new HttpRequestException($"SetSiteAdmin failed ({code}): {message}", null,
                code == "-2147024891" ? HttpStatusCode.Forbidden : HttpStatusCode.BadRequest);
        }
    }

    // ─── HTTP ───

    private const int MaxAttempts = 5;

    /// <summary>
    /// Send one SharePoint call, retrying throttling (429/503), gateway errors (502/504), timeouts and
    /// network failures with Retry-After or capped backoff. Returns the parsed body, or null when there is
    /// none. Throws HttpRequestException with the status code on any other failure.
    /// </summary>
    private async Task<JsonElement?> SendAsync(HttpMethod method, string resource, string baseUrl, string apiPath,
        string? body, string label, CancellationToken ct, string mediaType = "application/json")
    {
        var fullUrl = string.IsNullOrEmpty(apiPath) ? baseUrl : $"{baseUrl.TrimEnd('/')}/{apiPath.TrimStart('/')}";

        for (int attempt = 1; ; attempt++)
        {
            var token = await _auth.GetAccessTokenAsync(resource, ct);
            using var request = new HttpRequestMessage(method, fullUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.Add("odata-version", "");
            if (body != null)
                request.Content = new StringContent(body, System.Text.Encoding.UTF8, MediaTypeHeaderValue.Parse(mediaType));

            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, ct);
            }
            catch (Exception ex) when (attempt < MaxAttempts && !ct.IsCancellationRequested
                && ex is HttpRequestException { StatusCode: null } or TaskCanceledException)
            {
                await Task.Delay(Backoff(attempt, null), ct);
                continue;
            }

            using (response)
            {
                if ((int)response.StatusCode is 429 or 502 or 503 or 504 && attempt < MaxAttempts)
                {
                    await Task.Delay(Backoff(attempt, response.Headers.RetryAfter), ct);
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync(ct);
                    throw new HttpRequestException(
                        $"{label} {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(errorBody, 500)}",
                        null, response.StatusCode);
                }

                var text = await response.Content.ReadAsStringAsync(ct);
                if (string.IsNullOrWhiteSpace(text)) return null;
                // A NoAccess-locked or redirected site answers with an HTML page instead of JSON.
                if (text.TrimStart().StartsWith('<'))
                    throw new HttpRequestException($"{label}: the site returned HTML instead of JSON (locked or redirected site?)",
                        null, HttpStatusCode.Forbidden);
                using var doc = JsonDocument.Parse(text);
                return doc.RootElement.Clone();
            }
        }
    }

    private static TimeSpan Backoff(int attempt, RetryConditionHeaderValue? retryAfter)
    {
        var hinted = retryAfter?.Delta
            ?? (retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : (TimeSpan?)null);
        if (hinted is { } h && h > TimeSpan.Zero) return h < TimeSpan.FromMinutes(5) ? h : TimeSpan.FromMinutes(5);
        return TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, attempt) * 2));
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "...";

    private static string ReadString(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind is JsonValueKind.Number ? v.ToString() : ""
            : "";

    /// <summary>
    /// Try to extract the site collection GUID from a Graph composite site ID:
    /// hostname,siteCollectionId,webId.
    /// </summary>
    public static string? TryExtractSiteCollectionId(string? graphSiteId)
    {
        if (string.IsNullOrWhiteSpace(graphSiteId)) return null;
        var parts = graphSiteId.Split(',');
        if (parts.Length >= 2 && !string.IsNullOrWhiteSpace(parts[1]))
            return parts[1];
        return null;
    }
}
