using System.Net.Http.Headers;
using System.Text.Json;
using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Graph;

/// <summary>
/// Client for SharePoint REST API v2 and Graph Sites API.
/// Replaces PnP.PowerShell — all calls are pure HTTP.
/// </summary>
public sealed class SharePointRestClient
{
    private readonly DelegatedAuth _auth;
    private readonly GraphClient _graphClient;
    private readonly HttpClient _http;

    public SharePointRestClient(DelegatedAuth auth, GraphClient graphClient)
    {
        _auth = auth;
        _graphClient = graphClient;
        _http = new HttpClient();
    }

    /// <summary>Enumerate all sites in the tenant via Graph getAllSites (admin-consented).</summary>
    public async IAsyncEnumerable<JsonElement> GetAllSitesAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        // getAllSites returns ALL tenant sites (requires Sites.Read.All with admin consent)
        // Falls back to sites?search=* if getAllSites fails (returns only user-accessible sites)
        bool useGetAllSites = true;

        try
        {
            // Test if getAllSites works with a single item
            await _graphClient.GetAsync("sites/getAllSites?$top=1&$select=id", ct: ct);
        }
        catch
        {
            useGetAllSites = false;
        }

        if (useGetAllSites)
        {
            await foreach (var site in _graphClient.GetPaginatedAsync(
                "sites/getAllSites?$select=id,displayName,webUrl,createdDateTime,lastModifiedDateTime,siteCollection",
                ct: ct))
            {
                yield return site;
            }
        }
        else
        {
            // Fallback: search=* returns only sites the user can discover
            await foreach (var site in _graphClient.GetPaginatedAsync(
                "sites?search=*&$select=id,displayName,webUrl,createdDateTime,lastModifiedDateTime,siteCollection",
                ct: ct))
            {
                yield return site;
            }
        }
    }

    /// <summary>Get site permissions (app registrations, users, groups with direct access).</summary>
    public IAsyncEnumerable<JsonElement> GetSitePermissionsAsync(string siteId, CancellationToken ct = default)
    {
        return _graphClient.GetPaginatedAsync($"sites/{siteId}/permissions", ct: ct);
    }

    /// <summary>
    /// Call SharePoint REST API directly (for features not yet in Graph).
    /// Example: /_api/web/roleassignments, /_api/web/sitegroups
    /// </summary>
    public Task<JsonElement?> CallSpRestAsync(string siteUrl, string apiPath, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, "sharepoint", siteUrl, apiPath, null, "SPO REST", ct);

    /// <summary>POST to SharePoint REST API and return the response JSON.</summary>
    private Task<JsonElement?> PostSpRestAsync(string siteUrl, string apiPath, string jsonBody, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, "sharepoint", siteUrl, apiPath, jsonBody, "SPO REST POST", ct);

    /// <summary>PATCH/MERGE to SharePoint REST API (for updating user properties).</summary>
    private Task PatchSpRestAsync(string siteUrl, string apiPath, string jsonBody, CancellationToken ct = default)
        => SendAsync(HttpMethod.Patch, "sharepoint", siteUrl, apiPath, jsonBody, "SPO REST PATCH", ct);

    private const int MaxAttempts = 5;

    /// <summary>
    /// Send one SharePoint REST call, retrying throttled responses (429/503) with Retry-After.
    /// Returns the parsed body, or null when there is none (PATCH/MERGE). Throws HttpRequestException
    /// with the status code on any other failure.
    /// </summary>
    private async Task<JsonElement?> SendAsync(HttpMethod method, string resource, string baseUrl, string apiPath,
        string? jsonBody, string label, CancellationToken ct)
    {
        var fullUrl = $"{baseUrl.TrimEnd('/')}/{apiPath.TrimStart('/')}";

        for (int attempt = 1; ; attempt++)
        {
            var token = await _auth.GetAccessTokenAsync(resource, ct);
            using var request = new HttpRequestMessage(method, fullUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("odata-version", "");
            if (method == HttpMethod.Patch)
            {
                request.Headers.Add("X-HTTP-Method", "MERGE");
                request.Headers.Add("IF-MATCH", "*");
            }
            if (jsonBody != null)
                request.Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");

            using var response = await _http.SendAsync(request, ct);

            if ((int)response.StatusCode is 429 or 503 && attempt < MaxAttempts)
            {
                await Task.Delay(response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt)), ct);
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(ct);
                throw new HttpRequestException(
                    $"{label} {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(errorBody, 500)}",
                    null, response.StatusCode);
            }

            if (method == HttpMethod.Patch || response.Content.Headers.ContentLength == 0)
                return null;

            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            return doc.RootElement.Clone();
        }
    }

    /// <summary>
    /// Ensure the current user is a site collection admin. Returns true if the user was ADDED
    /// (was not already admin), false if they were already admin.
    /// </summary>
    public async Task<bool> EnsureSiteAdminAsync(string siteUrl, string userUpn, CancellationToken ct = default)
    {
        // First check if user is already a site admin
        var admins = await GetSiteAdminsAsync(siteUrl, ct);
        foreach (var admin in admins)
        {
            var email = admin.TryGetProperty("Email", out var e) ? e.GetString() ?? "" : "";
            var loginName = admin.TryGetProperty("LoginName", out var ln) ? ln.GetString() ?? "" : "";

            if (email.Equals(userUpn, StringComparison.OrdinalIgnoreCase) ||
                loginName.Contains(userUpn, StringComparison.OrdinalIgnoreCase))
            {
                return false; // Already an admin
            }
        }

        // EnsureUser first to get the user into the site's user info list
        var ensureBody = JsonSerializer.Serialize(new { logonName = $"i:0#.f|membership|{userUpn}" });
        var userResult = await PostSpRestAsync(siteUrl, "_api/web/ensureuser", ensureBody, ct);

        // Get the user's SP user ID from the response
        int userId = 0;
        if (userResult?.TryGetProperty("Id", out var idProp) == true)
        {
            userId = idProp.GetInt32();
        }
        else
        {
            throw new InvalidOperationException($"EnsureUser did not return an Id for {userUpn}");
        }

        // Set IsSiteAdmin = true via MERGE
        var patchBody = JsonSerializer.Serialize(new { IsSiteAdmin = true });
        await PatchSpRestAsync(siteUrl, $"_api/web/GetUserById({userId})", patchBody, ct);

        return true; // Was added as admin
    }

    /// <summary>
    /// Remove a user's site collection admin rights.
    /// </summary>
    public async Task RemoveSiteAdminAsync(string siteUrl, string userUpn, CancellationToken ct = default)
    {
        // EnsureUser to get SP user ID
        var ensureBody = JsonSerializer.Serialize(new { logonName = $"i:0#.f|membership|{userUpn}" });
        var userResult = await PostSpRestAsync(siteUrl, "_api/web/ensureuser", ensureBody, ct);

        int userId = 0;
        if (userResult?.TryGetProperty("Id", out var idProp) == true)
        {
            userId = idProp.GetInt32();
        }
        else
        {
            return; // Can't find user — nothing to remove
        }

        var patchBody = JsonSerializer.Serialize(new { IsSiteAdmin = false });
        await PatchSpRestAsync(siteUrl, $"_api/web/GetUserById({userId})", patchBody, ct);
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "...";

    /// <summary>Get site collection admins via SharePoint REST.</summary>
    public async Task<List<JsonElement>> GetSiteAdminsAsync(string siteUrl, CancellationToken ct = default)
    {
        var result = new List<JsonElement>();
        var json = await CallSpRestAsync(siteUrl, "_api/web/siteusers?$filter=IsSiteAdmin eq true", ct);
        if (json?.TryGetProperty("value", out var admins) == true)
        {
            foreach (var admin in admins.EnumerateArray())
                result.Add(admin.Clone());
        }
        return result;
    }

    /// <summary>Get role assignments (unique permissions) for a web.</summary>
    public async Task<List<JsonElement>> GetRoleAssignmentsAsync(string siteUrl, CancellationToken ct = default)
    {
        var result = new List<JsonElement>();
        // $top: without it large collections can come back truncated (same as the hosted scanner).
        var json = await CallSpRestAsync(siteUrl,
            "_api/web/roleassignments?$expand=Member,RoleDefinitionBindings&$top=5000", ct);
        if (json?.TryGetProperty("value", out var assignments) == true)
        {
            foreach (var assignment in assignments.EnumerateArray())
                result.Add(assignment.Clone());
        }
        return result;
    }

    // ─── Tenant admin API methods (for OneDrive personal sites) ───

    /// <summary>
    /// Get the site collection GUID from a site URL via Microsoft Graph.
    /// Graph returns id as "hostname,siteCollectionId,webId" — we need the middle GUID.
    /// </summary>
    private async Task<string> GetSiteCollectionIdAsync(string siteUrl, CancellationToken ct)
    {
        var uri = new Uri(siteUrl);
        var hostname = uri.Host;
        var sitePath = uri.AbsolutePath.TrimEnd('/');

        JsonElement? siteResponse;
        if (string.IsNullOrEmpty(sitePath) || sitePath == "/")
            siteResponse = await _graphClient.GetAsync($"sites/{hostname}?$select=id", ct: ct);
        else
            siteResponse = await _graphClient.GetAsync($"sites/{hostname}:{sitePath}?$select=id", ct: ct);

        if (siteResponse == null)
            throw new InvalidOperationException($"Could not resolve site via Graph: {siteUrl}");

        var siteId = siteResponse.Value.GetProperty("id").GetString() ?? "";
        var parts = siteId.Split(',');
        if (parts.Length >= 2) return parts[1];
        throw new InvalidOperationException($"Unexpected site ID format from Graph: {siteId}");
    }

    /// <summary>POST to SharePoint admin REST API.</summary>
    private Task<JsonElement?> PostAdminRestAsync(string adminUrl, string apiPath, string jsonBody, CancellationToken ct)
        => SendAsync(HttpMethod.Post, "sharepointadmin", adminUrl, apiPath, jsonBody, "Admin REST POST", ct);

    /// <summary>
    /// Add a user as site collection admin via the SharePoint tenant admin API.
    /// This works on OneDrive personal sites where the scanning user has no direct access.
    /// Returns true if the user was added, false if already an admin.
    /// </summary>
    public async Task<bool> EnsureSiteAdminViaTenantAsync(string siteUrl, string userUpn, CancellationToken ct = default, string? siteCollectionId = null)
    {
        var adminUrl = _auth.GetSharePointAdminUrl();
        siteCollectionId ??= await GetSiteCollectionIdAsync(siteUrl, ct);
        var loginName = $"i:0#.f|membership|{userUpn}";

        // Get current secondary admins
        var currentAdmins = new List<string>();
        try
        {
            var body = JsonSerializer.Serialize(new
            {
                secondaryAdministratorsFieldsData = new { siteId = siteCollectionId }
            });
            var response = await PostAdminRestAsync(adminUrl,
                "_api/SPOInternalUseOnly.Tenant/GetSiteSecondaryAdministrators", body, ct);

            if (response?.TryGetProperty("value", out var admins) == true && admins.ValueKind == JsonValueKind.Array)
            {
                foreach (var admin in admins.EnumerateArray())
                {
                    // Each entry may have encodedClaim, loginName, or be a plain string
                    var name = admin.TryGetProperty("encodedClaim", out var ec)
                        ? ec.GetString() ?? ""
                        : admin.TryGetProperty("loginName", out var ln)
                            ? ln.GetString() ?? ""
                            : admin.ValueKind == JsonValueKind.String
                                ? admin.GetString() ?? ""
                                : "";
                    if (!string.IsNullOrEmpty(name))
                        currentAdmins.Add(name);
                }
            }
        }
        catch
        {
            // No existing secondary admins or endpoint format differs — proceed with empty list
        }

        // Check if already admin
        if (currentAdmins.Any(a => a.Contains(userUpn, StringComparison.OrdinalIgnoreCase)))
            return false;

        // Add user to secondary admins list
        currentAdmins.Add(loginName);

        var setBody = JsonSerializer.Serialize(new
        {
            secondaryAdministratorsFieldsData = new
            {
                siteId = siteCollectionId,
                secondaryAdministratorLoginNames = currentAdmins.ToArray()
            }
        });

        await PostAdminRestAsync(adminUrl,
            "_api/SPOInternalUseOnly.Tenant/SetSiteSecondaryAdministrators", setBody, ct);
        return true;
    }

    /// <summary>
    /// Remove a user from site collection admins via the SharePoint tenant admin API.
    /// </summary>
    public async Task RemoveSiteAdminViaTenantAsync(string siteUrl, string userUpn, CancellationToken ct = default, string? siteCollectionId = null)
    {
        var adminUrl = _auth.GetSharePointAdminUrl();

        if (string.IsNullOrEmpty(siteCollectionId))
        {
            try
            {
                siteCollectionId = await GetSiteCollectionIdAsync(siteUrl, ct);
            }
            catch
            {
                return; // Can't resolve site — nothing to remove
            }
        }

        // Get current secondary admins
        var currentAdmins = new List<string>();
        try
        {
            var body = JsonSerializer.Serialize(new
            {
                secondaryAdministratorsFieldsData = new { siteId = siteCollectionId }
            });
            var response = await PostAdminRestAsync(adminUrl,
                "_api/SPOInternalUseOnly.Tenant/GetSiteSecondaryAdministrators", body, ct);

            if (response?.TryGetProperty("value", out var admins) == true && admins.ValueKind == JsonValueKind.Array)
            {
                foreach (var admin in admins.EnumerateArray())
                {
                    var name = admin.TryGetProperty("encodedClaim", out var ec)
                        ? ec.GetString() ?? ""
                        : admin.TryGetProperty("loginName", out var ln)
                            ? ln.GetString() ?? ""
                            : admin.ValueKind == JsonValueKind.String
                                ? admin.GetString() ?? ""
                                : "";
                    if (!string.IsNullOrEmpty(name))
                        currentAdmins.Add(name);
                }
            }
        }
        catch
        {
            return; // Can't get admins — nothing to remove
        }

        // Remove the user
        var filtered = currentAdmins
            .Where(a => !a.Contains(userUpn, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (filtered.Count == currentAdmins.Count)
            return; // User wasn't in the list

        var setBody = JsonSerializer.Serialize(new
        {
            secondaryAdministratorsFieldsData = new
            {
                siteId = siteCollectionId,
                secondaryAdministratorLoginNames = filtered.ToArray()
            }
        });

        await PostAdminRestAsync(adminUrl,
            "_api/SPOInternalUseOnly.Tenant/SetSiteSecondaryAdministrators", setBody, ct);
    }

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
