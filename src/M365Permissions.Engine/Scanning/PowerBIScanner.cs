using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Power BI workspaces for access permissions.
/// Uses the Power BI admin API (all workspaces) and falls back to the caller's own workspaces
/// when the account is not a Fabric/Power BI administrator.
/// </summary>
public sealed class PowerBIScanner : IScanProvider
{
    public string Category => "PowerBI";

    private const string ApiBase = "https://api.powerbi.com/v1.0/myorg";
    private const int MaxRetries = 5;

    private readonly DelegatedAuth _auth;

    // admin/groups?$expand=users with 5000 workspaces per page can exceed HttpClient's default 100 s.
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(5) };

    public PowerBIScanner(DelegatedAuth auth)
    {
        _auth = auth;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Power BI workspaces...", 3);

        // Admin API first for full workspace enumeration. Throttling and server errors are retried and
        // then fail the category; only an authorization failure falls back to the user-scoped API.
        var pbiWorkspaces = new List<JsonElement>();
        var useFallback = false;
        const int pageSize = 5000; // admin/groups requires $top and caps it at 5000; page with $skip
        for (int skip = 0; ; skip += pageSize)
        {
            using var resp = await GetAsync($"{ApiBase}/admin/groups?$top={pageSize}&$skip={skip}&$expand=users", ct);

            if (!resp.IsSuccessStatusCode)
            {
                if (skip == 0 && resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    useFallback = true;
                    break;
                }
                throw new InvalidOperationException(
                    $"Power BI Admin API returned HTTP {(int)resp.StatusCode} after {skip} workspaces; results would be incomplete.");
            }

            using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            var count = 0;
            if (doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
            {
                foreach (var ws in val.EnumerateArray())
                {
                    pbiWorkspaces.Add(ws.Clone());
                    count++;
                }
            }
            if (count < pageSize) break;
        }

        if (useFallback)
        {
            context.MarkPartial("Power BI admin API not available (needs Fabric/Power BI Administrator); only workspaces the signed-in account belongs to were scanned");
            await foreach (var entry in ScanUserWorkspacesAsync(context, ct))
                yield return entry;
            context.ReportProgress("Completed Power BI scan.", 3);
            yield break;
        }

        var active = pbiWorkspaces.Where(IsActive).ToList();
        if (active.Count < pbiWorkspaces.Count)
            context.ReportProgress($"Skipped {pbiWorkspaces.Count - active.Count} deleted or removing Power BI workspace(s).", 4);

        context.SetTotalTargets(active.Count);
        context.ReportProgress($"Found {active.Count} active Power BI workspaces via Admin API.", 3);

        var orphaned = 0;
        foreach (var ws in active)
        {
            ct.ThrowIfCancellationRequested();

            var wsId = GetString(ws, "id");
            var wsName = GetString(ws, "name");
            var users = ws.TryGetProperty("users", out var u) && u.ValueKind == JsonValueKind.Array
                ? u.EnumerateArray().ToList()
                : new List<JsonElement>();

            var targetType = WorkspaceTargetType(GetString(ws, "type"), users);
            if (targetType == OrphanedWorkspace) orphaned++;

            foreach (var user in users)
            {
                var entry = MapWorkspaceUser(user, wsName, wsId, targetType);
                if (entry != null) yield return entry;
            }

            context.CompleteTarget();
        }

        if (orphaned > 0)
            context.ReportProgress($"{orphaned} Power BI workspace(s) have no Admin (orphaned); reported with target type {OrphanedWorkspace}.", 2);

        context.ReportProgress("Completed Power BI scan.", 3);
    }

    /// <summary>
    /// Fallback for non-admins: the caller's own workspaces, with users read per workspace
    /// (the non-admin groups list does not expand users).
    /// </summary>
    private async IAsyncEnumerable<PermissionEntry> ScanUserWorkspacesAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var workspaces = await GetPagedAsync($"{ApiBase}/groups", ct);
        var active = workspaces.Where(IsActive).ToList();
        context.SetTotalTargets(active.Count);
        context.ReportProgress($"Found {active.Count} Power BI workspaces the signed-in account belongs to.", 3);

        var orphaned = 0;
        foreach (var ws in active)
        {
            ct.ThrowIfCancellationRequested();

            var wsId = GetString(ws, "id");
            var wsName = GetString(ws, "name");

            List<JsonElement> users;
            try
            {
                users = await GetPagedAsync($"{ApiBase}/groups/{Uri.EscapeDataString(wsId)}/users", ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.ReportProgress($"Failed to read users of Power BI workspace '{wsName}': {ex.Message}", 2);
                context.FailTarget();
                continue;
            }

            var targetType = WorkspaceTargetType(GetString(ws, "type"), users);
            if (targetType == OrphanedWorkspace) orphaned++;

            foreach (var user in users)
            {
                var entry = MapWorkspaceUser(user, wsName, wsId, targetType);
                if (entry != null) yield return entry;
            }

            context.CompleteTarget();
        }

        if (orphaned > 0)
            context.ReportProgress($"{orphaned} Power BI workspace(s) have no Admin (orphaned); reported with target type {OrphanedWorkspace}.", 2);
    }

    /// <summary>GET a $top/$skip paged Power BI list. Throws on any non-success status.</summary>
    private async Task<List<JsonElement>> GetPagedAsync(string url, CancellationToken ct)
    {
        const int pageSize = 5000;
        var items = new List<JsonElement>();
        var sep = url.Contains('?') ? "&" : "?";
        for (int skip = 0; ; skip += pageSize)
        {
            using var resp = await GetAsync($"{url}{sep}$top={pageSize}&$skip={skip}", ct);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"Power BI API returned HTTP {(int)resp.StatusCode} for {url}", null, resp.StatusCode);

            using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            var count = 0;
            if (doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in val.EnumerateArray())
                {
                    items.Add(item.Clone());
                    count++;
                }
            }
            if (count < pageSize) return items;
        }
    }

    /// <summary>GET with retry on 429 (honouring Retry-After) and 5xx. Returns the last response.</summary>
    private async Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            var token = await _auth.GetAccessTokenAsync("powerbi", ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var resp = await _http.SendAsync(req, ct);

            var retryable = resp.StatusCode == (HttpStatusCode)429 || (int)resp.StatusCode >= 500;
            if (!retryable || attempt >= MaxRetries - 1) return resp;

            var delay = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1));
            resp.Dispose();
            await Task.Delay(delay, ct);
        }
    }

    // ── Mapping helpers ─────────────────────────────────────────

    internal const string OrphanedWorkspace = "OrphanedWorkspace";

    /// <summary>Live workspaces: Active, Orphaned, or no state (user-scoped API). Deleted/Removing are skipped.</summary>
    internal static bool IsActive(JsonElement ws)
    {
        var state = GetString(ws, "state");
        return state.Length == 0 ||
               state.Equals("Active", StringComparison.OrdinalIgnoreCase) ||
               state.Equals("Orphaned", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>PersonalWorkspace for My workspaces, OrphanedWorkspace when no user holds Admin, else Workspace.</summary>
    internal static string WorkspaceTargetType(string? workspaceType, IEnumerable<JsonElement> users)
    {
        if (workspaceType is not null &&
            (workspaceType.Equals("PersonalGroup", StringComparison.OrdinalIgnoreCase) ||
             workspaceType.Equals("Personal", StringComparison.OrdinalIgnoreCase)))
            return "PersonalWorkspace";

        var hasAdmin = users.Any(u => GetString(u, "groupUserAccessRight").Equals("Admin", StringComparison.OrdinalIgnoreCase));
        return hasAdmin ? "Workspace" : OrphanedWorkspace;
    }

    internal static PermissionEntry? MapWorkspaceUser(JsonElement user, string workspaceName, string workspaceId, string targetType)
    {
        var email = GetString(user, "emailAddress");
        var displayName = GetString(user, "displayName");
        var role = GetString(user, "groupUserAccessRight");
        var principalType = GetString(user, "principalType");
        var identifier = GetString(user, "identifier");
        var graphId = GetString(user, "graphId");

        if (email.Length == 0 && displayName.Length == 0 && identifier.Length == 0)
            return null;

        // For users the identifier is the UPN/email; graphId carries the Entra object id.
        var isUser = principalType.Equals("User", StringComparison.OrdinalIgnoreCase);
        var entraId = graphId.Length > 0 ? graphId : (isUser && identifier.Contains('@') ? "" : identifier);
        var upn = email.Length > 0 ? email : (isUser ? identifier : "");

        return new PermissionEntry
        {
            TargetPath = $"PowerBI/{workspaceName}",
            TargetType = targetType,
            TargetId = workspaceId,
            PrincipalEntraUpn = upn,
            PrincipalEntraId = entraId,
            PrincipalSysId = identifier,
            PrincipalSysName = displayName.Length > 0 ? displayName : upn,
            PrincipalType = MapPrincipalType(principalType, GetString(user, "userType")),
            PrincipalRole = role,
            Through = "WorkspaceAccess",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    internal static string MapPrincipalType(string? pbiType, string? userType = null) => pbiType?.ToLowerInvariant() switch
    {
        "user" when string.Equals(userType, "Guest", StringComparison.OrdinalIgnoreCase) => "Guest",
        "user" => "User",
        "group" => "SecurityGroup",
        "app" => "Application",
        _ => "Unknown"
    };

    private static string GetString(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
