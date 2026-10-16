using System.Net.Http.Headers;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Power Platform environments: Power Automate flows, PowerApps, and connectors.
/// Uses the Flow Management API and PowerApps API.
/// </summary>
public sealed class PowerAutomateScanner : IScanProvider
{
    public string Category => "PowerAutomate";

    private const string ApiVersion = "api-version=2016-11-01";

    private readonly DelegatedAuth _auth;
    private readonly ResilientHttpClient _http;

    public PowerAutomateScanner(DelegatedAuth auth)
    {
        _auth = auth;
        _http = new ResilientHttpClient(auth);
    }

    /// <summary>
    /// GET a Power Platform list with the powerapps token, following nextLink. Returns null plus the status
    /// code when the first page fails (callers fall back); throws when a later page fails.
    /// </summary>
    private async Task<(List<JsonElement>? Items, int Status)> GetAllAsync(string url, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        string? next = url;
        while (!string.IsNullOrEmpty(next))
        {
            var pageUrl = next;
            var token = await _auth.GetAccessTokenAsync("powerapps", ct);
            using var resp = await _http.SendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, pageUrl);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return req;
            }, ct);

            if (!resp.IsSuccessStatusCode)
            {
                if (items.Count == 0 && pageUrl == url) return (null, (int)resp.StatusCode);
                throw new HttpRequestException($"HTTP {(int)resp.StatusCode} while paging {url}; results would be incomplete.", null, resp.StatusCode);
            }

            using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            if (doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                foreach (var v in val.EnumerateArray())
                    items.Add(v.Clone());
            next = doc.RootElement.TryGetProperty("nextLink", out var nl) ? nl.GetString() : null;
        }
        return (items, 200);
    }

    /// <summary>Per-environment scan state: admin vs user-scoped endpoints, and whether a list failed.</summary>
    private sealed class EnvScan
    {
        public required string Id { get; init; }
        public required string Name { get; init; }
        public required bool Admin { get; init; }
        public bool Failed { get; set; }
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Power Platform environments...", 3);

        // Discover environments via BAP API (audience = service.powerapps.com per MS module)
        var environments = new List<(string Id, string Name)>();
        var admin = true;
        try
        {
            // Try admin endpoint first for all tenant environments
            var (envList, status) = await GetAllAsync(
                $"https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?{ApiVersion}", ct);
            if (envList == null)
            {
                admin = false;
                context.MarkPartial($"Power Platform admin API returned HTTP {status} (needs Power Platform Administrator); only environments, flows and apps the signed-in account can access were scanned");
                (envList, status) = await GetAllAsync(
                    $"https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments?{ApiVersion}", ct);
            }

            if (envList != null)
            {
                foreach (var env in envList)
                {
                    var envId = env.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    var envDisplayName = envId;
                    if (env.TryGetProperty("properties", out var props))
                    {
                        if (props.TryGetProperty("displayName", out var dn))
                            envDisplayName = dn.GetString() ?? envId;

                        // Skip disabled environments (matching V1)
                        if (props.TryGetProperty("states", out var states) &&
                            states.TryGetProperty("runtime", out var runtime) &&
                            runtime.TryGetProperty("id", out var runtimeId) &&
                            string.Equals(runtimeId.GetString(), "Disabled", StringComparison.OrdinalIgnoreCase))
                        {
                            context.ReportProgress($"Skipping environment '{envDisplayName}' because it is disabled.", 4);
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(envId))
                        environments.Add((envId, envDisplayName));
                }
            }
            else
            {
                throw new InvalidOperationException($"Cannot access Power Platform environments API (HTTP {status}). Check required scopes.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ResourcePrincipalNotFoundException and not InvalidOperationException)
        {
            // Without environments nothing else runs: fail the category instead of reporting it complete.
            throw new InvalidOperationException($"Failed to enumerate Power Platform environments: {ex.Message}", ex);
        }

        context.ReportProgress($"Found {environments.Count} Power Platform environment(s).", 3);

        context.SetTotalTargets(environments.Count);

        foreach (var (envId, envName) in environments)
        {
            ct.ThrowIfCancellationRequested();
            var env = new EnvScan { Id = envId, Name = envName, Admin = admin };

            // ── Flows ──────────────────────────────────────────
            await foreach (var entry in ScanFlowsAsync(env, context, ct))
                yield return entry;

            // ── PowerApps ──────────────────────────────────────
            await foreach (var entry in ScanPowerAppsAsync(env, context, ct))
                yield return entry;

            // ── Connectors ─────────────────────────────────────
            await foreach (var entry in ScanConnectorsAsync(env, context, ct))
                yield return entry;

            if (env.Failed) context.FailTarget();
            else context.CompleteTarget();
        }

        context.ReportProgress("Completed Power Platform scan.", 3);
    }

    /// <summary>
    /// List items for an environment: admin URL first (when admin), user URL as fallback.
    /// Returns null and marks the environment failed when the list cannot be read.
    /// </summary>
    private async Task<List<JsonElement>?> ListAsync(
        EnvScan env, string kind, string adminUrl, string userUrl, ScanContext context, CancellationToken ct)
    {
        try
        {
            if (env.Admin)
            {
                var (list, status) = await GetAllAsync(adminUrl, ct);
                if (list != null) return list;
                context.MarkPartial($"{kind} admin API returned HTTP {status} for '{env.Name}'; only {kind.ToLowerInvariant()} the signed-in account can access were scanned there");
            }

            var (userList, userStatus) = await GetAllAsync(userUrl, ct);
            if (userList != null) return userList;
            context.ReportProgress($"Cannot list {kind.ToLowerInvariant()} in '{env.Name}': HTTP {userStatus}.", 2);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Error listing {kind.ToLowerInvariant()} in '{env.Name}': {ex.Message}", 2);
        }

        env.Failed = true;
        return null;
    }

    /// <summary>
    /// Read a flow/app permissions list. Returns null when it could not be read; 409 (solution-aware
    /// flows have no sharing list here) is expected and logged at debug level, other failures fail the item.
    /// </summary>
    private async Task<List<JsonElement>?> GetPermissionsAsync(string url, string itemLabel, ScanContext context, CancellationToken ct)
    {
        try
        {
            var (permissions, status) = await GetAllAsync(url, ct);
            if (permissions != null) return permissions;
            if (status == 409)
            {
                context.ReportProgress($"No permissions list for {itemLabel} (HTTP 409, solution-aware).", 4);
                return null;
            }
            context.ReportProgress($"Failed to read permissions of {itemLabel}: HTTP {status}.", 2);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Failed to read permissions of {itemLabel}: {ex.Message}", 2);
        }

        context.FailTarget();
        return null;
    }

    // ── Flows ────────────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanFlowsAsync(
        EnvScan env, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var flows = await ListAsync(env, "Flows",
            $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{env.Id}/v2/flows?{ApiVersion}&$select=permissions",
            $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/{env.Id}/flows?{ApiVersion}&$top=250&$select=permissions",
            context, ct);
        if (flows == null) yield break;

        context.ReportProgress($"Scanning {flows.Count} flows in '{env.Name}'...", 3);

        foreach (var flow in flows)
        {
            ct.ThrowIfCancellationRequested();

            var flowId = flow.TryGetProperty("name", out var fn) ? fn.GetString() ?? "" : "";
            var flowDisplayName = flowId;
            JsonElement creator = default;
            if (flow.TryGetProperty("properties", out var fprops))
            {
                if (fprops.TryGetProperty("displayName", out var fdn))
                    flowDisplayName = fdn.GetString() ?? flowId;
                if (fprops.TryGetProperty("creator", out var cr))
                    creator = cr;
            }

            var targetPath = $"PowerAutomate/{env.Name}/{flowDisplayName}";
            var permUrl = env.Admin
                ? $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{env.Id}/flows/{flowId}/permissions?{ApiVersion}"
                : $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/{env.Id}/flows/{flowId}/permissions?{ApiVersion}";
            var permissions = await GetPermissionsAsync(permUrl, $"flow '{flowDisplayName}' in '{env.Name}'", context, ct);

            if (permissions != null)
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var perm in permissions)
                {
                    var entry = MapPermission(perm, targetPath, "Flow", flowId, "FlowPermission");
                    if (entry != null && seen.Add(DedupKey(entry))) yield return entry;
                }
            }
            else
            {
                // Without the sharing list the creator is the only known principal.
                var entry = MapFlowCreator(creator, targetPath, flowId);
                if (entry != null) yield return entry;
            }
        }
    }

    // ── PowerApps ────────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanPowerAppsAsync(
        EnvScan env, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var apps = await ListAsync(env, "PowerApps",
            $"https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{env.Id}/apps?{ApiVersion}&$expand=permissions",
            $"https://api.powerapps.com/providers/Microsoft.PowerApps/apps?{ApiVersion}&$filter=environment eq '{env.Id}'",
            context, ct);
        if (apps == null || apps.Count == 0) yield break;

        context.ReportProgress($"Scanning {apps.Count} PowerApps in '{env.Name}'...", 3);

        foreach (var app in apps)
        {
            ct.ThrowIfCancellationRequested();

            var appId = app.TryGetProperty("name", out var an) ? an.GetString() ?? "" : "";
            var appDisplayName = appId;
            JsonElement owner = default;
            if (app.TryGetProperty("properties", out var aprops))
            {
                if (aprops.TryGetProperty("displayName", out var adn))
                    appDisplayName = adn.GetString() ?? appId;
                if (aprops.TryGetProperty("owner", out var ow))
                    owner = ow;
            }

            var targetPath = $"PowerApps/{env.Name}/{appDisplayName}";
            var permUrl = env.Admin
                ? $"https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{env.Id}/apps/{appId}/permissions?{ApiVersion}"
                : $"https://api.powerapps.com/providers/Microsoft.PowerApps/apps/{appId}/permissions?{ApiVersion}";
            var permissions = await GetPermissionsAsync(permUrl, $"app '{appDisplayName}' in '{env.Name}'", context, ct);

            // The owner also appears in the permissions list as Owner; de-duplicate on (principal, role).
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var perm in permissions ?? new())
            {
                var entry = MapPermission(perm, targetPath, "PowerApp", appId, "AppPermission");
                if (entry != null && seen.Add(DedupKey(entry))) yield return entry;
            }

            var ownerEntry = MapAppOwner(owner, targetPath, appId);
            if (ownerEntry != null && seen.Add(DedupKey(ownerEntry))) yield return ownerEntry;
        }
    }

    // ── Connectors ───────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanConnectorsAsync(
        EnvScan env, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // Admin route as used by Get-AdminPowerAppConnector; custom connectors carry isCustomApi=true.
        var filter = $"$filter=environment eq '{env.Id}'";
        var apis = await ListAsync(env, "Connectors",
            $"https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{env.Id}/apis?{ApiVersion}&{filter}",
            $"https://api.powerapps.com/providers/Microsoft.PowerApps/apis?{ApiVersion}&{filter}",
            context, ct);
        if (apis == null) yield break;

        var connectors = apis.Where(IsCustomConnector).ToList();
        if (connectors.Count == 0) yield break;
        context.ReportProgress($"Scanning {connectors.Count} custom connectors in '{env.Name}'...", 4);

        foreach (var conn in connectors)
        {
            ct.ThrowIfCancellationRequested();

            var connId = conn.TryGetProperty("name", out var cn) ? cn.GetString() ?? "" : "";
            var connDisplayName = connId;
            if (!conn.TryGetProperty("properties", out var cprops)) continue;
            if (cprops.TryGetProperty("displayName", out var cdn))
                connDisplayName = cdn.GetString() ?? connId;

            if (!cprops.TryGetProperty("createdBy", out var creator)) continue;
            var creatorId = GetString(creator, "id");
            if (creatorId.Length == 0) continue;

            yield return new PermissionEntry
            {
                TargetPath = $"Connector/{env.Name}/{connDisplayName}",
                TargetType = "Connector",
                TargetId = connId,
                PrincipalEntraId = creatorId,
                PrincipalEntraUpn = FirstNonEmpty(GetString(creator, "userPrincipalName"), GetString(creator, "email")),
                PrincipalSysName = GetString(creator, "displayName"),
                PrincipalType = "User",
                PrincipalRole = "Owner",
                Through = "ConnectorCreator",
                AccessType = "Allow",
                Tenure = "Permanent"
            };
        }
    }

    // ── Mapping helpers ─────────────────────────────────────────

    internal const string EveryoneInOrganization = "Everyone in the organization";

    /// <summary>Map a flow/app permission object (properties.roleName + properties.principal) to an entry.</summary>
    internal static PermissionEntry? MapPermission(JsonElement perm, string targetPath, string targetType, string targetId, string through)
    {
        if (!perm.TryGetProperty("properties", out var pp) || !pp.TryGetProperty("principal", out var principal))
            return null;

        var roleName = GetString(pp, "roleName");
        var principalType = GetString(principal, "type");
        var principalId = GetString(principal, "id");
        var displayName = GetString(principal, "displayName");
        var email = GetString(principal, "email");

        // Sharing with the whole organization: the principal only carries the tenant id.
        if (principalType.Equals("Tenant", StringComparison.OrdinalIgnoreCase))
        {
            principalId = FirstNonEmpty(GetString(principal, "tenantId"), principalId);
            displayName = EveryoneInOrganization;
        }

        if (principalId.Length == 0 && email.Length == 0) return null;

        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = targetType,
            TargetId = targetId,
            PrincipalEntraUpn = email,
            PrincipalEntraId = principalId,
            PrincipalSysName = displayName,
            PrincipalType = MapPrincipalType(principalType),
            PrincipalRole = MapRole(roleName),
            Through = through,
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    /// <summary>Flow creator row, used only when the flow's permissions could not be read.</summary>
    internal static PermissionEntry? MapFlowCreator(JsonElement creator, string targetPath, string flowId)
    {
        if (creator.ValueKind != JsonValueKind.Object) return null;
        // objectId and userId are both the creator's Entra object id, not a UPN.
        var id = FirstNonEmpty(GetString(creator, "objectId"), GetString(creator, "userId"));
        if (id.Length == 0) return null;

        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = "Flow",
            TargetId = flowId,
            PrincipalEntraId = id,
            PrincipalType = "User",
            PrincipalRole = "Creator",
            Through = "FlowCreator",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    internal static PermissionEntry? MapAppOwner(JsonElement owner, string targetPath, string appId)
    {
        if (owner.ValueKind != JsonValueKind.Object) return null;
        var ownerId = GetString(owner, "id");
        var ownerUpn = GetString(owner, "email");
        if (ownerId.Length == 0 && ownerUpn.Length == 0) return null;

        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = "PowerApp",
            TargetId = appId,
            PrincipalEntraUpn = ownerUpn,
            PrincipalEntraId = ownerId,
            PrincipalSysName = FirstNonEmpty(GetString(owner, "displayName"), ownerUpn),
            PrincipalType = "User",
            PrincipalRole = "Owner",
            Through = "AppOwner",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    internal static bool IsCustomConnector(JsonElement api)
        => !(api.TryGetProperty("properties", out var p) && p.TryGetProperty("isCustomApi", out var c) && c.ValueKind == JsonValueKind.False);

    private static string DedupKey(PermissionEntry e)
        => $"{(e.PrincipalEntraId.Length > 0 ? e.PrincipalEntraId : e.PrincipalEntraUpn)}|{e.PrincipalRole}";

    internal static string MapPrincipalType(string? flowType) => flowType?.ToLowerInvariant() switch
    {
        "user" => "User",
        "group" => "SecurityGroup",
        "serviceprincipal" => "Application",
        "tenant" => "Everyone",
        _ => "Unknown"
    };

    private static string MapRole(string? roleName) => roleName?.ToLowerInvariant() switch
    {
        "canview" or "reader" => "CanView",
        "canedit" or "writer" => "CanEdit",
        "owner" => "Owner",
        "canviewwithshare" => "CanViewWithShare",
        "caneditwithshare" => "CanEditWithShare",
        _ => string.IsNullOrEmpty(roleName) ? "Unknown" : roleName
    };

    private static string GetString(JsonElement el, string name)
        => el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    private static string FirstNonEmpty(params string[] values) => values.FirstOrDefault(v => v.Length > 0) ?? "";
}
