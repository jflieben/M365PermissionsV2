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

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Power Platform environments...", 3);

        // Discover environments via BAP API (audience = service.powerapps.com per MS module)
        var environments = new List<(string Id, string Name)>();
        try
        {
            // Try admin endpoint first for all tenant environments
            var (envList, status) = await GetAllAsync(
                "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2016-11-01", ct);
            if (envList == null)
            {
                context.ReportProgress($"BAP admin environments API returned HTTP {status}, falling back to user environments...", 4);
                (envList, status) = await GetAllAsync(
                    "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments?api-version=2016-11-01", ct);
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

            // ── Flows ──────────────────────────────────────────
            await foreach (var entry in ScanFlowsAsync(envId, envName, context, ct))
                yield return entry;

            // ── PowerApps ──────────────────────────────────────
            await foreach (var entry in ScanPowerAppsAsync(envId, envName, context, ct))
                yield return entry;

            // ── Connectors ─────────────────────────────────────
            await foreach (var entry in ScanConnectorsAsync(envId, envName, context, ct))
                yield return entry;

            context.CompleteTarget();
        }

        context.ReportProgress("Completed Power Platform scan.", 3);
    }

    // ── Flows ────────────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanFlowsAsync(
        string envId, string envName, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var flows = new List<JsonElement>();
        try
        {
            // Try admin API first for all flows in the environment
            var (list, status) = await GetAllAsync(
                $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{envId}/v2/flows?api-version=2016-11-01&$select=permissions", ct);
            if (list == null)
            {
                context.ReportProgress($"Flow admin API returned HTTP {status} for {envName}, trying user API fallback...", 4);
                // Fallback: get user's own flows
                (list, status) = await GetAllAsync(
                    $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/{envId}/flows?api-version=2016-11-01&$top=250&$select=permissions", ct);
                if (list == null)
                    context.ReportProgress($"Flow user API also returned HTTP {status} for {envName}. Check permissions.", 2);
            }
            if (list != null) flows.AddRange(list);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Error enumerating flows in {envName}: {ex.Message}", 2);
            yield break;
        }

        context.ReportProgress($"Scanning {flows.Count} flows in '{envName}'...", 3);

        if (flows.Count == 0)
        {
            context.ReportProgress($"No flows found in '{envName}'. This may be expected if no flows exist or permissions are insufficient.", 4);
        }

        foreach (var flow in flows)
        {
            ct.ThrowIfCancellationRequested();

            var flowId = flow.TryGetProperty("name", out var fn) ? fn.GetString() ?? "" : "";
            var flowDisplayName = "";
            if (flow.TryGetProperty("properties", out var fprops))
            {
                if (fprops.TryGetProperty("displayName", out var fdn))
                    flowDisplayName = fdn.GetString() ?? flowId;

                // Extract creator/owner from properties
                if (fprops.TryGetProperty("creator", out var creator))
                {
                    var ownerId = creator.TryGetProperty("objectId", out var oid) ? oid.GetString() ?? "" : "";
                    var ownerUpn = creator.TryGetProperty("userId", out var uid) ? uid.GetString() ?? "" : "";

                    if (!string.IsNullOrEmpty(ownerId) || !string.IsNullOrEmpty(ownerUpn))
                    {
                        yield return new PermissionEntry
                        {
                            TargetPath = $"PowerAutomate/{envName}/{flowDisplayName}",
                            TargetType = "Flow",
                            TargetId = flowId,
                            PrincipalEntraUpn = ownerUpn,
                            PrincipalEntraId = ownerId,
                            PrincipalSysName = ownerUpn,
                            PrincipalType = "User",
                            PrincipalRole = "Owner",
                            Through = "FlowCreator",
                            AccessType = "Allow",
                            Tenure = "Permanent"
                        };
                    }
                }
            }

            // Get flow permissions (sharing)
            await foreach (var entry in GetFlowPermissionsAsync(envId, flowId, flowDisplayName, envName, ct))
                yield return entry;
        }
    }

    private async IAsyncEnumerable<PermissionEntry> GetFlowPermissionsAsync(
        string envId, string flowId, string flowDisplayName, string envName,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        List<JsonElement>? permissions;
        try
        {
            (permissions, _) = await GetAllAsync(
                $"https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{envId}/flows/{flowId}/permissions?api-version=2016-11-01", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            yield break;
        }

        foreach (var perm in permissions ?? new())
        {
            var permType = perm.TryGetProperty("properties", out var pp)
                ? (pp.TryGetProperty("roleName", out var rn) ? rn.GetString() ?? "" : "")
                : "";

            JsonElement principal = default;
            if (pp.ValueKind != JsonValueKind.Undefined && pp.TryGetProperty("principal", out var pr))
                principal = pr;

            if (principal.ValueKind == JsonValueKind.Undefined) continue;

            var principalId = principal.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
            var principalType = principal.TryGetProperty("type", out var pt) ? pt.GetString() ?? "" : "";
            var displayName = principal.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
            var email = principal.TryGetProperty("email", out var em) ? em.GetString() ?? "" : "";

            if (string.IsNullOrEmpty(principalId) && string.IsNullOrEmpty(email)) continue;

            yield return new PermissionEntry
            {
                TargetPath = $"PowerAutomate/{envName}/{flowDisplayName}",
                TargetType = "Flow",
                TargetId = flowId,
                PrincipalEntraUpn = email,
                PrincipalEntraId = principalId,
                PrincipalSysName = displayName,
                PrincipalType = MapPrincipalType(principalType),
                PrincipalRole = MapRole(permType),
                Through = "FlowPermission",
                AccessType = "Allow",
                Tenure = "Permanent"
            };
        }
    }

    // ── PowerApps ────────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanPowerAppsAsync(
        string envId, string envName, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        List<JsonElement> apps = new();
        try
        {
            // Try admin API first (with permissions expanded, matching V1)
            var (list, status) = await GetAllAsync(
                $"https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{envId}/apps?api-version=2016-11-01&$expand=permissions", ct);
            if (list == null)
            {
                context.ReportProgress($"PowerApps admin API returned HTTP {status} for {envName}, trying user API fallback...", 4);
                // Fallback: user's own apps
                (list, status) = await GetAllAsync(
                    $"https://api.powerapps.com/providers/Microsoft.PowerApps/apps?api-version=2016-11-01&$filter=environment eq '{envId}'", ct);
                if (list == null)
                    context.ReportProgress($"PowerApps user API also returned HTTP {status} for {envName}. Check permissions.", 2);
            }
            if (list != null) apps.AddRange(list);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"PowerApps scan skipped for {envName}: {ex.Message}", 3);
            yield break;
        }

        if (apps.Count == 0) yield break;
        context.ReportProgress($"Scanning {apps.Count} PowerApps in '{envName}'...", 3);

        foreach (var app in apps)
        {
            ct.ThrowIfCancellationRequested();

            var appId = app.TryGetProperty("name", out var an) ? an.GetString() ?? "" : "";
            var appDisplayName = "";
            if (app.TryGetProperty("properties", out var aprops))
            {
                if (aprops.TryGetProperty("displayName", out var adn))
                    appDisplayName = adn.GetString() ?? appId;

                // Creator
                if (aprops.TryGetProperty("owner", out var owner))
                {
                    var ownerId = owner.TryGetProperty("id", out var oid) ? oid.GetString() ?? "" : "";
                    var ownerUpn = owner.TryGetProperty("email", out var oemail) ? oemail.GetString() ?? "" : "";
                    var ownerName = owner.TryGetProperty("displayName", out var odn) ? odn.GetString() ?? "" : "";

                    if (!string.IsNullOrEmpty(ownerId) || !string.IsNullOrEmpty(ownerUpn))
                    {
                        yield return new PermissionEntry
                        {
                            TargetPath = $"PowerApps/{envName}/{appDisplayName}",
                            TargetType = "PowerApp",
                            TargetId = appId,
                            PrincipalEntraUpn = ownerUpn,
                            PrincipalEntraId = ownerId,
                            PrincipalSysName = ownerName.Length > 0 ? ownerName : ownerUpn,
                            PrincipalType = "User",
                            PrincipalRole = "Owner",
                            Through = "AppOwner",
                            AccessType = "Allow",
                            Tenure = "Permanent"
                        };
                    }
                }
            }

            // Get app permissions (role assignments)
            await foreach (var entry in GetAppPermissionsAsync(envId, appId, appDisplayName, envName, ct))
                yield return entry;
        }
    }

    private async IAsyncEnumerable<PermissionEntry> GetAppPermissionsAsync(
        string envId, string appId, string appDisplayName, string envName,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        List<JsonElement>? permissions;
        try
        {
            (permissions, _) = await GetAllAsync(
                $"https://api.powerapps.com/providers/Microsoft.PowerApps/apps/{appId}/permissions?api-version=2016-11-01", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            yield break;
        }

        foreach (var perm in permissions ?? new())
        {
            var pp = perm.TryGetProperty("properties", out var props) ? props : default;
            if (pp.ValueKind == JsonValueKind.Undefined) continue;

            var roleName = pp.TryGetProperty("roleName", out var rn) ? rn.GetString() ?? "" : "";

            JsonElement principal = default;
            if (pp.TryGetProperty("principal", out var pr))
                principal = pr;

            if (principal.ValueKind == JsonValueKind.Undefined) continue;

            var principalId = principal.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
            var principalType = principal.TryGetProperty("type", out var pt) ? pt.GetString() ?? "" : "";
            var displayName = principal.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
            var email = principal.TryGetProperty("email", out var em) ? em.GetString() ?? "" : "";

            if (string.IsNullOrEmpty(principalId) && string.IsNullOrEmpty(email)) continue;

            yield return new PermissionEntry
            {
                TargetPath = $"PowerApps/{envName}/{appDisplayName}",
                TargetType = "PowerApp",
                TargetId = appId,
                PrincipalEntraUpn = email,
                PrincipalEntraId = principalId,
                PrincipalSysName = displayName,
                PrincipalType = MapPrincipalType(principalType),
                PrincipalRole = MapRole(roleName),
                Through = "AppPermission",
                AccessType = "Allow",
                Tenure = "Permanent"
            };
        }
    }

    // ── Connectors ───────────────────────────────────────────────

    private async IAsyncEnumerable<PermissionEntry> ScanConnectorsAsync(
        string envId, string envName, ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        List<JsonElement>? connectors;
        try
        {
            (connectors, _) = await GetAllAsync(
                $"https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{envId}/connectors?api-version=2016-11-01", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            yield break;
        }

        if (connectors == null || connectors.Count == 0) yield break;
        context.ReportProgress($"Scanning {connectors.Count} custom connectors in '{envName}'...", 4);

        foreach (var conn in connectors)
        {
            ct.ThrowIfCancellationRequested();

            var connId = conn.TryGetProperty("name", out var cn) ? cn.GetString() ?? "" : "";
            var connDisplayName = "";
            if (conn.TryGetProperty("properties", out var cprops))
            {
                if (cprops.TryGetProperty("displayName", out var cdn))
                    connDisplayName = cdn.GetString() ?? connId;

                // Creator
                if (cprops.TryGetProperty("createdBy", out var creator))
                {
                    var creatorId = creator.TryGetProperty("id", out var cid) ? cid.GetString() ?? "" : "";
                    var creatorName = creator.TryGetProperty("displayName", out var cdf) ? cdf.GetString() ?? "" : "";

                    if (!string.IsNullOrEmpty(creatorId))
                    {
                        yield return new PermissionEntry
                        {
                            TargetPath = $"Connector/{envName}/{connDisplayName}",
                            TargetType = "Connector",
                            TargetId = connId,
                            PrincipalEntraId = creatorId,
                            PrincipalSysName = creatorName,
                            PrincipalType = "User",
                            PrincipalRole = "Owner",
                            Through = "ConnectorCreator",
                            AccessType = "Allow",
                            Tenure = "Permanent"
                        };
                    }
                }
            }
        }
    }

    private static string MapPrincipalType(string? flowType) => flowType?.ToLower() switch
    {
        "user" => "User",
        "group" => "SecurityGroup",
        "serviceprincipal" => "Application",
        "tenant" => "Tenant",
        _ => "User"
    };

    private static string MapRole(string? roleName) => roleName?.ToLower() switch
    {
        "canview" or "reader" => "CanView",
        "canedit" or "writer" => "CanEdit",
        "owner" => "Owner",
        "canviewwithshare" => "CanViewWithShare",
        "caneditwithshare" => "CanEditWithShare",
        _ => roleName ?? "Unknown"
    };
}
