using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Azure RBAC role assignments across subscriptions.
/// Uses the Azure Resource Manager REST API (management.azure.com).
/// </summary>
public sealed class AzureScanner : IScanProvider
{
    public string Category => "Azure";

    private const string Arm = "https://management.azure.com";

    private readonly DelegatedAuth _auth;
    private readonly HttpClient _http;
    private readonly ResilientHttpClient _arm;

    public AzureScanner(DelegatedAuth auth)
    {
        _auth = auth;
        _http = new HttpClient();
        _arm = new ResilientHttpClient(auth);
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Azure subscriptions...", 3);

        var subscriptions = new List<(string Id, string Name)>();
        try
        {
            foreach (var sub in await QueryArmValueAsync($"{Arm}/subscriptions?api-version=2022-12-01", ct))
            {
                var subId = sub.TryGetProperty("subscriptionId", out var sid) ? sid.GetString() ?? "" : "";
                var displayName = sub.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
                if (!string.IsNullOrEmpty(subId))
                    subscriptions.Add((subId, displayName));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ResourcePrincipalNotFoundException)
        {
            // Nothing below can run without this list: fail the category rather than report it complete.
            throw new InvalidOperationException(
                $"Cannot list Azure subscriptions ({ex.Message}). Ensure the account has Reader access to at least one subscription.", ex);
        }

        if (subscriptions.Count == 0)
            context.ReportProgress("No Azure subscriptions found (or no access).", 3);
        else
            context.ReportProgress($"Found {subscriptions.Count} Azure subscription(s).", 3);

        context.SetTotalTargets(subscriptions.Count);

        // Cache role definitions to avoid repeated lookups
        var roleCache = new Dictionary<string, string>();
        var allEntries = new List<PermissionEntry>();

        foreach (var (subId, subName) in subscriptions)
        {
            ct.ThrowIfCancellationRequested();
            context.ReportProgress($"Scanning subscription: {subName}...", 4);

            // No atScope() filter: that returns only assignments at the subscription and above, which drops
            // every resource group and resource assignment and repeats inherited management-group ones.
            // Everything above the subscription is collected once in the management-group pass below.
            var subScope = $"/subscriptions/{subId}";
            List<JsonElement> assignments;
            try
            {
                assignments = (await QueryArmValueAsync(
                        $"{Arm}{subScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", ct))
                    .Where(a => IsAtOrBelow(ScopeOf(a), subScope))
                    .ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.ReportProgress($"Error scanning subscription {subName}: {ex.Message}", 2);
                context.FailTarget();
                continue;
            }

            // Resolve role definitions for THIS subscription. Custom roles are scoped per
            // subscription (distinct GUIDs), so loading only once left custom roles in other
            // subscriptions rendered as raw GUIDs (B16). Built-in role GUIDs are shared, so
            // merging repeatedly into the cache is harmless.
            try
            {
                await LoadRoleDefinitionsAsync(subId, roleCache, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* continue with raw role IDs */ }

            foreach (var assignment in assignments)
            {
                if (!assignment.TryGetProperty("properties", out var props)) continue;

                var roleDefId = props.TryGetProperty("roleDefinitionId", out var rdi) ? rdi.GetString() ?? "" : "";
                var principalId = props.TryGetProperty("principalId", out var pid) ? pid.GetString() ?? "" : "";
                var principalType = props.TryGetProperty("principalType", out var pt) ? pt.GetString() ?? "" : "";
                var scope = ScopeOf(assignment);

                allEntries.Add(new PermissionEntry
                {
                    TargetPath = $"Azure/{subName}{FormatScope(scope, subId)}",
                    TargetType = DetermineTargetType(scope),
                    TargetId = scope,
                    PrincipalEntraId = principalId,
                    PrincipalType = MapPrincipalType(principalType),
                    PrincipalRole = ResolveRoleName(roleDefId, roleCache),
                    Through = "AzureRBAC",
                    AccessType = "Allow",
                    Tenure = "Permanent"
                });
            }

            context.CompleteTarget();
            context.ReportProgress($"Found {assignments.Count} role assignments in '{subName}'.", 4);
        }

        // --- Management group and root role assignments (often where tenant-wide Owner lives) - A5 ---
        // atScope() on each group also returns its parents' assignments, so de-duplicate by assignment ID.
        try
        {
            var mgs = await GetManagementGroupsAsync(ct);
            if (mgs.Count > 0)
                context.ReportProgress($"Scanning {mgs.Count} management group(s)...", 3);
            var mgNames = mgs.ToDictionary(m => m.Name, m => string.IsNullOrEmpty(m.DisplayName) ? m.Name : m.DisplayName, StringComparer.OrdinalIgnoreCase);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (mgName, _) in mgs)
            {
                ct.ThrowIfCancellationRequested();
                var url = $"{Arm}/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mgName)}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()";
                foreach (var a in await QueryArmValueAsync(url, ct))
                {
                    var assignmentId = a.TryGetProperty("id", out var aid) ? aid.GetString() ?? "" : "";
                    if (!string.IsNullOrEmpty(assignmentId) && !seen.Add(assignmentId)) continue;
                    if (!a.TryGetProperty("properties", out var props)) continue;

                    var roleDefId = props.TryGetProperty("roleDefinitionId", out var rdi) ? rdi.GetString() ?? "" : "";
                    var principalId = props.TryGetProperty("principalId", out var pid) ? pid.GetString() ?? "" : "";
                    var principalType = props.TryGetProperty("principalType", out var pt) ? pt.GetString() ?? "" : "";
                    var scope = ScopeOf(a);

                    allEntries.Add(new PermissionEntry
                    {
                        TargetPath = DescribeManagementScope(scope, mgNames),
                        // Root ("/") stays ManagementGroup so the management-group risk policy covers it.
                        TargetType = "ManagementGroup",
                        TargetId = scope,
                        PrincipalEntraId = principalId,
                        PrincipalType = MapPrincipalType(principalType),
                        PrincipalRole = ResolveRoleName(roleDefId, roleCache),
                        Through = "AzureRBAC",
                        AccessType = "Allow",
                        Tenure = "Permanent"
                    });
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { context.ReportProgress($"Management group scan skipped: {ex.Message}", 3); }

        // --- Azure PIM eligible role assignments (per subscription) - A5 ---
        foreach (var (subId, subName) in subscriptions)
        {
            ct.ThrowIfCancellationRequested();
            List<JsonElement> eligible;
            try
            {
                eligible = await QueryArmValueAsync(
                    $"{Arm}/subscriptions/{subId}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01", ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.ReportProgress($"Azure PIM scan skipped for '{subName}': {ex.Message}", 3);
                continue;
            }

            foreach (var e in eligible)
            {
                if (!e.TryGetProperty("properties", out var props)) continue;
                var roleDefId = props.TryGetProperty("roleDefinitionId", out var rdi) ? rdi.GetString() ?? "" : "";
                var principalId = props.TryGetProperty("principalId", out var pid) ? pid.GetString() ?? "" : "";
                var principalType = props.TryGetProperty("principalType", out var pt) ? pt.GetString() ?? "" : "";
                var scope = props.TryGetProperty("scope", out var scp) ? scp.GetString() ?? "" : "";
                var endTime = props.TryGetProperty("endDateTime", out var et) && et.ValueKind == JsonValueKind.String ? et.GetString() ?? "" : "";
                allEntries.Add(new PermissionEntry
                {
                    TargetPath = $"Azure/{subName}{FormatScope(scope, subId)}",
                    TargetType = DetermineTargetType(scope),
                    TargetId = scope,
                    PrincipalEntraId = principalId,
                    PrincipalType = MapPrincipalType(principalType),
                    PrincipalRole = ResolveRoleName(roleDefId, roleCache),
                    Through = "AzurePIM-Eligible",
                    AccessType = "Allow",
                    Tenure = string.IsNullOrEmpty(endTime) ? "Eligible-Permanent" : $"Eligible (until {endTime})"
                });
            }
            if (eligible.Count > 0)
                context.ReportProgress($"Found {eligible.Count} PIM-eligible Azure assignment(s) in '{subName}'.", 4);
        }

        // Resolve principal display names via Graph API
        if (allEntries.Count > 0)
        {
            context.ReportProgress($"Resolving {allEntries.Count} principal display names via Graph...", 3);
            var principalIds = allEntries
                .Where(e => !string.IsNullOrEmpty(e.PrincipalEntraId))
                .Select(e => e.PrincipalEntraId!)
                .Distinct()
                .ToList();
            var nameCache = await ResolvePrincipalNamesAsync(principalIds, ct);
            foreach (var entry in allEntries)
            {
                if (!string.IsNullOrEmpty(entry.PrincipalEntraId) &&
                    nameCache.TryGetValue(entry.PrincipalEntraId, out var displayName))
                {
                    entry.PrincipalSysName = displayName;
                }
                else if (string.IsNullOrEmpty(entry.PrincipalSysName))
                {
                    entry.PrincipalSysName = entry.PrincipalEntraId ?? "";
                }
            }
        }

        foreach (var entry in allEntries)
            yield return entry;

        context.ReportProgress("Completed Azure RBAC scan.", 3);
    }

    private static string ScopeOf(JsonElement assignment)
        => assignment.TryGetProperty("properties", out var p) && p.TryGetProperty("scope", out var s) ? s.GetString() ?? "" : "";

    /// <summary>True when <paramref name="scope"/> is <paramref name="parentScope"/> or a scope beneath it.</summary>
    public static bool IsAtOrBelow(string scope, string parentScope)
        => scope.Equals(parentScope, StringComparison.OrdinalIgnoreCase)
           || scope.StartsWith(parentScope.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase);

    private static string DescribeManagementScope(string scope, Dictionary<string, string> mgNames)
    {
        if (scope == "/") return "Azure/Root (/)";
        var name = scope.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? scope;
        return $"Azure/ManagementGroup/{(mgNames.TryGetValue(name, out var display) ? display : name)}";
    }

    /// <summary>Enumerate management groups the user can see (A5).</summary>
    private async Task<List<(string Name, string DisplayName)>> GetManagementGroupsAsync(CancellationToken ct)
    {
        var result = new List<(string, string)>();
        foreach (var mg in await QueryArmValueAsync($"{Arm}/providers/Microsoft.Management/managementGroups?api-version=2020-05-01", ct))
        {
            var name = mg.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var disp = mg.TryGetProperty("properties", out var p) && p.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
            if (!string.IsNullOrEmpty(name)) result.Add((name, disp));
        }
        return result;
    }

    /// <summary>
    /// GET an ARM collection endpoint, following nextLink, returning the "value" array items. Retries
    /// throttling and 5xx; throws on any other failure so a partial list is never mistaken for a complete one.
    /// </summary>
    private async Task<List<JsonElement>> QueryArmValueAsync(string url, CancellationToken ct)
    {
        var results = new List<JsonElement>();
        string? next = url;
        while (!string.IsNullOrEmpty(next))
        {
            ct.ThrowIfCancellationRequested();
            var json = await _arm.GetJsonAsync(next, "azure", ct);
            if (json == null) break; // 404: nothing at this scope
            if (json.Value.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                foreach (var v in val.EnumerateArray()) results.Add(v.Clone());
            next = json.Value.TryGetProperty("nextLink", out var nl) ? nl.GetString() : null;
        }
        return results;
    }

    private async Task LoadRoleDefinitionsAsync(string subscriptionId, Dictionary<string, string> cache, CancellationToken ct)
    {
        foreach (var rd in await QueryArmValueAsync(
            $"{Arm}/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", ct))
        {
            var id = rd.TryGetProperty("id", out var rid) ? rid.GetString() ?? "" : "";
            var name = "";
            if (rd.TryGetProperty("properties", out var rdp) && rdp.TryGetProperty("roleName", out var rn))
                name = rn.GetString() ?? "";
            if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name))
                cache[id] = name;
        }
    }

    private static string ResolveRoleName(string roleDefinitionId, Dictionary<string, string> cache)
    {
        if (cache.TryGetValue(roleDefinitionId, out var name))
            return name;

        // Extract the role definition GUID from the full resource ID
        var parts = roleDefinitionId.Split('/');
        var guid = parts.Length > 0 ? parts[^1] : roleDefinitionId;

        // Check by GUID suffix too
        foreach (var (key, val) in cache)
        {
            if (key.EndsWith(guid, StringComparison.OrdinalIgnoreCase))
                return val;
        }

        return guid; // Return GUID if we can't resolve
    }

    private static string MapPrincipalType(string? azureType) => azureType switch
    {
        "User" => "User",
        "Group" => "SecurityGroup",
        "ServicePrincipal" => "Application",
        "ForeignGroup" => "External Group",
        "Device" => "Device",
        _ => azureType ?? "Unknown"
    };

    private static string DetermineTargetType(string scope)
    {
        if (string.IsNullOrEmpty(scope)) return "Unknown";
        if (scope.Contains("/resourceGroups/", StringComparison.OrdinalIgnoreCase))
        {
            if (scope.Contains("/providers/", StringComparison.OrdinalIgnoreCase))
                return "Resource";
            return "ResourceGroup";
        }
        if (scope.Contains("/managementGroups/", StringComparison.OrdinalIgnoreCase))
            return "ManagementGroup";
        return "Subscription";
    }

    private static string FormatScope(string scope, string subscriptionId)
    {
        // Strip the leading /subscriptions/{id} to make it shorter
        var prefix = $"/subscriptions/{subscriptionId}";
        if (scope.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            var remainder = scope[prefix.Length..];
            return string.IsNullOrEmpty(remainder) ? "" : remainder;
        }
        return scope;
    }

    /// <summary>
    /// Resolve principal GUIDs to display names via Graph /directoryObjects/getByIds (up to 1000 per call).
    /// </summary>
    private async Task<Dictionary<string, string>> ResolvePrincipalNamesAsync(
        List<string> principalIds, CancellationToken ct)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (principalIds.Count == 0) return result;

        string token;
        try
        {
            token = await _auth.GetAccessTokenAsync("graph", ct);
        }
        catch
        {
            return result; // Can't resolve without Graph token — fall back to GUIDs
        }

        // Process in chunks of 1000 (Graph API limit for getByIds)
        for (int i = 0; i < principalIds.Count; i += 1000)
        {
            ct.ThrowIfCancellationRequested();
            var chunk = principalIds.Skip(i).Take(1000).ToList();

            try
            {
                var body = JsonSerializer.Serialize(new
                {
                    ids = chunk,
                    types = new[] { "user", "group", "servicePrincipal" }
                });

                using var req = new HttpRequestMessage(HttpMethod.Post,
                    "https://graph.microsoft.com/v1.0/directoryObjects/getByIds");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Content = new StringContent(body, Encoding.UTF8, "application/json");

                var resp = await _http.SendAsync(req, ct);
                if (!resp.IsSuccessStatusCode) continue;

                var doc = await JsonDocument.ParseAsync(
                    await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                if (doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                {
                    foreach (var obj in val.EnumerateArray())
                    {
                        var id = obj.TryGetProperty("id", out var oid) ? oid.GetString() ?? "" : "";
                        var displayName = obj.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
                        var upn = obj.TryGetProperty("userPrincipalName", out var u) ? u.GetString() ?? "" : "";

                        if (!string.IsNullOrEmpty(id))
                        {
                            // Prefer "displayName (UPN)" for users, just displayName for groups/SPs
                            var name = !string.IsNullOrEmpty(upn) && !string.IsNullOrEmpty(displayName)
                                ? $"{displayName} ({upn})"
                                : !string.IsNullOrEmpty(displayName) ? displayName
                                : upn;
                            if (!string.IsNullOrEmpty(name))
                                result[id] = name;
                        }
                    }
                }
            }
            catch { /* continue with remaining chunks */ }
        }

        return result;
    }
}
