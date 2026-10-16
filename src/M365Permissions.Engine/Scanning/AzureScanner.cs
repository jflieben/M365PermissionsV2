using System.Net;
using System.Net.Http.Headers;
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
    private const string ScheduleApi = "api-version=2020-10-01";

    private readonly DelegatedAuth _auth;
    private readonly ResilientHttpClient _arm;
    private readonly GraphClient _graph;

    public AzureScanner(DelegatedAuth auth)
    {
        _auth = auth;
        _arm = new ResilientHttpClient(auth);
        _graph = new GraphClient(auth, maxConcurrency: 2);
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
            context.ReportProgress("No Azure subscriptions visible to this account.", 2);
        else
            context.ReportProgress($"Found {subscriptions.Count} Azure subscription(s).", 3);

        context.SetTotalTargets(subscriptions.Count);

        // Role names by definition GUID: built-in GUIDs are shared, custom role GUIDs are unique.
        var roleCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var allEntries = new List<PermissionEntry>();
        var seenEligible = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pimUnlicensedLogged = false;

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

            // Role definitions per subscription: custom roles are scoped per subscription (B16).
            try
            {
                await LoadRoleDefinitionsAsync($"{Arm}{subScope}", roleCache, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.ReportProgress($"Could not load role definitions for '{subName}' ({ex.Message}); roles are resolved one by one.", 2);
            }

            var schedules = await LoadActiveSchedulesAsync($"{Arm}{subScope}", subName, context, ct);
            var describe = (string scope) => $"Azure/{subName}{FormatScope(scope, subId)}";

            foreach (var assignment in assignments)
            {
                var entry = await MapAssignmentAsync(assignment, describe, DetermineTargetType, schedules, roleCache, ct);
                if (entry != null) allEntries.Add(entry);
            }

            // PIM eligibility below this subscription (the list also returns inherited MG ones).
            var targetFailed = false;
            try
            {
                var eligible = await QueryArmValueAsync(
                    $"{Arm}{subScope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?{ScheduleApi}", ct);
                var added = 0;
                foreach (var e in eligible)
                {
                    if (!IsAtOrBelow(ScopeOf(e), subScope) || !seenEligible.Add(IdOf(e))) continue;
                    var entry = await MapEligibleAsync(e, describe, DetermineTargetType, roleCache, ct);
                    if (entry != null) { allEntries.Add(entry); added++; }
                }
                if (added > 0)
                    context.ReportProgress($"Found {added} PIM-eligible Azure assignment(s) in '{subName}'.", 4);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (IsPimUnlicensed(ex))
                {
                    if (!pimUnlicensedLogged)
                        context.ReportProgress("Azure PIM is not available (requires Microsoft Entra ID P2); no eligible assignments to report.", 3);
                    pimUnlicensedLogged = true;
                }
                else
                {
                    context.ReportProgress($"Azure PIM eligibility could not be read for '{subName}': {ex.Message}", 2);
                    targetFailed = true;
                }
            }

            if (targetFailed) context.FailTarget();
            else context.CompleteTarget();
            context.ReportProgress($"Found {assignments.Count} role assignments in '{subName}'.", 4);
        }

        // --- Management group and root role assignments (often where tenant-wide Owner lives) - A5 ---
        // atScope() on each group also returns its parents' assignments, so de-duplicate by assignment ID.
        List<(string Name, string DisplayName)> mgs;
        try
        {
            mgs = await GetManagementGroupsAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.MarkPartial($"Management groups could not be listed ({ex.Message}); assignments above subscriptions are missing.");
            mgs = new();
        }

        if (mgs.Count > 0)
        {
            context.ReportProgress($"Scanning {mgs.Count} management group(s)...", 3);
            context.SetTotalTargets(subscriptions.Count + mgs.Count);
        }
        var mgNames = mgs.ToDictionary(m => m.Name, m => string.IsNullOrEmpty(m.DisplayName) ? m.Name : m.DisplayName, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var describeMg = (string scope) => DescribeManagementScope(scope, mgNames);
        // Root ("/") stays ManagementGroup so the management-group risk policy covers it.
        var mgTargetType = (string _) => "ManagementGroup";

        foreach (var (mgName, mgDisplay) in mgs)
        {
            ct.ThrowIfCancellationRequested();
            var mgScope = $"{Arm}/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mgName)}";
            try
            {
                var schedules = await LoadActiveSchedulesAsync(mgScope, mgDisplay, context, ct, atScope: true);
                foreach (var a in await QueryArmValueAsync($"{mgScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", ct))
                {
                    if (!seen.Add(IdOf(a))) continue;
                    var entry = await MapAssignmentAsync(a, describeMg, mgTargetType, schedules, roleCache, ct);
                    if (entry != null) allEntries.Add(entry);
                }

                try
                {
                    foreach (var e in await QueryArmValueAsync($"{mgScope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?{ScheduleApi}&$filter=atScope()", ct))
                    {
                        // Subscription-level eligibility was collected above.
                        if (ScopeOf(e).StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase) || !seenEligible.Add(IdOf(e))) continue;
                        var entry = await MapEligibleAsync(e, describeMg, mgTargetType, roleCache, ct);
                        if (entry != null) allEntries.Add(entry);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException && IsPimUnlicensed(ex)) { }

                context.CompleteTarget();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.ReportProgress($"Management group '{mgDisplay}' could not be scanned: {ex.Message}", 2);
                context.FailTarget();
            }
        }

        if (allEntries.Count > 0)
            await ResolvePrincipalsAsync(allEntries, context, ct);

        foreach (var entry in allEntries)
            yield return entry;

        context.ReportProgress("Completed Azure RBAC scan.", 3);
    }

    private static string ScopeOf(JsonElement item)
        => item.TryGetProperty("properties", out var p) && p.TryGetProperty("scope", out var s) ? s.GetString() ?? "" : "";

    private static string IdOf(JsonElement item)
        => item.TryGetProperty("id", out var i) ? i.GetString() ?? Guid.NewGuid().ToString() : Guid.NewGuid().ToString();

    private static string Prop(JsonElement props, string name)
        => props.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    /// <summary>Last path segment of an ARM id (the GUID of a role assignment or definition).</summary>
    private static string LastSegment(string id) => id.TrimEnd('/').Split('/').LastOrDefault() ?? id;

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

    /// <summary>
    /// Active role assignment schedule instances at a scope, keyed by role assignment GUID. They carry
    /// assignmentType (Assigned/Activated) and endDateTime, which plain role assignments lack (A2).
    /// </summary>
    private async Task<Dictionary<string, JsonElement>> LoadActiveSchedulesAsync(
        string scopeUrl, string scopeName, ScanContext context, CancellationToken ct, bool atScope = false)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var url = $"{scopeUrl}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?{ScheduleApi}" + (atScope ? "&$filter=atScope()" : "");
            foreach (var i in await QueryArmValueAsync(url, ct))
            {
                if (!i.TryGetProperty("properties", out var p)) continue;
                // Group/Inherited instances describe the same assignment for other principals or scopes.
                if (Prop(p, "memberType") is { Length: > 0 } mt && !mt.Equals("Direct", StringComparison.OrdinalIgnoreCase)) continue;
                var origin = Prop(p, "originRoleAssignmentId");
                if (!string.IsNullOrEmpty(origin)) result.TryAdd(LastSegment(origin), p.Clone());
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (!IsPimUnlicensed(ex))
                context.ReportProgress($"Assignment schedules for '{scopeName}' could not be read ({ex.Message}); activated and time-bound assignments there are reported as Permanent.", 2);
        }
        return result;
    }

    private async Task<PermissionEntry?> MapAssignmentAsync(JsonElement assignment, Func<string, string> describe,
        Func<string, string> targetType, Dictionary<string, JsonElement> schedules,
        Dictionary<string, string> roleCache, CancellationToken ct)
    {
        if (!assignment.TryGetProperty("properties", out var props)) return null;
        var scope = ScopeOf(assignment);
        var guid = LastSegment(IdOf(assignment));

        var assignmentType = "";
        var start = "";
        var end = "";
        if (schedules.TryGetValue(guid, out var schedule))
        {
            assignmentType = Prop(schedule, "assignmentType");
            start = Prop(schedule, "startDateTime");
            end = Prop(schedule, "endDateTime");
        }

        // ABAC conditions narrow what the role allows; mark them so reviewers don't read it as unrestricted.
        var conditional = !string.IsNullOrWhiteSpace(Prop(props, "condition"));

        return new PermissionEntry
        {
            TargetPath = describe(scope),
            TargetType = targetType(scope),
            TargetId = scope,
            PrincipalEntraId = Prop(props, "principalId"),
            PrincipalType = MapPrincipalType(Prop(props, "principalType")),
            PrincipalRole = await ResolveRoleNameAsync(Prop(props, "roleDefinitionId"), roleCache, ct),
            Through = conditional ? "AzureRBAC (conditional)" : "AzureRBAC",
            AccessType = "Allow",
            Tenure = RoleTenure.Active(assignmentType, end),
            StartDateTime = start,
            EndDateTime = end
        };
    }

    private async Task<PermissionEntry?> MapEligibleAsync(JsonElement eligible, Func<string, string> describe,
        Func<string, string> targetType, Dictionary<string, string> roleCache, CancellationToken ct)
    {
        if (!eligible.TryGetProperty("properties", out var props)) return null;
        var scope = Prop(props, "scope");
        var end = Prop(props, "endDateTime");
        return new PermissionEntry
        {
            TargetPath = describe(scope),
            TargetType = targetType(scope),
            TargetId = scope,
            PrincipalEntraId = Prop(props, "principalId"),
            PrincipalType = MapPrincipalType(Prop(props, "principalType")),
            PrincipalRole = await ResolveRoleNameAsync(Prop(props, "roleDefinitionId"), roleCache, ct),
            Through = string.IsNullOrWhiteSpace(Prop(props, "condition")) ? "AzurePIM-Eligible" : "AzurePIM-Eligible (conditional)",
            AccessType = "Allow",
            Tenure = RoleTenure.Eligible(end),
            StartDateTime = Prop(props, "startDateTime"),
            EndDateTime = end
        };
    }

    /// <summary>ARM answers PIM schedule calls without an Entra ID P2 licence with a licensing error.</summary>
    private static bool IsPimUnlicensed(Exception ex)
        => ex.Message.Contains("license", StringComparison.OrdinalIgnoreCase)
           || ex.Message.Contains("AadPremium", StringComparison.OrdinalIgnoreCase);

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
    /// throttling and 5xx; throws (with ARM's error body) on any other failure so a partial list is
    /// never mistaken for a complete one.
    /// </summary>
    private async Task<List<JsonElement>> QueryArmValueAsync(string url, CancellationToken ct)
    {
        var results = new List<JsonElement>();
        string? next = url;
        while (!string.IsNullOrEmpty(next))
        {
            ct.ThrowIfCancellationRequested();
            var json = await GetArmJsonAsync(next, ct);
            if (json == null) break; // 404: nothing at this scope
            if (json.Value.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
                foreach (var v in val.EnumerateArray()) results.Add(v.Clone());
            next = json.Value.TryGetProperty("nextLink", out var nl) ? nl.GetString() : null;
        }
        return results;
    }

    private async Task<JsonElement?> GetArmJsonAsync(string url, CancellationToken ct)
    {
        using var resp = await _arm.SendAsync(async tok =>
        {
            var token = await _auth.GetAccessTokenAsync("azure", tok);
            var r = new HttpRequestMessage(HttpMethod.Get, url);
            r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return r;
        }, ct);

        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}: {(body.Length > 400 ? body[..400] + "..." : body)}", null, resp.StatusCode);
        }
        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        return doc.RootElement.Clone();
    }

    private async Task LoadRoleDefinitionsAsync(string scopeUrl, Dictionary<string, string> cache, CancellationToken ct)
    {
        foreach (var rd in await QueryArmValueAsync(
            $"{scopeUrl}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", ct))
        {
            var id = rd.TryGetProperty("id", out var rid) ? rid.GetString() ?? "" : "";
            var name = rd.TryGetProperty("properties", out var rdp) ? Prop(rdp, "roleName") : "";
            if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name))
                cache[LastSegment(id)] = name;
        }
    }

    /// <summary>Role name by definition GUID; on a miss (custom role defined elsewhere) GET the definition itself (A5).</summary>
    private async Task<string> ResolveRoleNameAsync(string roleDefinitionId, Dictionary<string, string> cache, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(roleDefinitionId)) return "";
        var guid = LastSegment(roleDefinitionId);
        if (cache.TryGetValue(guid, out var name)) return name;

        name = guid;
        try
        {
            var path = roleDefinitionId.StartsWith('/') ? roleDefinitionId : "/" + roleDefinitionId;
            var rd = await GetArmJsonAsync($"{Arm}{path}?api-version=2022-04-01", ct);
            if (rd is { } def && def.TryGetProperty("properties", out var p) && Prop(p, "roleName") is { Length: > 0 } roleName)
                name = roleName;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* keep the GUID */ }

        cache[guid] = name; // also caches failures, so each unknown role is fetched once
        return name;
    }

    private static string MapPrincipalType(string? azureType) => azureType switch
    {
        "User" => "User",
        "Group" => "SecurityGroup",
        "ServicePrincipal" => "Application",
        "ForeignGroup" => "External Group",
        "Device" => "Device",
        null or "" => "Unknown",
        _ => azureType
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
    /// Fill names and UPNs via Graph getByIds (A4). A principal that getByIds does not return no longer
    /// exists: the assignment is orphaned and is reported as such rather than as a bare GUID.
    /// </summary>
    private async Task ResolvePrincipalsAsync(List<PermissionEntry> entries, ScanContext context, CancellationToken ct)
    {
        var ids = entries.Select(e => e.PrincipalEntraId).Where(i => !string.IsNullOrEmpty(i)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        context.ReportProgress($"Resolving {ids.Count} principal(s) via Graph...", 3);

        Dictionary<string, JsonElement> found;
        try
        {
            found = await _graph.GetDirectoryObjectsByIdsAsync(ids, new[] { "user", "group", "servicePrincipal" }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Principal names could not be resolved via Graph ({ex.Message}); rows show object ids.", 2);
            foreach (var e in entries.Where(e => string.IsNullOrEmpty(e.PrincipalSysName)))
                e.PrincipalSysName = e.PrincipalEntraId;
            return;
        }

        var deleted = 0;
        foreach (var entry in entries)
        {
            if (string.IsNullOrEmpty(entry.PrincipalEntraId)) continue;
            if (!found.TryGetValue(entry.PrincipalEntraId, out var obj))
            {
                entry.PrincipalType = "Deleted principal";
                entry.PrincipalSysName = $"Deleted principal ({entry.PrincipalEntraId})";
                deleted++;
                continue;
            }

            var displayName = Prop(obj, "displayName");
            var upn = Prop(obj, "userPrincipalName");
            entry.PrincipalSysName = !string.IsNullOrEmpty(displayName) ? displayName : (string.IsNullOrEmpty(upn) ? entry.PrincipalEntraId : upn);
            if (!string.IsNullOrEmpty(upn)) entry.PrincipalEntraUpn = upn;
            if (entry.PrincipalType == "User" && EntraScanner.IsGuest(Prop(obj, "userType"), upn))
                entry.PrincipalType = "Guest";
        }
        if (deleted > 0)
            context.ReportProgress($"{deleted} Azure role assignment(s) belong to deleted principals.", 3);
    }
}
