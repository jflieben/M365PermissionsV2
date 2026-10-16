using System.Net;
using System.Text.Json;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Entra ID (Azure AD) for permissions: users, groups, roles, service principals, app registrations.
/// Replaces V1's get-AllEntraPermissions.ps1.
/// </summary>
public sealed class EntraScanner : IScanProvider
{
    public string Category => "Entra";

    private readonly GraphClient _graphClient;

    private const int ExpandCap = 20;
    private const string OwnerSelect = "$select=id,displayName,userPrincipalName,userType";
    private const string MemberSelect = "$select=id,displayName,userPrincipalName,userType";

    public EntraScanner(GraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    /// <summary>A permission resource (API) with its app roles and delegated scopes, resolved separately (N8).</summary>
    private sealed class ResourceApi
    {
        public string Name = "";
        public readonly Dictionary<string, string> AppRoles = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> Scopes = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ServicePrincipalCache
    {
        public readonly Dictionary<string, ResourceApi> ByAppId = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, ResourceApi> ByObjectId = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> ObjectIdByAppId = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> AppIdByObjectId = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> NameByObjectId = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<JsonElement> WithOwners = new();
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // Phases: role assignments, app registrations, service principals, PIM eligibility, OAuth2 grants (+ groups later).
        const int phases = 5;
        context.SetTotalTargets(phases);

        context.ReportProgress("Loading Entra role definitions...", 3);
        var roleDefs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        await foreach (var rd in _graphClient.GetPaginatedAsync("roleManagement/directory/roleDefinitions?$select=id,displayName,templateId", ct: ct))
        {
            var name = Str(rd, "displayName");
            if (Str(rd, "id") is { Length: > 0 } id) roleDefs[id] = name;
            if (Str(rd, "templateId") is { Length: > 0 } tid) roleDefs.TryAdd(tid, name);
        }

        // Permission GUID to name lookups (A1), names for app-scoped role assignments and OAuth2 grants, SP owners.
        context.ReportProgress("Resolving application permission definitions...", 3);
        var sps = await BuildServicePrincipalCacheAsync(context, ct);

        context.ReportProgress("Enumerating app registrations...", 3);
        var (apps, appOwnersExpanded) = await CollectWithFallbackAsync(
            $"applications?$select=id,displayName,appId,requiredResourceAccess&$expand=owners({OwnerSelect})",
            "applications?$select=id,displayName,appId,requiredResourceAccess", ct);
        if (!appOwnersExpanded)
            context.MarkPartial("App registration owners could not be expanded; app owners are missing.");

        // Readable names for role assignment scopes: administrative units and app-scoped assignments.
        var scopeNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (spId, spName) in sps.NameByObjectId) scopeNames[$"/{spId}"] = $"app {spName}";
        foreach (var app in apps)
            if (Str(app, "id") is { Length: > 0 } appObjId) scopeNames[$"/{appObjId}"] = $"app {Str(app, "displayName")}";
        try
        {
            await foreach (var au in _graphClient.GetPaginatedAsync("directory/administrativeUnits?$select=id,displayName", ct: ct))
                if (Str(au, "id") is { Length: > 0 } auId) scopeNames[$"/administrativeUnits/{auId}"] = $"AU {Str(au, "displayName")}";
        }
        catch (HttpRequestException ex)
        {
            context.ReportProgress($"Administrative unit names unavailable ({ex.Message}); scoped roles show the AU id.", 4);
        }

        var groupMembers = new Dictionary<string, List<JsonElement>?>(StringComparer.OrdinalIgnoreCase);

        // --- Active directory role assignments (N1, N2, N3) ---
        context.ReportProgress("Scanning Entra role assignments...", 3);
        foreach (var e in await ScanActiveRoleAssignmentsAsync(context, roleDefs, scopeNames, groupMembers, ct))
            yield return e;
        context.CompleteTarget();

        // --- App registrations: REQUESTED permissions (requiredResourceAccess) and owners ---
        context.ReportProgress("Scanning app registrations...", 3);
        foreach (var app in apps)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var e in MapRequestedPermissions(app, sps)) yield return e;

            var appObjId = Str(app, "id");
            var target = new OwnedObject($"AppRegistration/{Str(app, "displayName")}", "Application", appObjId, "ApplicationOwner");
            foreach (var e in await ReadOwnersAsync(app, appOwnersExpanded, $"applications/{appObjId}/owners?{OwnerSelect}", target, context, ct))
                yield return e;
        }
        context.ReportProgress($"Scanned {apps.Count} app registrations.", 3);
        context.CompleteTarget();

        // --- Service principals: owners and GRANTED application permissions (appRoleAssignments) ---
        context.ReportProgress("Scanning enterprise app owners and granted application permissions...", 3);
        foreach (var sp in sps.WithOwners)
        {
            var spId = Str(sp, "id");
            var target = new OwnedObject($"EnterpriseApp/{Str(sp, "displayName")}", "ServicePrincipal", spId, "ServicePrincipalOwner");
            foreach (var e in await ReadOwnersAsync(sp, true, $"servicePrincipals/{spId}/owners?{OwnerSelect}", target, context, ct))
                yield return e;
        }

        int grantedPermCount = 0;
        await foreach (var sp in _graphClient.GetPaginatedAsync(
            "servicePrincipals?$select=id,appId,displayName&$expand=appRoleAssignments", ct: ct))
        {
            ct.ThrowIfCancellationRequested();

            var spName = Str(sp, "displayName");
            var spAppId = Str(sp, "appId");
            var spId = Str(sp, "id");

            if (!sp.TryGetProperty("appRoleAssignments", out var aras) || aras.ValueKind != JsonValueKind.Array)
                continue;

            // Graph caps an expanded directory relationship at 20 items without a nextLink, and the apps
            // with many grants are the ones that matter most. Re-read those in full.
            IEnumerable<JsonElement> assignments = aras.EnumerateArray().ToList();
            if (aras.GetArrayLength() >= ExpandCap && !string.IsNullOrEmpty(spId))
            {
                var all = new List<JsonElement>();
                await foreach (var a in _graphClient.GetPaginatedAsync($"servicePrincipals/{spId}/appRoleAssignments", ct: ct))
                    all.Add(a);
                assignments = all;
            }

            foreach (var ara in assignments)
            {
                var appRoleId = Str(ara, "appRoleId");
                var resourceId = Str(ara, "resourceId");
                var resourceName = Str(ara, "resourceDisplayName");

                // The all-zero GUID is the "default access" role (no specific app role): skip it.
                if (string.IsNullOrEmpty(appRoleId) || appRoleId == "00000000-0000-0000-0000-000000000000")
                    continue;

                var permName = sps.ByObjectId.TryGetValue(resourceId, out var api)
                    && api.AppRoles.TryGetValue(appRoleId, out var pn) ? pn : appRoleId;

                grantedPermCount++;
                yield return new PermissionEntry
                {
                    TargetPath = string.IsNullOrEmpty(resourceName) ? $"EnterpriseApp/{spName}" : $"EnterpriseApp/{spName} → {resourceName}",
                    TargetType = "ServicePrincipal",
                    TargetId = spId,
                    PrincipalEntraId = spId,
                    PrincipalSysId = spAppId,
                    PrincipalSysName = spName,
                    PrincipalType = "Application",
                    PrincipalRole = permName,
                    Through = "ApplicationPermission",
                    AccessType = "Allow",
                    Tenure = "Granted"
                };
            }
        }
        context.ReportProgress($"Found {grantedPermCount} granted application permissions.", 3);
        context.CompleteTarget();

        // Groups are listed up front: PIM for Groups needs the role-assignable ones.
        context.ReportProgress("Enumerating groups...", 3);
        var groups = new List<JsonElement>();
        await foreach (var group in _graphClient.GetPaginatedAsync(
            "groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled,isAssignableToRole", ct: ct))
        {
            groups.Add(group);
        }

        // --- PIM: eligible directory roles and eligible group memberships ---
        context.ReportProgress("Checking PIM (Privileged Identity Management) eligible assignments...", 3);
        foreach (var e in await ScanEligibleRolesAsync(context, roleDefs, scopeNames, groupMembers, ct))
            yield return e;
        foreach (var e in await ScanEligibleGroupMembershipsAsync(context, groups, ct))
            yield return e;
        context.CompleteTarget();

        // --- OAuth2 permission grants (delegated consent) ---
        context.ReportProgress("Scanning OAuth2 permission grants...", 3);
        foreach (var e in await ScanOAuth2GrantsAsync(context, sps, ct))
            yield return e;
        context.CompleteTarget();

        // Graph webhook subscriptions are not scanned: with delegated auth Graph lists only the calling
        // app's own subscriptions, so third-party subscriptions were never visible (N9).

        // --- Group memberships (security groups + M365 groups) ---
        context.ReportProgress($"Found {groups.Count} groups to scan for memberships.", 3);
        context.SetTotalTargets(phases + groups.Count);

        int groupsDone = 0;
        foreach (var group in groups)
        {
            ct.ThrowIfCancellationRequested();

            var groupId = Str(group, "id");
            var groupName = Str(group, "displayName");
            var groupTypes = StringArray(group, "groupTypes");
            var targetType = ClassifyGroup(groupTypes, Bool(group, "securityEnabled"), Bool(group, "mailEnabled"));
            var memberThrough = groupTypes.Contains("DynamicMembership", StringComparer.OrdinalIgnoreCase) ? "DynamicRule" : "Direct";

            if (string.IsNullOrEmpty(groupId))
            {
                context.CompleteTarget();
                groupsDone++;
                continue;
            }

            // Get group members and owners. Owners can add members (a privilege-escalation path),
            // so they must be captured distinctly (A2). Nested groups appear here as Group-typed
            // members, which flags the transitive path for review.
            var memberEntries = new List<PermissionEntry>();
            bool memberFetchFailed = false;
            try
            {
                await foreach (var member in _graphClient.GetPaginatedAsync($"groups/{groupId}/members?{MemberSelect}", ct: ct))
                    memberEntries.Add(MapPrincipalEntry(member, $"Group/{groupName}", targetType, groupId, "Member", memberThrough, "Permanent"));

                await foreach (var owner in _graphClient.GetPaginatedAsync($"groups/{groupId}/owners?{OwnerSelect}", ct: ct))
                    memberEntries.Add(MapPrincipalEntry(owner, $"Group/{groupName}", targetType, groupId, "Owner", "Direct", "Permanent"));
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                context.ReportProgress($"Failed to get members of group '{groupName}': {ex.Message}", 2);
                memberFetchFailed = true;
            }

            // Yield whatever members we collected (even if partial due to error)
            foreach (var e in memberEntries) yield return e;

            if (memberFetchFailed) context.FailTarget();
            else context.CompleteTarget();

            groupsDone++;
            if (groupsDone % 50 == 0)
                context.ReportProgress($"Scanned {groupsDone}/{groups.Count} groups...", 4);
        }

        context.ReportProgress($"Completed scanning {groupsDone} groups.", 3);
    }

    // ---------------------------------------------------------------- role assignments

    private readonly record struct Schedule(string AssignmentType, string Start, string End);

    /// <summary>
    /// Active role assignments from roleManagement (covers custom roles and AU/app-scoped assignments that
    /// directoryRoles/members misses, N1), with tenure from the assignment schedule instances (N2).
    /// </summary>
    private async Task<List<PermissionEntry>> ScanActiveRoleAssignmentsAsync(ScanContext context,
        Dictionary<string, string> roleDefs, Dictionary<string, string> scopeNames,
        Dictionary<string, List<JsonElement>?> groupMembers, CancellationToken ct)
    {
        var assignments = new List<JsonElement>();
        try
        {
            await foreach (var a in _graphClient.GetPaginatedAsync("roleManagement/directory/roleAssignments?$expand=principal", ct: ct))
                assignments.Add(a);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.BadRequest)
        {
            // Some tenants require a filter on this list: read it per role definition instead.
            assignments.Clear();
            foreach (var roleDefId in roleDefs.Keys.Distinct(StringComparer.OrdinalIgnoreCase))
                await foreach (var a in _graphClient.GetPaginatedAsync(
                    $"roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{roleDefId}'&$expand=principal", ct: ct))
                    assignments.Add(a);
            assignments = assignments.GroupBy(a => Str(a, "id")).Select(g => g.First()).ToList();
        }

        var schedules = await LoadAssignmentSchedulesAsync(context, ct);

        var entries = new List<PermissionEntry>();
        foreach (var a in assignments)
        {
            var roleDefId = Str(a, "roleDefinitionId");
            var roleName = roleDefs.TryGetValue(roleDefId, out var rn) && !string.IsNullOrEmpty(rn) ? rn : roleDefId;
            var scopeId = Str(a, "directoryScopeId");
            var principalId = Str(a, "principalId");

            var schedule = schedules.TryGetValue(Str(a, "id"), out var s) ? s
                : schedules.TryGetValue(ScheduleKey(principalId, roleDefId, scopeId), out var s2) ? s2
                : default;
            var tenure = RoleTenure.Active(schedule.AssignmentType, schedule.End);

            var row = MapRolePrincipal(a, principalId, roleName, roleDefId, scopeId, scopeNames, "DirectoryRoleAssignment", tenure);
            row.StartDateTime = schedule.Start ?? "";
            row.EndDateTime = schedule.End ?? "";
            entries.Add(row);
            entries.AddRange(await ExpandGroupHolderAsync(row, context, groupMembers, ct));
        }

        context.ReportProgress($"Found {assignments.Count} active role assignments.", 3);
        return entries;
    }

    private static string ScheduleKey(string principalId, string roleDefId, string scopeId)
        => $"{principalId}|{roleDefId}|{(string.IsNullOrEmpty(scopeId) ? "/" : scopeId)}";

    /// <summary>
    /// Assignment schedule instances, keyed by role assignment id and by principal|role|scope. Without them an
    /// activated PIM role looks permanent, which flags every admin who activated a role to run the scan.
    /// </summary>
    private async Task<Dictionary<string, Schedule>> LoadAssignmentSchedulesAsync(ScanContext context, CancellationToken ct)
    {
        var result = new Dictionary<string, Schedule>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await foreach (var i in _graphClient.GetPaginatedAsync("roleManagement/directory/roleAssignmentScheduleInstances", ct: ct))
            {
                var schedule = new Schedule(Str(i, "assignmentType"), Str(i, "startDateTime"), Str(i, "endDateTime"));
                var direct = Str(i, "memberType") is not { Length: > 0 } mt || mt.Equals("Direct", StringComparison.OrdinalIgnoreCase);
                if (Str(i, "roleAssignmentOriginId") is { Length: > 0 } origin && direct)
                    result[origin] = schedule;
                var key = ScheduleKey(Str(i, "principalId"), Str(i, "roleDefinitionId"), Str(i, "directoryScopeId"));
                if (direct) result[key] = schedule;
                else result.TryAdd(key, schedule);
            }
        }
        catch (HttpRequestException ex) when (IsLicensingError(ex))
        {
            // No PIM licence: activations and time-bound assignments cannot exist, so Permanent is accurate.
            context.ReportProgress("PIM is not licensed in this tenant; all active role assignments are permanent.", 3);
        }
        catch (HttpRequestException ex)
        {
            context.MarkPartial($"Role assignment schedules could not be read ({DescribeGraphError(ex)}); PIM-activated and time-bound roles are reported as Permanent.");
        }
        return result;
    }

    /// <summary>
    /// Members of a role-holding group hold the role too (N3). Emits one row per transitive member,
    /// keeping the group row; same role, target and tenure, Through="GroupMember", ParentId=group.
    /// </summary>
    private async Task<List<PermissionEntry>> ExpandGroupHolderAsync(PermissionEntry groupRow, ScanContext context,
        Dictionary<string, List<JsonElement>?> cache, CancellationToken ct)
    {
        var result = new List<PermissionEntry>();
        if (groupRow.PrincipalType != "Group" || string.IsNullOrEmpty(groupRow.PrincipalEntraId)) return result;

        if (!cache.TryGetValue(groupRow.PrincipalEntraId, out var members))
        {
            try
            {
                members = new List<JsonElement>();
                await foreach (var m in _graphClient.GetPaginatedAsync($"groups/{groupRow.PrincipalEntraId}/transitiveMembers?{MemberSelect}", ct: ct))
                    members.Add(m);
            }
            catch (HttpRequestException ex)
            {
                context.MarkPartial($"Members of role-holding group '{groupRow.PrincipalSysName}' could not be read ({ex.Message}).");
                members = null;
            }
            cache[groupRow.PrincipalEntraId] = members;
        }
        if (members == null) return result;

        foreach (var m in members)
        {
            var row = MapPrincipalEntry(m, groupRow.TargetPath, groupRow.TargetType, groupRow.TargetId,
                groupRow.PrincipalRole, "GroupMember", groupRow.Tenure);
            if (row.PrincipalType == "Group") continue; // nested groups are intermediates; their members are already listed
            row.ParentId = groupRow.PrincipalEntraId;
            row.StartDateTime = groupRow.StartDateTime;
            row.EndDateTime = groupRow.EndDateTime;
            result.Add(row);
        }
        return result;
    }

    /// <summary>"DirectoryRole/{role}", with " (scope: {id}, {name})" for AU- or app-scoped assignments.</summary>
    public static string RoleTargetPath(string roleName, string? directoryScopeId, IReadOnlyDictionary<string, string>? scopeNames = null)
    {
        if (string.IsNullOrEmpty(directoryScopeId) || directoryScopeId == "/") return $"DirectoryRole/{roleName}";
        var label = scopeNames != null && scopeNames.TryGetValue(directoryScopeId, out var n) && !string.IsNullOrEmpty(n) ? $", {n}" : "";
        return $"DirectoryRole/{roleName} (scope: {directoryScopeId}{label})";
    }

    private static PermissionEntry MapRolePrincipal(JsonElement assignment, string principalId, string roleName, string roleDefId,
        string scopeId, Dictionary<string, string> scopeNames, string through, string tenure)
    {
        var principal = assignment.TryGetProperty("principal", out var p) && p.ValueKind == JsonValueKind.Object ? p : default;
        var row = principal.ValueKind == JsonValueKind.Object
            ? MapPrincipalEntry(principal, RoleTargetPath(roleName, scopeId, scopeNames), "DirectoryRole", roleDefId, roleName, through, tenure)
            : new PermissionEntry
            {
                TargetPath = RoleTargetPath(roleName, scopeId, scopeNames),
                TargetType = "DirectoryRole",
                TargetId = roleDefId,
                PrincipalSysName = principalId,
                PrincipalType = "Unknown",
                PrincipalRole = roleName,
                Through = through,
                AccessType = "Allow",
                Tenure = tenure
            };
        if (string.IsNullOrEmpty(row.PrincipalEntraId)) row.PrincipalEntraId = principalId;
        return row;
    }

    // ---------------------------------------------------------------- PIM eligibility

    private async Task<List<PermissionEntry>> ScanEligibleRolesAsync(ScanContext context,
        Dictionary<string, string> roleDefs, Dictionary<string, string> scopeNames,
        Dictionary<string, List<JsonElement>?> groupMembers, CancellationToken ct)
    {
        var entries = new List<PermissionEntry>();
        var count = 0;
        try
        {
            await foreach (var a in _graphClient.GetPaginatedAsync(
                "roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal", ct: ct))
            {
                ct.ThrowIfCancellationRequested();
                count++;
                var roleDefId = Str(a, "roleDefinitionId");
                var roleName = roleDefs.TryGetValue(roleDefId, out var rn) && !string.IsNullOrEmpty(rn) ? rn : roleDefId;
                var end = Str(a, "endDateTime");

                var row = MapRolePrincipal(a, Str(a, "principalId"), roleName, roleDefId, Str(a, "directoryScopeId"),
                    scopeNames, "PIM-Eligible", RoleTenure.Eligible(end));
                row.StartDateTime = Str(a, "startDateTime");
                row.EndDateTime = end;
                entries.Add(row);
                entries.AddRange(await ExpandGroupHolderAsync(row, context, groupMembers, ct));
            }
            context.ReportProgress($"Found {count} PIM-eligible role assignments.", 3);
        }
        catch (HttpRequestException ex) when (IsLicensingError(ex))
        {
            context.ReportProgress("PIM is not available in this tenant (requires Microsoft Entra ID P2); no eligible role assignments.", 3);
        }
        catch (HttpRequestException ex)
        {
            context.MarkPartial($"PIM eligible role assignments could not be read ({DescribeGraphError(ex)}).");
        }
        return entries;
    }

    /// <summary>
    /// PIM for Groups eligibility (N4). The API requires a groupId (or principalId) filter, so it is read
    /// per role-assignable group: those are the groups that can carry directory roles.
    /// </summary>
    private async Task<List<PermissionEntry>> ScanEligibleGroupMembershipsAsync(ScanContext context,
        List<JsonElement> allGroups, CancellationToken ct)
    {
        var entries = new List<PermissionEntry>();
        var groups = allGroups.Where(g => Bool(g, "isAssignableToRole")).ToList();

        var raw = new List<(JsonElement Instance, JsonElement Group)>();
        var failed = 0;
        string? firstError = null;
        foreach (var group in groups)
        {
            ct.ThrowIfCancellationRequested();
            var groupId = Str(group, "id");
            try
            {
                await foreach (var i in _graphClient.GetPaginatedAsync(
                    $"identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq '{groupId}'", ct: ct))
                    raw.Add((i, group));
            }
            catch (HttpRequestException ex) when (IsLicensingError(ex))
            {
                context.ReportProgress("PIM for Groups is not available in this tenant (requires Microsoft Entra ID P2).", 3);
                return entries;
            }
            catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
            {
                // Same answer for every group: report once and stop.
                context.MarkPartial($"PIM for Groups eligibility could not be read ({DescribeGraphError(ex)}). " +
                    "Needs consent for PrivilegedEligibilitySchedule.Read.AzureADGroup and a role that can read PIM (e.g. Global Reader, Privileged Role Administrator).");
                return entries;
            }
            catch (HttpRequestException ex)
            {
                failed++;
                firstError ??= $"'{Str(group, "displayName")}': {ex.Message}";
            }
        }
        if (failed > 0)
            context.MarkPartial($"PIM for Groups eligibility failed for {failed} of {groups.Count} role-assignable group(s), first {firstError}.");

        // Resolve principals in bulk; deleted ones are reported as such.
        Dictionary<string, JsonElement>? principals = null;
        try
        {
            principals = await _graphClient.GetDirectoryObjectsByIdsAsync(
                raw.Select(r => Str(r.Instance, "principalId")), new[] { "user", "group", "servicePrincipal" }, ct);
        }
        catch (HttpRequestException ex)
        {
            context.ReportProgress($"PIM for Groups principals could not be resolved ({ex.Message}); rows show object ids.", 2);
        }

        foreach (var (i, group) in raw)
        {
            var groupId = Str(group, "id");
            var principalId = Str(i, "principalId");
            var end = Str(i, "endDateTime");
            var targetType = ClassifyGroup(StringArray(group, "groupTypes"), Bool(group, "securityEnabled"), Bool(group, "mailEnabled"));
            var role = Str(i, "accessId").Equals("owner", StringComparison.OrdinalIgnoreCase) ? "Owner" : "Member";

            PermissionEntry row;
            if (principals != null && principals.TryGetValue(principalId, out var p))
                row = MapPrincipalEntry(p, $"Group/{Str(group, "displayName")}", targetType, groupId, role, "PIM-EligibleGroupAccess", RoleTenure.Eligible(end));
            else
                row = new PermissionEntry
                {
                    TargetPath = $"Group/{Str(group, "displayName")}",
                    TargetType = targetType,
                    TargetId = groupId,
                    PrincipalEntraId = principalId,
                    PrincipalSysName = principals != null ? $"Deleted principal ({principalId})" : principalId,
                    PrincipalType = principals != null ? "Deleted principal" : "Unknown",
                    PrincipalRole = role,
                    Through = "PIM-EligibleGroupAccess",
                    AccessType = "Allow",
                    Tenure = RoleTenure.Eligible(end)
                };
            row.StartDateTime = Str(i, "startDateTime");
            row.EndDateTime = end;
            entries.Add(row);
        }
        if (entries.Count > 0)
            context.ReportProgress($"Found {entries.Count} PIM-eligible group memberships.", 3);
        return entries;
    }

    // ---------------------------------------------------------------- OAuth2 grants

    /// <summary>
    /// Delegated permission grants (N6). AllPrincipals grants are held by the client app for every user;
    /// Principal grants are held by one user, who is the principal of the row.
    /// </summary>
    private async Task<List<PermissionEntry>> ScanOAuth2GrantsAsync(ScanContext context, ServicePrincipalCache sps, CancellationToken ct)
    {
        var grants = new List<JsonElement>();
        await foreach (var grant in _graphClient.GetPaginatedAsync(
            "oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope", ct: ct))
            grants.Add(grant);

        var userIds = grants.Where(g => Str(g, "consentType") == "Principal").Select(g => Str(g, "principalId")).ToList();
        Dictionary<string, JsonElement>? users = null;
        if (userIds.Count > 0)
        {
            try
            {
                users = await _graphClient.GetDirectoryObjectsByIdsAsync(userIds, new[] { "user" }, ct);
            }
            catch (HttpRequestException ex)
            {
                context.ReportProgress($"Users holding OAuth2 grants could not be resolved ({ex.Message}); rows show object ids.", 2);
            }
        }

        var entries = new List<PermissionEntry>();
        foreach (var grant in grants)
        {
            var clientId = Str(grant, "clientId");
            var resourceId = Str(grant, "resourceId");
            var principalId = Str(grant, "principalId");
            var allPrincipals = Str(grant, "consentType") == "AllPrincipals";

            sps.NameByObjectId.TryGetValue(clientId, out var clientName);
            sps.NameByObjectId.TryGetValue(resourceId, out var resourceName);
            var targetPath = $"OAuth2PermissionGrant/{(string.IsNullOrEmpty(clientName) ? clientId : clientName)}"
                + (string.IsNullOrEmpty(resourceName) ? "" : $" → {resourceName}");

            foreach (var permission in Str(grant, "scope").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var row = new PermissionEntry
                {
                    TargetPath = targetPath,
                    TargetType = "DelegatedConsent",
                    TargetId = clientId,
                    PrincipalRole = permission,
                    AccessType = "Allow",
                    Tenure = "Permanent"
                };

                if (allPrincipals)
                {
                    row.PrincipalEntraId = clientId;
                    row.PrincipalSysId = sps.AppIdByObjectId.TryGetValue(clientId, out var appId) ? appId : "";
                    row.PrincipalSysName = clientName ?? clientId;
                    row.PrincipalType = "Application";
                    row.Through = "OAuth2Grant (AllPrincipals)";
                }
                else
                {
                    row.Through = "OAuth2Grant (Principal)";
                    row.ParentId = clientId;
                    if (users != null && users.TryGetValue(principalId, out var u))
                    {
                        var upn = Str(u, "userPrincipalName");
                        row.PrincipalEntraId = principalId;
                        row.PrincipalEntraUpn = upn;
                        row.PrincipalSysName = Str(u, "displayName");
                        row.PrincipalType = IsGuest(Str(u, "userType"), upn) ? "Guest" : "User";
                    }
                    else
                    {
                        row.PrincipalEntraId = principalId;
                        row.PrincipalSysName = users != null ? $"Deleted principal ({principalId})" : principalId;
                        row.PrincipalType = users != null ? "Deleted principal" : "User";
                    }
                }
                entries.Add(row);
            }
        }

        context.ReportProgress($"Found {grants.Count} OAuth2 grants.", 3);
        return entries;
    }

    // ---------------------------------------------------------------- apps and owners

    private readonly record struct OwnedObject(string Path, string Type, string Id, string Through);

    /// <summary>Requested permissions from requiredResourceAccess; type Role resolves against appRoles, Scope against oauth2PermissionScopes (N8).</summary>
    private static IEnumerable<PermissionEntry> MapRequestedPermissions(JsonElement app, ServicePrincipalCache sps)
    {
        var appName = Str(app, "displayName");
        var appObjId = Str(app, "id");
        var appClientId = Str(app, "appId");
        sps.ObjectIdByAppId.TryGetValue(appClientId, out var spObjectId);

        if (!app.TryGetProperty("requiredResourceAccess", out var rra) || rra.ValueKind != JsonValueKind.Array) yield break;
        foreach (var resource in rra.EnumerateArray())
        {
            var resourceAppId = Str(resource, "resourceAppId");
            sps.ByAppId.TryGetValue(resourceAppId, out var api);
            var resourceName = !string.IsNullOrEmpty(api?.Name) ? api!.Name : resourceAppId;

            if (!resource.TryGetProperty("resourceAccess", out var accesses) || accesses.ValueKind != JsonValueKind.Array) continue;
            foreach (var access in accesses.EnumerateArray())
            {
                var permId = Str(access, "id");
                var isRole = Str(access, "type") == "Role";
                var names = isRole ? api?.AppRoles : api?.Scopes;
                var permName = names != null && names.TryGetValue(permId, out var pn) ? pn : permId;

                yield return new PermissionEntry
                {
                    TargetPath = $"AppRegistration/{appName} → {resourceName}",
                    TargetType = "Application",
                    TargetId = appObjId,
                    PrincipalEntraId = spObjectId ?? "",
                    PrincipalSysId = appClientId,
                    PrincipalSysName = appName,
                    PrincipalType = "Application",
                    PrincipalRole = permName,
                    // "Requested" is not "Granted": these come from the app manifest and may never have been
                    // consented, so risk policies keyed on "ApplicationPermission" must not fire on them (A1).
                    Through = isRole ? "RequestedApplicationPermission" : "RequestedDelegatedPermission",
                    AccessType = "Allow",
                    Tenure = "Requested"
                };
            }
        }
    }

    /// <summary>Owner rows from an expanded owners collection, re-read in full when the expand cap was hit.</summary>
    private async Task<List<PermissionEntry>> ReadOwnersAsync(JsonElement obj, bool expanded, string ownersUrl,
        OwnedObject target, ScanContext context, CancellationToken ct)
    {
        var result = new List<PermissionEntry>();
        if (!expanded || string.IsNullOrEmpty(target.Id)) return result;
        if (!obj.TryGetProperty("owners", out var owners) || owners.ValueKind != JsonValueKind.Array) return result;

        IEnumerable<JsonElement> list = owners.EnumerateArray().ToList();
        if (owners.GetArrayLength() >= ExpandCap)
        {
            try
            {
                var all = new List<JsonElement>();
                await foreach (var o in _graphClient.GetPaginatedAsync(ownersUrl, ct: ct)) all.Add(o);
                list = all;
            }
            catch (HttpRequestException ex)
            {
                context.MarkPartial($"Owners of '{target.Path}' could not be read in full ({ex.Message}).");
            }
        }

        foreach (var o in list)
            result.Add(MapPrincipalEntry(o, target.Path, target.Type, target.Id, "Owner", target.Through, "Permanent"));
        return result;
    }

    /// <summary>
    /// Enumerate service principals once: permission definitions per resource API (by appId and object id),
    /// names and appId/objectId maps, and the SPs that have owners.
    /// </summary>
    private async Task<ServicePrincipalCache> BuildServicePrincipalCacheAsync(ScanContext context, CancellationToken ct)
    {
        var cache = new ServicePrincipalCache();
        const string select = "servicePrincipals?$select=id,appId,displayName,appRoles,oauth2PermissionScopes";
        var (items, expanded) = await CollectWithFallbackAsync($"{select}&$expand=owners({OwnerSelect})", select, ct);
        if (!expanded)
            context.MarkPartial("Enterprise app owners could not be expanded; service principal owners are missing.");

        foreach (var sp in items)
        {
            var spId = Str(sp, "id");
            var appId = Str(sp, "appId");
            var api = new ResourceApi { Name = Str(sp, "displayName") };
            if (!string.IsNullOrEmpty(spId)) cache.NameByObjectId[spId] = api.Name;
            if (!string.IsNullOrEmpty(spId) && !string.IsNullOrEmpty(appId))
            {
                cache.ObjectIdByAppId[appId] = spId;
                cache.AppIdByObjectId[spId] = appId;
            }

            ReadPermissionNames(sp, "appRoles", api.AppRoles);
            ReadPermissionNames(sp, "oauth2PermissionScopes", api.Scopes);
            if (!string.IsNullOrEmpty(appId)) cache.ByAppId[appId] = api;
            if (!string.IsNullOrEmpty(spId)) cache.ByObjectId[spId] = api;

            if (sp.TryGetProperty("owners", out var o) && o.ValueKind == JsonValueKind.Array && o.GetArrayLength() > 0)
                cache.WithOwners.Add(sp);
        }
        return cache;
    }

    private static void ReadPermissionNames(JsonElement sp, string property, Dictionary<string, string> map)
    {
        if (!sp.TryGetProperty(property, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
        foreach (var item in arr.EnumerateArray())
            if (Str(item, "id") is { Length: > 0 } id && Str(item, "value") is { Length: > 0 } value)
                map[id] = value;
    }

    /// <summary>Collect a paged list; when the expanded query is rejected (400), fall back to the plain one.</summary>
    private async Task<(List<JsonElement> Items, bool UsedPrimary)> CollectWithFallbackAsync(string url, string fallbackUrl, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        try
        {
            await foreach (var i in _graphClient.GetPaginatedAsync(url, ct: ct)) items.Add(i);
            return (items, true);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.BadRequest)
        {
            items.Clear();
            await foreach (var i in _graphClient.GetPaginatedAsync(fallbackUrl, ct: ct)) items.Add(i);
            return (items, false);
        }
    }

    // ---------------------------------------------------------------- mapping helpers

    private static PermissionEntry MapPrincipalEntry(JsonElement principal, string targetPath, string targetType, string targetId,
        string role, string through, string tenure)
    {
        var upn = Str(principal, "userPrincipalName");
        var type = MapMemberType(Str(principal, "@odata.type"), Str(principal, "userType"), upn);
        var id = Str(principal, "id");
        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = targetType,
            TargetId = targetId,
            PrincipalEntraId = id,
            PrincipalEntraUpn = upn,
            PrincipalSysId = type == "ServicePrincipal" ? Str(principal, "appId") : "",
            PrincipalSysName = Str(principal, "displayName"),
            PrincipalType = type,
            PrincipalRole = role,
            Through = through,
            AccessType = "Allow",
            Tenure = tenure
        };
    }

    /// <summary>
    /// Group TargetType (N10): Unified = M365Group, security-enabled (mail-enabled or not) = SecurityGroup,
    /// mail-enabled only = DistributionList.
    /// </summary>
    public static string ClassifyGroup(IEnumerable<string>? groupTypes, bool securityEnabled, bool mailEnabled)
    {
        if (groupTypes != null && groupTypes.Contains("Unified", StringComparer.OrdinalIgnoreCase)) return "M365Group";
        if (securityEnabled) return "SecurityGroup";
        if (mailEnabled) return "DistributionList";
        return "SecurityGroup";
    }

    /// <summary>Guests are users with userType Guest; B2B guests also carry #EXT# in their UPN when userType is not returned.</summary>
    public static bool IsGuest(string? userType, string? upn)
        => string.Equals(userType, "Guest", StringComparison.OrdinalIgnoreCase)
           || (upn?.Contains("#EXT#", StringComparison.OrdinalIgnoreCase) ?? false);

    public static string MapMemberType(string odataType, string userType = "", string upn = "")
    {
        // Surfacing guests as "Guest" lets the guest/external policy fire on Entra rows (A2).
        if (odataType == "#microsoft.graph.user" && IsGuest(userType, upn))
            return "Guest";

        return odataType switch
        {
            "#microsoft.graph.user" => "User",
            "#microsoft.graph.servicePrincipal" => "ServicePrincipal",
            "#microsoft.graph.group" => "Group",
            "#microsoft.graph.device" => "Device",
            _ => "Unknown"
        };
    }

    /// <summary>Graph returns 400 with a licensing message when PIM (Entra ID P2) is not available.</summary>
    internal static bool IsLicensingError(HttpRequestException ex)
        => ex.StatusCode == HttpStatusCode.BadRequest
           && (ex.Message.Contains("license", StringComparison.OrdinalIgnoreCase)
               || ex.Message.Contains("AadPremium", StringComparison.OrdinalIgnoreCase)
               || ex.Message.Contains("P2", StringComparison.Ordinal));

    private static string DescribeGraphError(HttpRequestException ex) => ex.StatusCode switch
    {
        HttpStatusCode.Forbidden => "HTTP 403: missing consent or the signed-in account lacks a role that can read it",
        HttpStatusCode.Unauthorized => "HTTP 401: token rejected",
        _ => ex.Message
    };

    /// <summary>Errors a per-item loop can absorb; cancellation and exhausted retries end the category.</summary>
    private static bool IsRecoverable(Exception ex) => ex is not OperationCanceledException and not GraphRetryExhaustedException;

    private static string Str(JsonElement el, string name)
        => el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static bool Bool(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static List<string> StringArray(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").ToList()
            : new List<string>();
}

/// <summary>
/// Tenure strings shared by the Entra and Azure scanners. Policies key on "Permanent" (exact) and on the
/// "Eligible" prefix, so those two spellings must not change.
/// </summary>
public static class RoleTenure
{
    /// <summary>
    /// Active assignment: "Permanent" (assigned, no end), "Active (until X)" (time-bound assigned) or
    /// "Activated (PIM, until X)" (a PIM activation of an eligible assignment).
    /// </summary>
    public static string Active(string? assignmentType, string? endDateTime)
    {
        var hasEnd = !string.IsNullOrWhiteSpace(endDateTime);
        if (string.Equals(assignmentType, "Activated", StringComparison.OrdinalIgnoreCase))
            return hasEnd ? $"Activated (PIM, until {endDateTime})" : "Activated (PIM)";
        return hasEnd ? $"Active (until {endDateTime})" : "Permanent";
    }

    /// <summary>Eligible assignment: "Eligible-Permanent" or "Eligible (until X)".</summary>
    public static string Eligible(string? endDateTime)
        => string.IsNullOrWhiteSpace(endDateTime) ? "Eligible-Permanent" : $"Eligible (until {endDateTime})";
}
