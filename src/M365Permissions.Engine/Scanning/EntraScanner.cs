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

    public EntraScanner(GraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // --- Directory Roles ---
        context.ReportProgress("Scanning Entra directory roles...", 3);

        var roles = new List<JsonElement>();
        await foreach (var role in _graphClient.GetPaginatedAsync("directoryRoles", ct: ct))
        {
            roles.Add(role);
        }

        context.ReportProgress($"Found {roles.Count} directory roles.", 3);

        // We'll add to total targets as we discover groups later
        context.SetTotalTargets(roles.Count + 3); // roles + apps phase + OAuth2 phase + groups-enum phase

        foreach (var role in roles)
        {
            ct.ThrowIfCancellationRequested();

            var roleName = role.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
            var roleId = role.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";

            if (!string.IsNullOrEmpty(roleId))
            {
                // Enumerate members with pagination per role. directoryRoles?$expand=members caps
                // at ~20 members with no nextLink for the expanded collection, silently dropping
                // members in large roles — the worst failure mode for an audit tool (B4).
                await foreach (var member in _graphClient.GetPaginatedAsync(
                    $"directoryRoles/{roleId}/members?$select=id,displayName,userPrincipalName,userType", ct: ct))
                {
                    yield return MapDirectoryRoleMember(member, roleName, roleId);
                }
            }

            context.CompleteTarget();
        }

        // Build caches that resolve permission GUIDs → human-readable names (Mail.Read, etc.).
        // Needed both to make requested-permission entries readable and to resolve granted
        // app-role assignments below (A1). Without this, principal_role held raw GUIDs, so the
        // high-risk-application-permission policy could never match a permission name.
        context.ReportProgress("Resolving application permission definitions...", 3);
        var (appPermsByAppId, appPermsByObjectId) = await BuildAppPermissionCachesAsync(ct);

        // --- App Registrations: REQUESTED permissions (requiredResourceAccess) ---
        context.ReportProgress("Scanning app registrations...", 3);

        int appCount = 0;
        await foreach (var app in _graphClient.GetPaginatedAsync(
            "applications?$select=id,displayName,appId,requiredResourceAccess", ct: ct))
        {
            ct.ThrowIfCancellationRequested();
            appCount++;

            var appName = app.TryGetProperty("displayName", out var dn2) ? dn2.GetString() ?? "" : "";
            var appObjId = app.TryGetProperty("id", out var id2) ? id2.GetString() ?? "" : "";
            var appClientId = app.TryGetProperty("appId", out var aid) ? aid.GetString() ?? "" : "";

            if (app.TryGetProperty("requiredResourceAccess", out var rra) && rra.ValueKind == JsonValueKind.Array)
            {
                foreach (var resource in rra.EnumerateArray())
                {
                    var resourceAppId = resource.TryGetProperty("resourceAppId", out var rai) ? rai.GetString() ?? "" : "";
                    if (resource.TryGetProperty("resourceAccess", out var accesses) && accesses.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var access in accesses.EnumerateArray())
                        {
                            var permId = access.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
                            var permType = access.TryGetProperty("type", out var pt) ? pt.GetString() ?? "" : "";

                            // Resolve the permission GUID to its name via the resource app's definitions.
                            var permName = appPermsByAppId.TryGetValue(resourceAppId, out var rmap)
                                && rmap.TryGetValue(permId, out var pn) ? pn : permId;

                            yield return new PermissionEntry
                            {
                                TargetPath = $"AppRegistration/{appName}",
                                TargetType = "Application",
                                TargetId = appObjId,
                                PrincipalEntraId = appClientId,
                                PrincipalSysName = appName,
                                PrincipalType = "Application",
                                PrincipalRole = permName,
                                // "Requested" ≠ "Granted": these come from the app manifest and may
                                // never have been consented. Mark distinctly so risk policies (which
                                // key on the granted "ApplicationPermission") don't fire on them (A1).
                                Through = permType == "Role" ? "RequestedApplicationPermission" : "RequestedDelegatedPermission",
                                AccessType = "Allow",
                                Tenure = "Requested"
                            };
                        }
                    }
                }
            }
        }

        context.ReportProgress($"Scanned {appCount} app registrations.", 3);

        // --- Service principals: GRANTED application permissions (appRoleAssignments) ---
        // These are the permissions actually consented to an app — the real risk surface.
        context.ReportProgress("Scanning granted application permissions...", 3);
        int grantedPermCount = 0;
        await foreach (var sp in _graphClient.GetPaginatedAsync(
            "servicePrincipals?$select=id,appId,displayName&$expand=appRoleAssignments", ct: ct))
        {
            ct.ThrowIfCancellationRequested();

            var spName = sp.TryGetProperty("displayName", out var spdn) ? spdn.GetString() ?? "" : "";
            var spAppId = sp.TryGetProperty("appId", out var spaid) ? spaid.GetString() ?? "" : "";
            var spId = sp.TryGetProperty("id", out var spid) ? spid.GetString() ?? "" : "";

            if (!sp.TryGetProperty("appRoleAssignments", out var aras) || aras.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var ara in aras.EnumerateArray())
            {
                var appRoleId = ara.TryGetProperty("appRoleId", out var arid) ? arid.GetString() ?? "" : "";
                var resourceId = ara.TryGetProperty("resourceId", out var resId) ? resId.GetString() ?? "" : "";
                var resourceName = ara.TryGetProperty("resourceDisplayName", out var rdn) ? rdn.GetString() ?? "" : "";

                // The all-zero GUID is the "default access" role (no specific app role) — skip it.
                if (string.IsNullOrEmpty(appRoleId) || appRoleId == "00000000-0000-0000-0000-000000000000")
                    continue;

                var permName = appPermsByObjectId.TryGetValue(resourceId, out var rmap2)
                    && rmap2.TryGetValue(appRoleId, out var pn2) ? pn2 : appRoleId;

                grantedPermCount++;
                yield return new PermissionEntry
                {
                    TargetPath = string.IsNullOrEmpty(resourceName) ? $"EnterpriseApp/{spName}" : $"EnterpriseApp/{spName} → {resourceName}",
                    TargetType = "ServicePrincipal",
                    TargetId = spId,
                    PrincipalEntraId = spAppId,
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

        // --- PIM: Eligible directory role assignments ---
        context.ReportProgress("Checking for PIM (Privileged Identity Management) eligible assignments...", 3);

        bool pimAvailable = false;
        int eligibleCount = 0;
        var pimRoleEntries = new List<PermissionEntry>();
        try
        {
            await foreach (var assignment in _graphClient.GetPaginatedAsync(
                "roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal,roleDefinition", ct: ct))
            {
                ct.ThrowIfCancellationRequested();
                pimAvailable = true;
                eligibleCount++;

                var roleDef = assignment.TryGetProperty("roleDefinition", out var rd) ? rd : default;
                var roleName = roleDef.ValueKind != JsonValueKind.Undefined &&
                               roleDef.TryGetProperty("displayName", out var rdn) ? rdn.GetString() ?? "" : "";
                var roleDefId = assignment.TryGetProperty("roleDefinitionId", out var rdi) ? rdi.GetString() ?? "" : "";

                var principal = assignment.TryGetProperty("principal", out var pr) ? pr : default;
                var principalId = assignment.TryGetProperty("principalId", out var pid) ? pid.GetString() ?? "" : "";
                var principalUpn = principal.ValueKind != JsonValueKind.Undefined &&
                                   principal.TryGetProperty("userPrincipalName", out var pupn) ? pupn.GetString() ?? "" : "";
                var principalName = principal.ValueKind != JsonValueKind.Undefined &&
                                    principal.TryGetProperty("displayName", out var pdn) ? pdn.GetString() ?? "" : "";
                var principalOdataType = principal.ValueKind != JsonValueKind.Undefined &&
                                         principal.TryGetProperty("@odata.type", out var pot) ? pot.GetString() ?? "" : "";

                var startTime = assignment.TryGetProperty("startDateTime", out var st) ? st.GetString() ?? "" : "";
                var endTime = assignment.TryGetProperty("endDateTime", out var et) ? et.GetString() ?? "" : "";

                pimRoleEntries.Add(new PermissionEntry
                {
                    TargetPath = $"DirectoryRole/{roleName}",
                    TargetType = "DirectoryRole",
                    TargetId = roleDefId,
                    PrincipalEntraId = principalId,
                    PrincipalEntraUpn = principalUpn,
                    PrincipalSysName = principalName,
                    PrincipalType = MapMemberType(principalOdataType),
                    PrincipalRole = roleName,
                    Through = "PIM-Eligible",
                    AccessType = "Allow",
                    Tenure = string.IsNullOrEmpty(endTime) ? "Eligible-Permanent" : $"Eligible (until {endTime})"
                });
            }
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                                                ex.StatusCode == System.Net.HttpStatusCode.BadRequest)
        {
            context.ReportProgress("PIM not available in this tenant (may require P2 license).", 3);
        }
        catch (Exception ex)
        {
            context.ReportProgress($"PIM role eligibility check failed: {ex.Message}", 3);
        }

        foreach (var e in pimRoleEntries) yield return e;

        // --- PIM: Eligible group memberships ---
        var pimGroupEntries = new List<PermissionEntry>();
        try
        {
            await foreach (var assignment in _graphClient.GetPaginatedAsync(
                "identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$expand=principal,group", ct: ct))
            {
                ct.ThrowIfCancellationRequested();
                pimAvailable = true;
                eligibleCount++;

                var group = assignment.TryGetProperty("group", out var g) ? g : default;
                var groupName = group.ValueKind != JsonValueKind.Undefined &&
                                group.TryGetProperty("displayName", out var gdn) ? gdn.GetString() ?? "" : "";
                var groupId = assignment.TryGetProperty("groupId", out var gid) ? gid.GetString() ?? "" : "";
                var accessId = assignment.TryGetProperty("accessId", out var aid2) ? aid2.GetString() ?? "" : "member";

                var principal = assignment.TryGetProperty("principal", out var pr2) ? pr2 : default;
                var principalId = assignment.TryGetProperty("principalId", out var pid2) ? pid2.GetString() ?? "" : "";
                var principalUpn = principal.ValueKind != JsonValueKind.Undefined &&
                                   principal.TryGetProperty("userPrincipalName", out var pupn2) ? pupn2.GetString() ?? "" : "";
                var principalName = principal.ValueKind != JsonValueKind.Undefined &&
                                    principal.TryGetProperty("displayName", out var pdn2) ? pdn2.GetString() ?? "" : "";
                var principalOdataType = principal.ValueKind != JsonValueKind.Undefined &&
                                         principal.TryGetProperty("@odata.type", out var pot2) ? pot2.GetString() ?? "" : "";

                var endTime = assignment.TryGetProperty("endDateTime", out var et2) ? et2.GetString() ?? "" : "";

                pimGroupEntries.Add(new PermissionEntry
                {
                    TargetPath = $"Group/{groupName}",
                    TargetType = "SecurityGroup",
                    TargetId = groupId,
                    PrincipalEntraId = principalId,
                    PrincipalEntraUpn = principalUpn,
                    PrincipalSysName = principalName,
                    PrincipalType = MapMemberType(principalOdataType),
                    PrincipalRole = accessId == "owner" ? "Owner" : "Member",
                    Through = "PIM-EligibleGroupAccess",
                    AccessType = "Allow",
                    Tenure = string.IsNullOrEmpty(endTime) ? "Eligible-Permanent" : $"Eligible (until {endTime})"
                });
            }
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                                                ex.StatusCode == System.Net.HttpStatusCode.BadRequest)
        {
            // Expected if PIM for groups is not configured
        }
        catch (Exception ex)
        {
            context.ReportProgress($"PIM group eligibility check failed: {ex.Message}", 3);
        }

        foreach (var e in pimGroupEntries) yield return e;

        if (pimAvailable)
            context.ReportProgress($"PIM active: found {eligibleCount} eligible assignments.", 3);
        else
            context.ReportProgress("PIM not detected or not accessible in this tenant.", 3);

        // --- Service Principal OAuth2 grants (delegated consent) ---
        context.ReportProgress("Scanning OAuth2 permission grants...", 3);

        // Build service principal lookup cache (id → displayName) for resolving OAuth2 grant targets
        context.ReportProgress("Building service principal cache for OAuth2 grants...", 3);
        var spCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        await foreach (var sp in _graphClient.GetPaginatedAsync(
            "servicePrincipals?$select=id,displayName", ct: ct))
        {
            ct.ThrowIfCancellationRequested();
            var spId = sp.TryGetProperty("id", out var sid) ? sid.GetString() ?? "" : "";
            var spName = sp.TryGetProperty("displayName", out var sdn) ? sdn.GetString() ?? "" : "";
            if (!string.IsNullOrEmpty(spId))
                spCache[spId] = spName;
        }
        context.ReportProgress($"Cached {spCache.Count} service principals.", 3);

        int oauth2GrantCount = 0;
        await foreach (var grant in _graphClient.GetPaginatedAsync(
            "oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope", ct: ct))
        {
            ct.ThrowIfCancellationRequested();
            oauth2GrantCount++;

            var clientId = grant.TryGetProperty("clientId", out var ci) ? ci.GetString() ?? "" : "";
            var resourceId = grant.TryGetProperty("resourceId", out var ri) ? ri.GetString() ?? "" : "";
            var scope = grant.TryGetProperty("scope", out var s) ? s.GetString() ?? "" : "";
            var consentType = grant.TryGetProperty("consentType", out var ct2) ? ct2.GetString() ?? "" : "";
            var principalId = grant.TryGetProperty("principalId", out var pi) ? pi.GetString() ?? "" : "";

            // Resolve display names from cache
            spCache.TryGetValue(clientId, out var clientName);
            spCache.TryGetValue(resourceId, out var resourceName);
            var targetPath = !string.IsNullOrEmpty(clientName) ? $"OAuth2PermissionGrant/{clientName}" : "OAuth2PermissionGrant";

            foreach (var permission in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                yield return new PermissionEntry
                {
                    TargetPath = targetPath,
                    TargetType = "DelegatedConsent",
                    TargetId = resourceId,
                    PrincipalEntraId = clientId,
                    PrincipalSysName = clientName ?? "",
                    PrincipalType = consentType == "AllPrincipals" ? "AllPrincipals" : "User",
                    PrincipalRole = permission,
                    Through = !string.IsNullOrEmpty(resourceName) ? $"OAuth2Grant → {resourceName}" : "OAuth2Grant",
                    ParentId = principalId,
                    AccessType = "Allow",
                    Tenure = "Permanent"
                };
            }
        }

        context.ReportProgress($"Found {oauth2GrantCount} OAuth2 grants.", 3);
        context.CompleteTarget();

        // --- Graph Subscriptions (webhook change notifications) ---
        context.ReportProgress("Scanning Graph webhook subscriptions...", 3);

        var subscriptionEntries = new List<PermissionEntry>();
        try
        {
            await foreach (var sub in _graphClient.GetPaginatedAsync(
                "subscriptions", ct: ct))
            {
                ct.ThrowIfCancellationRequested();

                var subId = sub.TryGetProperty("id", out var sid) ? sid.GetString() ?? "" : "";
                var resource = sub.TryGetProperty("resource", out var res) ? res.GetString() ?? "" : "";
                var changeType = sub.TryGetProperty("changeType", out var ctp) ? ctp.GetString() ?? "" : "";
                var notificationUrl = sub.TryGetProperty("notificationUrl", out var nu) ? nu.GetString() ?? "" : "";
                var expirationStr = sub.TryGetProperty("expirationDateTime", out var exp) ? exp.GetString() ?? "" : "";
                var applicationId = sub.TryGetProperty("applicationId", out var appId) ? appId.GetString() ?? "" : "";
                var creatorId = sub.TryGetProperty("creatorId", out var cid) ? cid.GetString() ?? "" : "";
                var includeResourceData = sub.TryGetProperty("includeResourceData", out var ird)
                    && ird.ValueKind == JsonValueKind.True;

                // Resolve application name from SP cache if available
                var appName = "";
                if (!string.IsNullOrEmpty(applicationId))
                    spCache.TryGetValue(applicationId, out appName);
                appName ??= "";

                // Determine tenure from expiration
                var tenure = "Permanent";
                if (!string.IsNullOrEmpty(expirationStr) && DateTimeOffset.TryParse(expirationStr, out var expDate))
                {
                    tenure = expDate > DateTimeOffset.UtcNow
                        ? $"Expires {expDate:yyyy-MM-dd HH:mm} UTC"
                        : $"Expired {expDate:yyyy-MM-dd HH:mm} UTC";
                }

                // Extract notification domain for readability
                var notifDomain = "";
                if (Uri.TryCreate(notificationUrl, UriKind.Absolute, out var notifUri))
                    notifDomain = notifUri.Host;

                var targetLabel = !string.IsNullOrEmpty(appName) ? appName : applicationId;

                subscriptionEntries.Add(new PermissionEntry
                {
                    TargetPath = $"Subscription/{targetLabel}/{resource}",
                    TargetType = "Subscription",
                    TargetId = subId,
                    PrincipalEntraId = applicationId,
                    PrincipalSysId = creatorId,
                    PrincipalSysName = !string.IsNullOrEmpty(appName) ? appName : applicationId,
                    PrincipalType = "Application",
                    PrincipalRole = changeType,
                    Through = !string.IsNullOrEmpty(notifDomain) ? $"Webhook → {notifDomain}" : "Webhook",
                    AccessType = includeResourceData ? "IncludesResourceData" : "NotificationOnly",
                    Tenure = tenure
                });
            }
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                                                ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            context.ReportProgress("Cannot list Graph subscriptions — Subscription.Read.All permission may be missing. Skipping.", 3);
        }
        catch (Exception ex)
        {
            context.ReportProgress($"Graph subscription enumeration failed: {ex.Message}", 3);
        }

        foreach (var e in subscriptionEntries) yield return e;
        context.ReportProgress($"Found {subscriptionEntries.Count} Graph webhook subscriptions.", 3);

        // --- Group memberships (security groups + M365 groups) ---
        context.ReportProgress("Enumerating groups...", 3);

        // First collect all groups, then set targets to include per-group progress
        var groups = new List<JsonElement>();
        await foreach (var group in _graphClient.GetPaginatedAsync(
            "groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled", ct: ct))
        {
            groups.Add(group);
        }

        context.ReportProgress($"Found {groups.Count} groups to scan for memberships.", 3);
        // Update total: roles already completed + apps + OAuth2 + individual groups
        context.SetTotalTargets(roles.Count + 2 + groups.Count);

        int groupsDone = 0;
        foreach (var group in groups)
        {
            ct.ThrowIfCancellationRequested();

            var groupId = group.TryGetProperty("id", out var gid) ? gid.GetString() ?? "" : "";
            var groupName = group.TryGetProperty("displayName", out var gdn) ? gdn.GetString() ?? "" : "";
            var secEnabled = group.TryGetProperty("securityEnabled", out var se) && se.GetBoolean();

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
                await foreach (var member in _graphClient.GetPaginatedAsync(
                    $"groups/{groupId}/members?$select=id,displayName,userPrincipalName,userType", ct: ct))
                {
                    var memberUpn = member.TryGetProperty("userPrincipalName", out var upn) ? upn.GetString() ?? "" : "";
                    var memberName = member.TryGetProperty("displayName", out var mdn) ? mdn.GetString() ?? "" : "";
                    var memberId = member.TryGetProperty("id", out var mid) ? mid.GetString() ?? "" : "";
                    var memberType = member.TryGetProperty("@odata.type", out var ot) ? ot.GetString() ?? "" : "";
                    var memberUserType = member.TryGetProperty("userType", out var mut) ? mut.GetString() ?? "" : "";

                    memberEntries.Add(new PermissionEntry
                    {
                        TargetPath = $"Group/{groupName}",
                        TargetType = secEnabled ? "SecurityGroup" : "M365Group",
                        TargetId = groupId,
                        PrincipalEntraId = memberId,
                        PrincipalEntraUpn = memberUpn,
                        PrincipalSysName = memberName,
                        PrincipalType = MapMemberType(memberType, memberUserType),
                        PrincipalRole = "Member",
                        Through = "Direct",
                        AccessType = "Allow",
                        Tenure = "Permanent"
                    });
                }

                await foreach (var owner in _graphClient.GetPaginatedAsync(
                    $"groups/{groupId}/owners?$select=id,displayName,userPrincipalName,userType", ct: ct))
                {
                    var ownerUpn = owner.TryGetProperty("userPrincipalName", out var oupn) ? oupn.GetString() ?? "" : "";
                    var ownerName = owner.TryGetProperty("displayName", out var odn) ? odn.GetString() ?? "" : "";
                    var ownerId = owner.TryGetProperty("id", out var oid) ? oid.GetString() ?? "" : "";
                    var ownerType = owner.TryGetProperty("@odata.type", out var oot) ? oot.GetString() ?? "" : "";
                    var ownerUserType = owner.TryGetProperty("userType", out var out2) ? out2.GetString() ?? "" : "";

                    memberEntries.Add(new PermissionEntry
                    {
                        TargetPath = $"Group/{groupName}",
                        TargetType = secEnabled ? "SecurityGroup" : "M365Group",
                        TargetId = groupId,
                        PrincipalEntraId = ownerId,
                        PrincipalEntraUpn = ownerUpn,
                        PrincipalSysName = ownerName,
                        PrincipalType = MapMemberType(ownerType, ownerUserType),
                        PrincipalRole = "Owner",
                        Through = "Direct",
                        AccessType = "Allow",
                        Tenure = "Permanent"
                    });
                }
            }
            catch (Exception ex)
            {
                context.ReportProgress($"Failed to get members of group '{groupName}': {ex.Message}", 2);
                memberFetchFailed = true;
            }

            // Yield whatever members we collected (even if partial due to error)
            foreach (var e in memberEntries) yield return e;

            if (memberFetchFailed)
            {
                context.FailTarget();
            }
            else
            {
                context.CompleteTarget();
            }

            groupsDone++;

            // Log progress periodically
            if (groupsDone % 50 == 0)
                context.ReportProgress($"Scanned {groupsDone}/{groups.Count} groups...", 4);
        }

        context.ReportProgress($"Completed scanning {groupsDone} groups.", 3);
    }

    /// <summary>
    /// Enumerate service principals once and build permission-GUID → name lookups, keyed both by
    /// the resource's appId (for resolving requiredResourceAccess) and its objectId (for resolving
    /// appRoleAssignments). Covers both app roles and delegated (oauth2) permission scopes.
    /// </summary>
    private async Task<(Dictionary<string, Dictionary<string, string>> byAppId,
                        Dictionary<string, Dictionary<string, string>> byObjectId)>
        BuildAppPermissionCachesAsync(CancellationToken ct)
    {
        var byAppId = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var byObjectId = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        await foreach (var sp in _graphClient.GetPaginatedAsync(
            "servicePrincipals?$select=id,appId,appRoles,oauth2PermissionScopes", ct: ct))
        {
            var spId = sp.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
            var appId = sp.TryGetProperty("appId", out var a) ? a.GetString() ?? "" : "";

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (sp.TryGetProperty("appRoles", out var ar) && ar.ValueKind == JsonValueKind.Array)
                foreach (var r in ar.EnumerateArray())
                {
                    var rid = r.TryGetProperty("id", out var ri) ? ri.GetString() ?? "" : "";
                    var val = r.TryGetProperty("value", out var rv) ? rv.GetString() ?? "" : "";
                    if (!string.IsNullOrEmpty(rid) && !string.IsNullOrEmpty(val)) map[rid] = val;
                }
            if (sp.TryGetProperty("oauth2PermissionScopes", out var sc) && sc.ValueKind == JsonValueKind.Array)
                foreach (var s in sc.EnumerateArray())
                {
                    var sid = s.TryGetProperty("id", out var si) ? si.GetString() ?? "" : "";
                    var val = s.TryGetProperty("value", out var sv) ? sv.GetString() ?? "" : "";
                    if (!string.IsNullOrEmpty(sid) && !string.IsNullOrEmpty(val)) map[sid] = val;
                }

            if (map.Count == 0) continue;
            if (!string.IsNullOrEmpty(appId)) byAppId[appId] = map;
            if (!string.IsNullOrEmpty(spId)) byObjectId[spId] = map;
        }

        return (byAppId, byObjectId);
    }

    private static PermissionEntry MapDirectoryRoleMember(JsonElement member, string roleName, string roleId)
    {
        var upn = member.TryGetProperty("userPrincipalName", out var u) ? u.GetString() ?? "" : "";
        var displayName = member.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
        var memberId = member.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
        var odataType = member.TryGetProperty("@odata.type", out var ot) ? ot.GetString() ?? "" : "";
        var userType = member.TryGetProperty("userType", out var ut) ? ut.GetString() ?? "" : "";

        return new PermissionEntry
        {
            TargetPath = $"DirectoryRole/{roleName}",
            TargetType = "DirectoryRole",
            TargetId = roleId,
            PrincipalEntraId = memberId,
            PrincipalEntraUpn = upn,
            PrincipalSysName = displayName,
            PrincipalType = MapMemberType(odataType, userType),
            PrincipalRole = roleName,
            Through = "DirectoryRoleAssignment",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    private static string MapMemberType(string odataType, string userType = "")
    {
        // Guests are ordinary users with userType=Guest. Surfacing them as "Guest" lets the
        // "Guest/external user access" policy fire on Entra/role/group members, not just the
        // SharePoint #ext# heuristic (A2).
        if (odataType == "#microsoft.graph.user" && string.Equals(userType, "Guest", StringComparison.OrdinalIgnoreCase))
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
}
