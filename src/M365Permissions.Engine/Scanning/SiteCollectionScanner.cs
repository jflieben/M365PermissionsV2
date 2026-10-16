using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans one SharePoint or OneDrive site collection: site collection admins, role assignments on the
/// root web, subsites and lists with unique permissions (SharePoint groups expanded to their members),
/// sharing links (from the SharingLinks.* groups) and Graph app grants. Shared by SharePointScanner and
/// OneDriveScanner. Individual files and folders with unique permissions are counted, not itemized.
/// </summary>
internal sealed class SiteCollectionScanner
{
    private const int MaxWebDepth = 8;
    private const int MaxLinkItemLookups = 250;

    private readonly SharePointRestClient _sp;
    private readonly string _scannerUpn;

    public SiteCollectionScanner(SharePointRestClient sp, string scannerUpn)
    {
        _sp = sp;
        _scannerUpn = scannerUpn;
    }

    /// <summary>Thread-safe tallies across parallel site scans, for the end-of-scan summary.</summary>
    public sealed class Stats
    {
        public long Attempted;
        public long AccessDenied;
        public long ElevationFailed;
        public long CleanupFailed;
    }

    public sealed class Options
    {
        public string RootTargetType { get; init; } = "Site";
        public bool IncludeGraphAppGrants { get; init; } = true;
        public bool IncludeSubsites { get; init; } = true;
    }

    /// <summary>Per-site state: SharePoint groups by id, collected once per site collection.</summary>
    private sealed class SiteState
    {
        public required SiteTarget Site { get; init; }
        public required ScanContext Context { get; init; }
        public required ChannelWriter<PermissionEntry> Writer { get; init; }
        public required Options Options { get; init; }
        public Dictionary<int, (string Title, List<JsonElement> Users)> Groups { get; } = new();
        public bool WasElevated { get; set; }
        public bool HadErrors { get; set; }
    }

    public async Task ScanAsync(SiteTarget site, ScanContext context, Options options, Stats stats,
        ChannelWriter<PermissionEntry> writer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var label = string.IsNullOrEmpty(site.Title) ? site.Url : site.Title;
        context.ReportProgress($"Scanning: {label}", 4);
        Interlocked.Increment(ref stats.Attempted);

        var state = new SiteState { Site = site, Context = context, Writer = writer, Options = options };

        // Temporary site collection admin: needed to read role assignments of sites the account isn't a member of.
        if (!string.IsNullOrEmpty(_scannerUpn))
        {
            try
            {
                var isAdmin = await _sp.IsCurrentUserSiteAdminAsync(site.Url, ct);
                if (isAdmin != true)
                {
                    await _sp.SetSiteAdminViaTenantAsync(site.Url, _scannerUpn, true, ct);
                    state.WasElevated = true;
                    context.ReportProgress($"Temporarily added {_scannerUpn} as site admin for: {label}", 4);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref stats.ElevationFailed);
                context.ReportProgress($"Could not make the account site admin of {label}: {ex.Message}", 3);
            }
        }

        try
        {
            // Groups first: role assignments reference them and SharingLinks.* groups are the link inventory.
            try
            {
                foreach (var group in await _sp.GetSiteGroupsWithUsersAsync(site.Url, ct))
                {
                    if (!group.TryGetProperty("Id", out var gid) || !gid.TryGetInt32(out var id)) continue;
                    var users = new List<JsonElement>();
                    if (group.TryGetProperty("Users", out var u) && u.ValueKind == JsonValueKind.Array)
                        users.AddRange(u.EnumerateArray());
                    state.Groups[id] = (SharePointPrincipal.ReadString(group, "Title"), users);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (IsDenied(ex))
                {
                    // Nothing below will be readable either.
                    Interlocked.Increment(ref stats.AccessDenied);
                    context.ReportProgress($"Skipping {label}: no access after elevation attempt ({Short(ex)}).", 2);
                    context.FailTarget();
                    return;
                }
                state.HadErrors = true;
                context.ReportProgress($"Failed to read SharePoint groups of {label}: {Short(ex)}", 2);
            }

            await EmitSiteAdminsAsync(state, ct);
            await ScanWebAsync(state, site.Url, isRoot: true, hasUnique: true, depth: 0, ct);
            await EmitSharingLinksAsync(state, ct);
            if (options.IncludeGraphAppGrants)
                await EmitGraphAppGrantsAsync(state, ct);

            context.AddInsight(InsightKeys.SitesScanned, 1);
            if (state.HadErrors) context.FailTarget();
            else context.CompleteTarget();
        }
        finally
        {
            // Always remove the temporary admin, also after cancellation (fresh token: the scan token may be cancelled).
            if (state.WasElevated)
            {
                using var cleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                try
                {
                    await _sp.SetSiteAdminViaTenantAsync(site.Url, _scannerUpn, false, cleanupCts.Token);
                    context.ReportProgress($"Removed temporary site admin from: {label}", 4);
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref stats.CleanupFailed);
                    context.ReportProgress($"WARNING: could not remove the temporary site admin from {site.Url}; remove {_scannerUpn} as site collection admin there manually: {Short(ex)}", 1);
                }
            }
        }
    }

    private async Task EmitSiteAdminsAsync(SiteState state, CancellationToken ct)
    {
        List<JsonElement> admins;
        try
        {
            admins = await _sp.GetSiteAdminsAsync(state.Site.Url, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.HadErrors = true;
            state.Context.ReportProgress($"Failed to get site collection admins of {state.Site.Url}: {Short(ex)}", 2);
            return;
        }

        foreach (var admin in admins)
        {
            var p = SharePointPrincipal.Describe(admin);
            if (p.IsSystem) continue;
            if (state.WasElevated && SharePointPrincipal.IsAccount(p.LoginName, _scannerUpn)) continue;
            await state.Writer.WriteAsync(NewEntry(state.Site.Url, state.Options.RootTargetType, state.Site.SiteId,
                p, "Site Collection Administrator", "Direct"), ct);
        }
    }

    private async Task ScanWebAsync(SiteState state, string webUrl, bool isRoot, bool hasUnique, int depth, CancellationToken ct)
    {
        var ctx = state.Context;

        if (hasUnique)
        {
            try
            {
                var targetType = isRoot ? state.Options.RootTargetType : "Subsite";
                foreach (var ra in await _sp.GetRoleAssignmentsAsync(webUrl, "_api/web", ct))
                    await EmitRoleAssignmentAsync(state, ra, webUrl, targetType, state.Site.SiteId, ct);
                if (!isRoot) ctx.AddInsight(InsightKeys.SubsitesWithUniquePermissions, 1);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                state.HadErrors = true;
                ctx.ReportProgress($"Failed to get role assignments of {webUrl}: {Short(ex)}", 2);
                if (isRoot) return;
            }
        }

        // Lists and libraries that break inheritance carry their own permissions.
        try
        {
            var uri = new Uri(webUrl);
            foreach (var list in await _sp.GetListsAsync(webUrl, ct))
            {
                var unique = list.TryGetProperty("HasUniqueRoleAssignments", out var hu) && hu.ValueKind == JsonValueKind.True;
                var hidden = list.TryGetProperty("Hidden", out var h) && h.ValueKind == JsonValueKind.True;
                if (!unique || hidden) continue;

                var listId = SharePointPrincipal.ReadString(list, "Id");
                var relUrl = list.TryGetProperty("RootFolder", out var rf) ? SharePointPrincipal.ReadString(rf, "ServerRelativeUrl") : "";
                var listUrl = string.IsNullOrEmpty(relUrl) ? $"{webUrl}/{SharePointPrincipal.ReadString(list, "Title")}" : $"{uri.Scheme}://{uri.Host}{relUrl}";
                var isLibrary = list.TryGetProperty("BaseType", out var bt) && bt.ValueKind == JsonValueKind.Number && bt.GetInt32() == 1;

                try
                {
                    foreach (var ra in await _sp.GetRoleAssignmentsAsync(webUrl, $"_api/web/lists(guid'{listId}')", ct))
                        await EmitRoleAssignmentAsync(state, ra, listUrl, isLibrary ? "Library" : "List", listId, ct);
                    ctx.AddInsight(InsightKeys.ListsWithUniquePermissions, 1);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    state.HadErrors = true;
                    ctx.ReportProgress($"Failed to get role assignments of {listUrl}: {Short(ex)}", 2);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.HadErrors = true;
            ctx.ReportProgress($"Failed to list the lists of {webUrl}: {Short(ex)}", 2);
        }

        if (!state.Options.IncludeSubsites || depth >= MaxWebDepth) return;

        // Subsites: recurse into all of them (an inheriting subsite can still hold unique lists).
        try
        {
            foreach (var web in await _sp.GetSubwebsAsync(webUrl, ct))
            {
                var url = SharePointPrincipal.ReadString(web, "Url");
                if (string.IsNullOrEmpty(url)) continue;
                var unique = web.TryGetProperty("HasUniqueRoleAssignments", out var hu) && hu.ValueKind == JsonValueKind.True;
                await ScanWebAsync(state, url.TrimEnd('/'), isRoot: false, hasUnique: unique, depth + 1, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.HadErrors = true;
            ctx.ReportProgress($"Failed to list subsites of {webUrl}: {Short(ex)}", 2);
        }
    }

    private async Task EmitRoleAssignmentAsync(SiteState state, JsonElement ra, string targetPath, string targetType,
        string targetId, CancellationToken ct)
    {
        if (!ra.TryGetProperty("Member", out var member)) return;
        if (!ra.TryGetProperty("RoleDefinitionBindings", out var bindings) || bindings.ValueKind != JsonValueKind.Array) return;

        var p = SharePointPrincipal.Describe(member);
        if (p.IsSystem) return;
        if (state.WasElevated && SharePointPrincipal.IsAccount(p.LoginName, _scannerUpn)) return;

        var roles = new List<string>();
        var limitedAccessOnly = true;
        foreach (var binding in bindings.EnumerateArray())
        {
            if (!SharePointPrincipal.IsLimitedAccess(binding)) limitedAccessOnly = false;
            var role = SharePointPrincipal.CanonicalRole(binding);
            if (role != null) roles.Add(role);
        }

        if (roles.Count == 0)
        {
            // Limited Access only: this principal has access to something further down (an item, folder or list).
            if (limitedAccessOnly && !p.Name.StartsWith("SharingLinks.", StringComparison.OrdinalIgnoreCase)
                && !p.Name.StartsWith("Limited Access System Group", StringComparison.OrdinalIgnoreCase))
                state.Context.AddInsight(InsightKeys.ItemLevelPrincipals, 1);
            return;
        }

        foreach (var role in roles)
        {
            await state.Writer.WriteAsync(NewEntry(targetPath, targetType, targetId, p, role, "Direct"), ct);

            // Expand SharePoint groups so each member's effective access is visible (and scored).
            if (p.TypeCode == 8 && member.TryGetProperty("Id", out var gid) && gid.TryGetInt32(out var groupId)
                && state.Groups.TryGetValue(groupId, out var group))
            {
                foreach (var user in group.Users)
                {
                    var mp = SharePointPrincipal.Describe(user);
                    if (mp.IsSystem) continue;
                    if (state.WasElevated && SharePointPrincipal.IsAccount(mp.LoginName, _scannerUpn)) continue;
                    var entry = NewEntry(targetPath, targetType, targetId, mp, role, "SharePointGroup");
                    entry.ParentId = group.Title;
                    await state.Writer.WriteAsync(entry, ct);
                }
            }
        }
    }

    /// <summary>
    /// Sharing links from the SharingLinks.&lt;itemUniqueId&gt;.&lt;kind&gt;.&lt;shareId&gt; groups SharePoint creates per link.
    /// Members are the specific recipients (or, for organization links, the people who used it).
    /// </summary>
    private async Task EmitSharingLinksAsync(SiteState state, CancellationToken ct)
    {
        var ctx = state.Context;
        var resolved = new Dictionary<string, (string Path, string Kind)?>(StringComparer.OrdinalIgnoreCase);
        var siteUri = new Uri(state.Site.Url);
        int lookups = 0;

        foreach (var (_, group) in state.Groups)
        {
            var link = ParseSharingLinkGroup(group.Title);
            if (link == null) continue;
            var (itemId, scope, role) = link.Value;

            ctx.AddInsight(InsightKeys.SharingLinks, 1);
            ctx.AddInsight(scope switch
            {
                "Anonymous" => InsightKeys.AnonymousLinks,
                "Organization" => InsightKeys.OrganizationLinks,
                _ => InsightKeys.SpecificPeopleLinks
            }, 1);

            if (!resolved.TryGetValue(itemId, out var item))
            {
                item = null;
                if (lookups < MaxLinkItemLookups)
                {
                    lookups++;
                    try { item = await _sp.ResolveItemAsync(state.Site.Url, itemId, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        ctx.ReportProgress($"Could not resolve shared item {itemId} in {state.Site.Url}: {Short(ex)}", 4);
                    }
                }
                resolved[itemId] = item;
                if (item == null) ctx.AddInsight(InsightKeys.UnresolvedLinkItems, 1);
            }

            var targetPath = item is { } it ? $"{siteUri.Scheme}://{siteUri.Host}{it.Path}" : $"{state.Site.Url} [shared item {itemId}]";
            var targetType = item?.Kind ?? "Item";

            if (scope == "Anonymous")
            {
                await state.Writer.WriteAsync(new PermissionEntry
                {
                    TargetPath = targetPath, TargetType = targetType, TargetId = itemId,
                    PrincipalSysId = group.Title, PrincipalSysName = "Anyone with the link",
                    PrincipalType = "Anonymous", PrincipalRole = role, Through = "SharingLink",
                    AccessType = "Allow", Tenure = "Permanent"
                }, ct);
                continue;
            }

            if (scope == "Organization")
            {
                await state.Writer.WriteAsync(new PermissionEntry
                {
                    TargetPath = targetPath, TargetType = targetType, TargetId = itemId,
                    PrincipalSysId = group.Title, PrincipalSysName = "Organization sharing link",
                    PrincipalType = "Everyone", PrincipalRole = role, Through = "SharingLink",
                    AccessType = "Allow", Tenure = "Permanent"
                }, ct);
            }

            var any = false;
            foreach (var user in group.Users)
            {
                var p = SharePointPrincipal.Describe(user);
                if (p.IsSystem) continue;
                any = true;
                var entry = NewEntry(targetPath, targetType, itemId, p, role, "SharingLink");
                entry.ParentId = scope == "Organization" ? "Organization sharing link" : "Specific people link";
                await state.Writer.WriteAsync(entry, ct);
            }

            if (!any && scope == "SpecificPeople")
            {
                await state.Writer.WriteAsync(new PermissionEntry
                {
                    TargetPath = targetPath, TargetType = targetType, TargetId = itemId,
                    PrincipalSysId = group.Title, PrincipalSysName = "Specific people link (no recipients listed)",
                    PrincipalType = "Unknown", PrincipalRole = role, Through = "SharingLink",
                    AccessType = "Allow", Tenure = "Permanent"
                }, ct);
            }
        }
    }

    /// <summary>Parses "SharingLinks.&lt;itemId&gt;.&lt;kind&gt;.&lt;shareId&gt;" into item id, scope and role.</summary>
    internal static (string ItemId, string Scope, string Role)? ParseSharingLinkGroup(string title)
    {
        if (!title.StartsWith("SharingLinks.", StringComparison.OrdinalIgnoreCase)) return null;
        var parts = title.Split('.');
        if (parts.Length < 3 || !Guid.TryParse(parts[1], out var itemId)) return null;
        var kind = parts[2];

        var scope = kind.StartsWith("Anonymous", StringComparison.OrdinalIgnoreCase) ? "Anonymous"
            : kind.StartsWith("Organization", StringComparison.OrdinalIgnoreCase) ? "Organization"
            : "SpecificPeople";
        var role = kind.Contains("Edit", StringComparison.OrdinalIgnoreCase) ? "Edit"
            : kind.Contains("Review", StringComparison.OrdinalIgnoreCase) ? "Review"
            : kind.Contains("RestrictedView", StringComparison.OrdinalIgnoreCase) ? "View Only"
            : kind.Contains("View", StringComparison.OrdinalIgnoreCase) ? "Read"
            : "View or Edit";
        return (itemId.ToString(), scope, role);
    }

    private async Task EmitGraphAppGrantsAsync(SiteState state, CancellationToken ct)
    {
        var ctx = state.Context;
        try
        {
            var graphId = state.Site.GraphSiteId;
            if (string.IsNullOrEmpty(graphId))
                graphId = state.Site.GraphSiteId = await _sp.ResolveGraphSiteIdAsync(state.Site.Url, ct);
            if (string.IsNullOrEmpty(graphId)) return;

            await foreach (var perm in _sp.GetSitePermissionsAsync(graphId, ct))
            {
                var full = perm;
                // The list call can omit roles; the single-permission GET returns them.
                if (!perm.TryGetProperty("roles", out var r) || r.ValueKind != JsonValueKind.Array || r.GetArrayLength() == 0)
                {
                    var id = perm.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
                    if (!string.IsNullOrEmpty(id) && await _sp.GetSitePermissionAsync(graphId, id, ct) is { } single)
                        full = single;
                }
                foreach (var entry in MapGraphSitePermission(full, state.Site.Url, state.Site.SiteId))
                    await state.Writer.WriteAsync(entry, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (ex.Message.Contains("notSupported", StringComparison.OrdinalIgnoreCase))
                ctx.ReportProgress($"Graph site permissions not supported for {state.Site.Url}.", 4);
            else
            {
                state.HadErrors = true;
                ctx.ReportProgress($"Failed to get app grants (Graph site permissions) of {state.Site.Url}: {Short(ex)}", 2);
            }
        }
    }

    internal static IEnumerable<PermissionEntry> MapGraphSitePermission(JsonElement perm, string siteUrl, string siteId)
    {
        var roles = new List<string>();
        if (perm.TryGetProperty("roles", out var r) && r.ValueKind == JsonValueKind.Array)
            foreach (var role in r.EnumerateArray())
                roles.Add(role.GetString() ?? "");
        var roleText = roles.Count > 0 ? string.Join(", ", roles) : "Unknown";

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in new[] { "grantedToIdentitiesV2", "grantedToIdentities" })
        {
            if (!perm.TryGetProperty(prop, out var identities) || identities.ValueKind != JsonValueKind.Array) continue;
            foreach (var identity in identities.EnumerateArray())
            {
                if (!identity.TryGetProperty("application", out var app)) continue;
                var appId = app.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
                var name = app.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
                if (string.IsNullOrEmpty(appId) && string.IsNullOrEmpty(name)) continue;
                if (!seen.Add(appId + "|" + name)) continue;
                yield return new PermissionEntry
                {
                    TargetPath = siteUrl, TargetType = "Site", TargetId = siteId,
                    PrincipalEntraId = appId, PrincipalSysId = appId, PrincipalSysName = name,
                    PrincipalType = "Application", PrincipalRole = roleText, Through = "GraphSitePermission",
                    AccessType = "Allow", Tenure = "Permanent"
                };
            }
        }
    }

    private static PermissionEntry NewEntry(string targetPath, string targetType, string targetId,
        SharePointPrincipalInfo p, string role, string through) => new()
    {
        TargetPath = targetPath,
        TargetType = targetType,
        TargetId = targetId,
        PrincipalEntraId = p.EntraId,
        PrincipalEntraUpn = p.Upn,
        PrincipalSysId = p.LoginName,
        PrincipalSysName = p.Name,
        PrincipalType = p.Type,
        PrincipalRole = role,
        Through = through,
        AccessType = "Allow",
        Tenure = "Permanent"
    };

    private static bool IsDenied(Exception ex)
        => ex is HttpRequestException { StatusCode: HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized };

    private static string Short(Exception ex) => ex.Message.Length <= 300 ? ex.Message : ex.Message[..300] + "...";
}
