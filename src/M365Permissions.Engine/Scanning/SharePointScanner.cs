using System.Text.Json;
using System.Threading.Channels;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans SharePoint Online sites for permissions using Graph API + SharePoint REST.
/// Replaces V1's PnP.PowerShell-based get-SpOPermissions.ps1.
/// </summary>
public sealed class SharePointScanner : IScanProvider
{
    public string Category => "SharePoint";

    private readonly SharePointRestClient _spClient;
    private readonly GraphClient _graphClient;
    private readonly DelegatedAuth _auth;

    // Graph's getAllSites endpoint does not return the site's WebTemplate, so we filter the
    // clearly-system site collections by URL instead (B10). This avoids wasted scan time,
    // noisy results, and — importantly — temporary-admin elevation writes on system sites.
    // OneDrive personal sites (on the -my host) are excluded here because OneDriveScanner
    // covers them; scanning them again in the SharePoint pass would double-elevate.
    private static readonly string[] SystemSiteUrlMarkers =
    {
        "/sites/appcatalog",
        "/sites/contenttypehub",
        "/portals/hub"
    };

    private static bool IsSystemSite(string webUrl)
    {
        if (string.IsNullOrEmpty(webUrl)) return true;
        if (webUrl.Contains("-my.sharepoint.com", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var marker in SystemSiteUrlMarkers)
            if (webUrl.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public SharePointScanner(SharePointRestClient spClient, GraphClient graphClient, DelegatedAuth auth)
    {
        _spClient = spClient;
        _graphClient = graphClient;
        _auth = auth;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // Surface the tenant root that was detected from Graph sites/root (webUrl → {tenant}), so
        // the log makes it obvious which tenant/host this scan (and any admin elevation) targets.
        var rootUrl = _auth.SharePointRootUrl;
        if (!string.IsNullOrEmpty(rootUrl))
            context.ReportProgress($"Detected tenant SharePoint root URL: {rootUrl} (admin: {_auth.SharePointAdminUrl})", 3);

        context.ReportProgress("Enumerating SharePoint sites...", 3);

        // Collect all sites first so we know the total
        var sites = new List<JsonElement>();
        await foreach (var site in _spClient.GetAllSitesAsync(ct))
        {
            sites.Add(site);
        }

        context.SetTotalTargets(sites.Count);
        context.ReportProgress($"Found {sites.Count} sites to scan.", 3);

        // Scan sites in parallel (P1). Per-site work (elevation + REST round-trips) dominates
        // wall-clock, so bounded concurrency turns days into hours on large tenants. Graph/SP
        // calls remain governed by the shared throttle manager.
        var stats = new SiteAccessStats();
        var dop = context.Config?.MaxThreads ?? 5;
        await foreach (var entry in ParallelScan.RunAsync(sites, dop,
            (site, writer, tok) => ScanSiteAsync(site, context, stats, writer, tok), ct))
        {
            yield return entry;
        }

        // One actionable summary instead of a wall of per-site 403s. When most/all sites deny
        // access, the near-certain cause is that the connected account lacks the SharePoint
        // Administrator (or Global Administrator) role needed to self-elevate as site admin.
        var attempted = Interlocked.Read(ref stats.Attempted);
        var denied = Interlocked.Read(ref stats.AccessDenied);
        var elevationFailed = Interlocked.Read(ref stats.ElevationFailed);
        if (attempted > 0 && denied > 0)
        {
            if (denied >= attempted)
                context.ReportProgress(
                    $"Permission summary: 0 of {attempted} sites returned permission data. The connected " +
                    "account could not read any site — this almost always means it is not a SharePoint " +
                    "Administrator (or Global Administrator), so it cannot temporarily elevate to site " +
                    "collection admin. Grant that role and re-run for complete results.", 1);
            else
                context.ReportProgress(
                    $"Permission summary: {denied} of {attempted} sites returned no permission data " +
                    $"(elevation failed on {elevationFailed}). Those sites need the connected account to be " +
                    "SharePoint Administrator (or site collection admin) for a complete scan.", 2);
        }
    }

    /// <summary>Thread-safe tallies across the parallel per-site scan, used for the end-of-scan summary.</summary>
    private sealed class SiteAccessStats
    {
        public long Attempted;       // sites we actually tried to read (post system-site filter)
        public long AccessDenied;    // sites where neither admins nor role assignments were readable
        public long ElevationFailed; // sites where temporary site-admin elevation could not be applied
    }

    private async Task ScanSiteAsync(JsonElement site, ScanContext context, SiteAccessStats stats,
        ChannelWriter<PermissionEntry> writer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var webUrl = site.TryGetProperty("webUrl", out var wUrl) ? wUrl.GetString() ?? "" : "";
        var siteId = site.TryGetProperty("id", out var sId) ? sId.GetString() ?? "" : "";
        var displayName = site.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? webUrl : webUrl;

        if (string.IsNullOrEmpty(webUrl) || IsSystemSite(webUrl))
        {
            context.CompleteTarget();
            return;
        }

        context.ReportProgress($"Scanning: {displayName}", 4);
        Interlocked.Increment(ref stats.Attempted);

        // Site collection admin elevation should target the site collection root, not a subsite URL.
        var elevationUrl = GetSiteCollectionRootUrl(webUrl);
        var siteCollectionId = SharePointRestClient.TryExtractSiteCollectionId(siteId);

        // --- Temporarily add scanning user as site admin if needed (like V1) ---
        bool wasAdded = false;
        bool wasAddedViaTenant = false;
        var userUpn = _auth.UserPrincipalName;

        if (!string.IsNullOrEmpty(userUpn))
        {
            try
            {
                wasAdded = await _spClient.EnsureSiteAdminAsync(elevationUrl, userUpn, ct);
                if (wasAdded)
                    context.ReportProgress($"Temporarily added {userUpn} as site admin for: {displayName}", 4);
            }
            catch (Exception ex)
            {
                // Fallback to tenant admin API for site collections where direct site REST elevation is blocked.
                if (ShouldTryTenantElevationFallback(ex))
                {
                    try
                    {
                        wasAdded = await _spClient.EnsureSiteAdminViaTenantAsync(elevationUrl, userUpn, ct, siteCollectionId);
                        wasAddedViaTenant = wasAdded;
                        if (wasAdded)
                            context.ReportProgress($"Temporarily added {userUpn} as site admin via tenant API for: {displayName}", 4);
                    }
                    catch (Exception tenantEx)
                    {
                        Interlocked.Increment(ref stats.ElevationFailed);
                        context.ReportProgress($"Could not ensure site admin for {displayName}: {tenantEx.Message}", 3);
                    }
                }
                else
                {
                    Interlocked.Increment(ref stats.ElevationFailed);
                    context.ReportProgress($"Could not ensure site admin for {displayName}: {ex.Message}", 3);
                }
            }
        }

        try
        {
            // --- Site admins ---
            List<JsonElement> admins;
            bool adminQueryUnauthorized = false;
            try
            {
                admins = await _spClient.GetSiteAdminsAsync(webUrl, ct);
            }
            catch (Exception ex)
            {
                context.ReportProgress($"Failed to get admins for {displayName}: {ex.Message}", 2);
                adminQueryUnauthorized = IsUnauthorized(ex);
                admins = new();
            }

            var scannerFilter = wasAdded ? (userUpn ?? "") : "";

            foreach (var admin in admins)
            {
                var entry = MapSiteAdmin(admin, webUrl, siteId, scannerFilter);
                if (entry != null) await writer.WriteAsync(entry, ct);
            }

            // --- Role assignments ---
            List<JsonElement> roleAssignments;
            bool roleQueryUnauthorized = false;
            try
            {
                roleAssignments = await _spClient.GetRoleAssignmentsAsync(webUrl, ct);
            }
            catch (Exception ex)
            {
                context.ReportProgress($"Failed to get role assignments for {displayName}: {ex.Message}", 2);
                roleQueryUnauthorized = IsUnauthorized(ex);
                roleAssignments = new();
            }

            // If we cannot query either admins or role assignments due authorization,
            // skip this site gracefully and continue with the scan.
            if (adminQueryUnauthorized && roleQueryUnauthorized)
            {
                Interlocked.Increment(ref stats.AccessDenied);
                context.ReportProgress($"Skipping {displayName}: no SharePoint REST access after elevation attempt.", 2);
                context.CompleteTarget();
                return;
            }

            foreach (var ra in roleAssignments)
            {
                var entries = MapRoleAssignment(ra, webUrl, siteId, scannerFilter);
                foreach (var entry in entries)
                    await writer.WriteAsync(entry, ct);
            }

            // --- Graph site permissions (apps, etc.) ---
            // Graph sites/{siteId}/permissions is only supported for root sites in a site collection,
            // not subsites. Detect subsites by checking if webUrl has a path beyond /sites/{name}.
            var isSubsite = IsSubsite(webUrl);
            if (!isSubsite)
            {
                try
                {
                    await foreach (var perm in _spClient.GetSitePermissionsAsync(siteId, ct))
                    {
                        var entry = MapGraphSitePermission(perm, webUrl, siteId);
                        if (entry != null) await writer.WriteAsync(entry, ct);
                    }
                }
                catch (Exception ex)
                {
                    if (IsGraphSitePermissionsNotSupported(ex))
                        context.ReportProgress($"Graph site permissions endpoint not supported for {displayName}; skipping app-only grants for this site.", 4);
                    else
                        context.ReportProgress($"Failed to get Graph permissions for {displayName}: {ex.Message}", 4);
                }
            }

            context.CompleteTarget();
        }
        finally
        {
            // Always remove temp admin rights, even if scan threw an exception or was
            // cancelled. Use a fresh short-timeout token (not the scan token, which may
            // already be cancelled) so cleanup still runs and the scanning account is not
            // left elevated as Site Collection Admin (B8).
            if (wasAdded && !string.IsNullOrEmpty(userUpn))
            {
                using var cleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var cleanupCt = cleanupCts.Token;
                try
                {
                    if (wasAddedViaTenant)
                        await _spClient.RemoveSiteAdminViaTenantAsync(elevationUrl, userUpn, cleanupCt, siteCollectionId);
                    else
                        await _spClient.RemoveSiteAdminAsync(elevationUrl, userUpn, cleanupCt);

                    context.ReportProgress($"Removed temporary site admin from: {displayName}", 4);
                }
                catch (Exception ex)
                {
                    context.ReportProgress($"WARNING: Failed to remove temp admin from {displayName} — account may remain elevated on {elevationUrl}: {ex.Message}", 2);
                }
            }
        }
    }

    private static PermissionEntry? MapSiteAdmin(JsonElement admin, string webUrl, string siteId, string scannerUpn)
    {
        var loginName = admin.TryGetProperty("LoginName", out var ln) ? ln.GetString() ?? "" : "";
        var title = admin.TryGetProperty("Title", out var t) ? t.GetString() ?? "" : "";
        var email = admin.TryGetProperty("Email", out var e) ? e.GetString() ?? "" : "";
        var id = admin.TryGetProperty("Id", out var i) ? i.GetInt32().ToString() : "";

        // Skip system accounts
        if (loginName.Contains("SHAREPOINT\\system", StringComparison.OrdinalIgnoreCase))
            return null;

        // Omit scanning identity (transient admin)
        if (!string.IsNullOrEmpty(scannerUpn) && email.Equals(scannerUpn, StringComparison.OrdinalIgnoreCase))
            return null;

        return new PermissionEntry
        {
            TargetPath = webUrl,
            TargetType = "Site",
            TargetId = siteId,
            PrincipalEntraUpn = email,
            PrincipalSysId = id,
            PrincipalSysName = title,
            PrincipalType = DeterminePrincipalType(loginName),
            PrincipalRole = "Site Collection Administrator",
            Through = "Direct",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    private static List<PermissionEntry> MapRoleAssignment(JsonElement ra, string webUrl, string siteId, string scannerUpn)
    {
        var entries = new List<PermissionEntry>();

        if (!ra.TryGetProperty("Member", out var member)) return entries;
        if (!ra.TryGetProperty("RoleDefinitionBindings", out var bindings)) return entries;

        var principalName = member.TryGetProperty("Title", out var t) ? t.GetString() ?? "" : "";
        var principalLogin = member.TryGetProperty("LoginName", out var ln) ? ln.GetString() ?? "" : "";
        var principalId = member.TryGetProperty("Id", out var i) ? i.GetInt32().ToString() : "";

        // Omit scanning identity
        if (!string.IsNullOrEmpty(scannerUpn) && principalLogin.Contains(scannerUpn, StringComparison.OrdinalIgnoreCase))
            return entries;

        foreach (var binding in bindings.EnumerateArray())
        {
            var roleName = binding.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
            var roleId = binding.TryGetProperty("Id", out var rid) ? rid.GetInt64() : 0;
            var hidden = binding.TryGetProperty("Hidden", out var h) && h.ValueKind == JsonValueKind.True;

            // Skip system/hidden roles by internal ID (locale-independent):
            // 1073741825 = Limited Access, 1073741924 = Web-Only Limited Access
            if (roleId == 1073741825 || roleId == 1073741924 || hidden)
                continue;

            entries.Add(new PermissionEntry
            {
                TargetPath = webUrl,
                TargetType = "Site",
                TargetId = siteId,
                PrincipalSysId = principalId,
                PrincipalSysName = principalName,
                PrincipalType = DeterminePrincipalType(principalLogin),
                PrincipalRole = roleName,
                Through = "Direct",
                AccessType = "Allow",
                Tenure = "Permanent"
            });
        }

        return entries;
    }

    private static PermissionEntry? MapGraphSitePermission(JsonElement perm, string webUrl, string siteId)
    {
        var roles = perm.TryGetProperty("roles", out var r) ? r : default;
        var grantedTo = perm.TryGetProperty("grantedToIdentitiesV2", out var g) ? g : default;

        if (roles.ValueKind != JsonValueKind.Array) return null;

        var roleList = new List<string>();
        foreach (var role in roles.EnumerateArray())
            roleList.Add(role.GetString() ?? "");

        var displayName = "";
        var appId = "";
        if (grantedTo.ValueKind == JsonValueKind.Array)
        {
            foreach (var identity in grantedTo.EnumerateArray())
            {
                if (identity.TryGetProperty("application", out var app))
                {
                    displayName = app.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
                    appId = app.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
                    break;
                }
            }
        }

        if (string.IsNullOrEmpty(displayName) && string.IsNullOrEmpty(appId))
            return null;

        return new PermissionEntry
        {
            TargetPath = webUrl,
            TargetType = "Site",
            TargetId = siteId,
            PrincipalEntraId = appId,
            PrincipalSysName = displayName,
            PrincipalType = "Application",
            PrincipalRole = string.Join(", ", roleList),
            Through = "GraphSitePermission",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    private static string DeterminePrincipalType(string loginName)
    {
        if (string.IsNullOrEmpty(loginName)) return "Unknown";
        // Order matters: more specific checks first
        // Users: i:0#.f|membership|user@domain.com
        if (loginName.StartsWith("i:0#.f|membership|", StringComparison.OrdinalIgnoreCase)) return "Internal User";
        // External users always contain #ext#
        if (loginName.Contains("#ext#", StringComparison.OrdinalIgnoreCase)) return "External User";
        // Security groups: c:0t.c|tenant|<guid> or c:0o.c|federateddirectoryclaimprovider|<guid>
        if (loginName.StartsWith("c:0t.c|tenant|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        if (loginName.Contains("|federateddirectoryclaimprovider|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        // SharePoint groups: c:0-.f|rolemanager|spo-grid-all-users/...
        if (loginName.Contains("c:0-.f|rolemanager|", StringComparison.OrdinalIgnoreCase)) return "SharePoint Group";
        // Everyone / Everyone except external: c:0(.s|true (all authenticated)
        if (loginName.StartsWith("c:0(.s|true", StringComparison.OrdinalIgnoreCase)) return "Everyone";
        // Remaining membership claims are typically groups
        if (loginName.Contains("|membership|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        return "Unknown";
    }

    private static bool IsUnauthorized(Exception ex)
    {
        if (ex is HttpRequestException hre)
        {
            return hre.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.Unauthorized;
        }

        return ex.Message.Contains("403", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("UnauthorizedAccessException", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldTryTenantElevationFallback(Exception ex)
    {
        if (IsUnauthorized(ex))
            return true;

        // Some SPO endpoints return 500 SPException instead of 403 when elevation is required.
        return ex.Message.Contains("You need to be a site collection administrator to set this property", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("SPException", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsGraphSitePermissionsNotSupported(Exception ex)
    {
        return ex.Message.Contains("notSupported", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("Operation not supported", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Detect if a URL is a subsite (has path segments beyond /sites/{name}).</summary>
    private static bool IsSubsite(string webUrl)
    {
        if (string.IsNullOrEmpty(webUrl)) return false;
        try
        {
            var uri = new Uri(webUrl);
            var path = uri.AbsolutePath.TrimEnd('/');
            // Root sites: / or /sites/SiteName or /teams/TeamName (2 segments under /sites/ or /teams/)
            // Subsites: /sites/SiteName/SubsiteName (3+ segments)
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            // /sites/name = 2 segments, /sites/name/sub = 3+ segments (subsite)
            return segments.Length > 2;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// For elevation actions, target the site collection root URL instead of subsite URLs.
    /// Example: https://tenant.sharepoint.com/sites/A/B/C -> https://tenant.sharepoint.com/sites/A
    /// </summary>
    private static string GetSiteCollectionRootUrl(string webUrl)
    {
        if (string.IsNullOrWhiteSpace(webUrl)) return webUrl;

        try
        {
            var uri = new Uri(webUrl);
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

            if (segments.Length >= 2 &&
                (segments[0].Equals("sites", StringComparison.OrdinalIgnoreCase)
                 || segments[0].Equals("teams", StringComparison.OrdinalIgnoreCase)
                 || segments[0].Equals("personal", StringComparison.OrdinalIgnoreCase)))
            {
                return $"{uri.Scheme}://{uri.Host}/{segments[0]}/{segments[1]}";
            }

            return webUrl.TrimEnd('/');
        }
        catch
        {
            return webUrl;
        }
    }
}
