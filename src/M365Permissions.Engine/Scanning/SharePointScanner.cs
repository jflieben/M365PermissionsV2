using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans SharePoint Online site collections: admins, site, subsite and list permissions, SharePoint
/// group members, sharing links and app grants. See <see cref="SiteCollectionScanner"/>.
/// </summary>
public sealed class SharePointScanner : IScanProvider
{
    public string Category => "SharePoint";

    private readonly SharePointRestClient _spClient;
    private readonly GraphClient _graphClient;
    private readonly DelegatedAuth _auth;

    // System site collections: no user permissions worth reporting, and elevating on them is noise.
    private static readonly string[] SkippedTemplatePrefixes = { "REDIRECTSITE", "APPCATALOG", "SPSMSITEHOST", "SPSPERS" };
    private static readonly string[] SkippedRootPaths = { "/sites/appcatalog", "/sites/contenttypehub", "/portals/hub" };

    public SharePointScanner(SharePointRestClient spClient, GraphClient graphClient, DelegatedAuth auth)
    {
        _spClient = spClient;
        _graphClient = graphClient;
        _auth = auth;
    }

    internal static bool IsSystemSite(SiteTarget site)
    {
        if (string.IsNullOrEmpty(site.Url)) return true;
        if (site.Url.Contains("-my.sharepoint.com", StringComparison.OrdinalIgnoreCase)) return true; // OneDriveScanner
        if (site.Url.Contains("/contentstorage/", StringComparison.OrdinalIgnoreCase)) return true;    // SharePoint Embedded
        foreach (var prefix in SkippedTemplatePrefixes)
            if (site.Template.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        if (!Uri.TryCreate(site.Url, UriKind.Absolute, out var uri)) return true;
        var path = uri.AbsolutePath.TrimEnd('/');
        foreach (var skipped in SkippedRootPaths)
            if (path.Equals(skipped, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var rootUrl = _auth.SharePointRootUrl;
        if (!string.IsNullOrEmpty(rootUrl))
            context.ReportProgress($"Detected tenant SharePoint root URL: {rootUrl} (admin: {_auth.SharePointAdminUrl})", 3);

        context.ReportProgress("Enumerating SharePoint sites...", 3);
        var sites = await EnumerateSitesAsync(context, ct);

        var skippedLocked = sites.Where(s => s.IsNoAccess).ToList();
        var skippedArchived = sites.Where(s => s.IsArchived && !s.IsNoAccess).ToList();
        var targets = sites.Where(s => !s.IsNoAccess && !s.IsArchived && !IsSystemSite(s)).ToList();
        if (skippedLocked.Count > 0)
        {
            context.AddInsight(InsightKeys.LockedSites, skippedLocked.Count);
            context.ReportProgress($"{skippedLocked.Count} site(s) are locked (NoAccess) and cannot be read by anyone; not scanned: " +
                string.Join(", ", skippedLocked.Take(10).Select(s => s.Url)) + (skippedLocked.Count > 10 ? ", ..." : ""), 2);
        }
        if (skippedArchived.Count > 0)
        {
            context.AddInsight(InsightKeys.ArchivedSites, skippedArchived.Count);
            context.ReportProgress($"{skippedArchived.Count} archived site(s) are not readable until reactivated; not scanned.", 2);
        }

        context.SetTotalTargets(targets.Count);
        context.ReportProgress($"Found {targets.Count} site collections to scan.", 3);

        var stats = new SiteCollectionScanner.Stats();
        var siteScanner = new SiteCollectionScanner(_spClient, _auth.UserPrincipalName ?? "");
        var options = new SiteCollectionScanner.Options { RootTargetType = "Site" };
        var dop = context.Config?.MaxThreads ?? 5;

        // One target per site collection, so elevation happens once per collection and never races.
        await foreach (var entry in ParallelScan.RunAsync(targets, dop,
            (site, writer, tok) => siteScanner.ScanAsync(site, context, options, stats, writer, tok), ct))
        {
            yield return entry;
        }

        ReportSummary(context, stats);
    }

    /// <summary>
    /// Union of the tenant admin API (every site, needs SharePoint Administrator) and Graph search (sites the
    /// account can see). Teams private and shared channel sites are asked for explicitly.
    /// </summary>
    private async Task<List<SiteTarget>> EnumerateSitesAsync(ScanContext context, CancellationToken ct)
    {
        var byUrl = new Dictionary<string, SiteTarget>(StringComparer.OrdinalIgnoreCase);
        var adminAvailable = true;

        try
        {
            foreach (var site in await _spClient.GetTenantSitesAsync(includePersonalSites: false, ct: ct))
                byUrl.TryAdd(site.Url, site);
            foreach (var template in new[] { "TEAMCHANNEL#0", "TEAMCHANNEL#1" })
            {
                try
                {
                    foreach (var site in await _spClient.GetTenantSitesAsync(includePersonalSites: false, template, ct))
                        byUrl.TryAdd(site.Url, site);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    context.ReportProgress($"Could not list {template} channel sites via the admin API: {ex.Message}", 4);
                }
            }
            context.ReportProgress($"Tenant admin API returned {byUrl.Count} site collections.", 3);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            adminAvailable = false;
            context.ReportProgress($"Tenant site list (SharePoint admin API) not available: {ex.Message}", 2);
        }

        var searchAdded = 0;
        try
        {
            foreach (var site in await _spClient.SearchSitesAsync(ct))
            {
                if (byUrl.TryGetValue(site.Url, out var existing))
                {
                    if (string.IsNullOrEmpty(existing.GraphSiteId)) existing.GraphSiteId = site.GraphSiteId;
                }
                else
                {
                    byUrl[site.Url] = site;
                    searchAdded++;
                }
            }
            if (adminAvailable && searchAdded > 0)
                context.ReportProgress($"Graph search found {searchAdded} additional site collection(s).", 3);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (!adminAvailable)
                throw new InvalidOperationException($"Could not enumerate SharePoint sites: {ex.Message}", ex);
            context.ReportProgress($"Graph site search failed (admin API list is used): {ex.Message}", 3);
        }

        if (!adminAvailable)
            context.MarkPartial("the site list came from search, which only returns sites the signed-in account can already open. " +
                "Activate SharePoint Administrator (or Global Administrator) and scan again for every site.");

        return byUrl.Values.ToList();
    }

    private static void ReportSummary(ScanContext context, SiteCollectionScanner.Stats stats)
    {
        // One actionable summary instead of a wall of per-site 403s.
        var attempted = Interlocked.Read(ref stats.Attempted);
        var denied = Interlocked.Read(ref stats.AccessDenied);
        var elevationFailed = Interlocked.Read(ref stats.ElevationFailed);
        var cleanupFailed = Interlocked.Read(ref stats.CleanupFailed);

        if (attempted > 0 && denied > 0)
        {
            if (denied >= attempted)
                context.ReportProgress(
                    $"Permission summary: none of the {attempted} sites could be read. This almost always means the " +
                    "connected account is not an active SharePoint Administrator or Global Administrator, so it cannot " +
                    "make itself site collection admin. Assign or activate (PIM) that role and start the scan again.", 1);
            else
                context.ReportProgress(
                    $"Permission summary: {denied} of {attempted} sites could not be read (elevation failed on {elevationFailed}). " +
                    "Those sites need the connected account to be SharePoint Administrator (or site collection admin).", 2);
        }

        if (cleanupFailed > 0)
            context.ReportProgress($"{cleanupFailed} temporary site admin assignment(s) could not be removed; see the warnings above.", 1);
    }
}
