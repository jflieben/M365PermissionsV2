using System.Collections.Concurrent;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans OneDrive for Business personal sites with the same per-site scan as SharePoint: admins,
/// unique permissions on the site and its libraries, and sharing links at any depth.
/// </summary>
public sealed class OneDriveScanner : IScanProvider
{
    public string Category => "OneDrive";

    private readonly GraphClient _graphClient;
    private readonly SharePointRestClient _spClient;
    private readonly DelegatedAuth _auth;

    public OneDriveScanner(GraphClient graphClient, SharePointRestClient spClient, DelegatedAuth auth)
    {
        _graphClient = graphClient;
        _spClient = spClient;
        _auth = auth;
    }

    internal static bool IsPersonalSite(SiteTarget site)
        => site.Template.StartsWith("SPSPERS", StringComparison.OrdinalIgnoreCase)
           || site.Url.Contains("-my.sharepoint.com/personal/", StringComparison.OrdinalIgnoreCase);

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var tenantName = _auth.SharePointTenantName;
        if (!string.IsNullOrEmpty(tenantName))
            context.ReportProgress(
                $"Detected tenant SharePoint root URL: {_auth.SharePointRootUrl} (OneDrive host: https://{tenantName}-my.sharepoint.com, admin: {_auth.SharePointAdminUrl})", 3);

        context.ReportProgress("Enumerating OneDrive personal sites...", 3);
        var sites = await EnumerateOneDrivesAsync(context, ct);

        var locked = sites.Count(s => s.IsNoAccess);
        if (locked > 0)
        {
            context.AddInsight(InsightKeys.LockedSites, locked);
            context.ReportProgress($"{locked} OneDrive(s) are locked (NoAccess) and cannot be read; not scanned.", 2);
        }
        var targets = sites.Where(s => !s.IsNoAccess).ToList();

        context.SetTotalTargets(targets.Count);
        context.ReportProgress($"Found {targets.Count} OneDrive sites to scan.", 3);

        var stats = new SiteCollectionScanner.Stats();
        var siteScanner = new SiteCollectionScanner(_spClient, _auth.UserPrincipalName ?? "");
        var options = new SiteCollectionScanner.Options { RootTargetType = "OneDrive", IncludeGraphAppGrants = false, IncludeSubsites = false };
        var dop = context.Config?.MaxThreads ?? 5;

        await foreach (var entry in ParallelScan.RunAsync(targets, dop,
            (site, writer, tok) => siteScanner.ScanAsync(site, context, options, stats, writer, tok), ct))
        {
            yield return entry;
        }

        var denied = Interlocked.Read(ref stats.AccessDenied);
        if (denied > 0)
            context.ReportProgress($"{denied} of {Interlocked.Read(ref stats.Attempted)} OneDrives could not be read. Reading other users' " +
                "OneDrives needs an active SharePoint Administrator (or Global Administrator) role.", denied >= targets.Count ? 1 : 2);
        var cleanupFailed = Interlocked.Read(ref stats.CleanupFailed);
        if (cleanupFailed > 0)
            context.ReportProgress($"{cleanupFailed} temporary OneDrive admin assignment(s) could not be removed; see the warnings above.", 1);
    }

    /// <summary>
    /// Every OneDrive via the tenant admin API (includes leavers and unlicensed users). Without it, falls back
    /// to resolving the drives of enabled, licensed users through Graph and marks the category partial.
    /// </summary>
    private async Task<List<SiteTarget>> EnumerateOneDrivesAsync(ScanContext context, CancellationToken ct)
    {
        try
        {
            var all = await _spClient.GetTenantSitesAsync(includePersonalSites: true, ct: ct);
            return all.Where(IsPersonalSite)
                .GroupBy(s => s.Url, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"OneDrive list (SharePoint admin API) not available: {ex.Message}", 2);
        }

        var users = new List<(string Id, string DisplayName)>();
        try
        {
            await foreach (var user in _graphClient.GetPaginatedAsync(
                "users?$select=id,displayName,assignedLicenses&$filter=accountEnabled eq true&$count=true",
                eventualConsistency: true, ct: ct))
            {
                var id = user.TryGetProperty("id", out var uid) ? uid.GetString() ?? "" : "";
                var licensed = user.TryGetProperty("assignedLicenses", out var lic) && lic.GetArrayLength() > 0;
                if (!string.IsNullOrEmpty(id) && licensed)
                    users.Add((id, user.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : ""));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException($"Failed to enumerate users: {ex.Message}", ex);
        }

        var found = new ConcurrentBag<SiteTarget>();
        var failed = 0;
        await Parallel.ForEachAsync(users, new ParallelOptions { MaxDegreeOfParallelism = context.Config?.MaxThreads ?? 5, CancellationToken = ct },
            async (user, tok) =>
            {
                try
                {
                    var drive = await _graphClient.GetAsync($"users/{user.Id}/drive?$select=webUrl", ct: tok);
                    var webUrl = drive?.TryGetProperty("webUrl", out var w) == true ? w.GetString() ?? "" : "";
                    // https://tenant-my.sharepoint.com/personal/user_domain_com/Documents -> site = first two segments
                    if (Uri.TryCreate(webUrl, UriKind.Absolute, out var uri))
                    {
                        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                        if (segments.Length >= 2)
                            found.Add(new SiteTarget { Url = $"{uri.Scheme}://{uri.Host}/{segments[0]}/{segments[1]}", Title = user.DisplayName });
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Interlocked.Increment(ref failed);
                }
            });

        context.MarkPartial("OneDrives were found through enabled, licensed users only, so OneDrives of leavers and unlicensed " +
            $"accounts are missing{(failed > 0 ? $" and {failed} user drive lookup(s) failed" : "")}. " +
            "Activate SharePoint Administrator and scan again for the complete list.");
        return found.ToList();
    }
}
