using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Export;

/// <summary>
/// Compares permissions between two scans and classifies rows as Added, Removed or Changed.
/// With a ScanRepository, only categories that completed in both scans are compared; the rest
/// are reported as excluded, so a failed or skipped category doesn't show up as mass removals.
/// </summary>
public sealed class ComparisonEngine
{
    private readonly PermissionRepository _permRepo;
    private readonly ScanRepository? _scanRepo;

    public ComparisonEngine(PermissionRepository permRepo) : this(permRepo, null) { }

    public ComparisonEngine(PermissionRepository permRepo, ScanRepository? scanRepo)
    {
        _permRepo = permRepo;
        _scanRepo = scanRepo;
    }

    private static readonly HashSet<string> ComparableStatuses = new(StringComparer.OrdinalIgnoreCase) { "Completed", "CompletedWithErrors" };

    /// <summary>
    /// Compare two scans. Key: category, target (id, else path), principal (Entra id, else system id,
    /// else UPN, else name), parent, role and through; duplicates are paired in a deterministic order.
    /// <paramref name="limit"/> caps each returned list (counts are always complete).
    /// Throws ArgumentException when the scans belong to different tenants.
    /// </summary>
    public ComparisonResult Compare(long oldScanId, long newScanId, string? category = null, int? limit = null)
    {
        var result = new ComparisonResult { OldScanId = oldScanId, NewScanId = newScanId };
        var categories = ResolveCategories(oldScanId, newScanId, category, result);

        foreach (var cat in categories)
            DiffCategory(oldScanId, newScanId, cat, result, limit);

        result.Truncated = limit.HasValue &&
            (result.AddedCount > limit || result.RemovedCount > limit || result.ChangedCount > limit);
        return result;
    }

    private List<string> ResolveCategories(long oldScanId, long newScanId, string? category, ComparisonResult result)
    {
        if (_scanRepo == null)
        {
            var all = _permRepo.GetCategories(oldScanId).Union(_permRepo.GetCategories(newScanId), StringComparer.OrdinalIgnoreCase)
                .Where(c => string.IsNullOrEmpty(category) || c.Equals(category, StringComparison.OrdinalIgnoreCase))
                .OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList();
            result.IncludedCategories.AddRange(all);
            return all;
        }

        var oldScan = _scanRepo.GetById(oldScanId) ?? throw new KeyNotFoundException($"Scan {oldScanId} not found");
        var newScan = _scanRepo.GetById(newScanId) ?? throw new KeyNotFoundException($"Scan {newScanId} not found");
        if (!string.IsNullOrEmpty(oldScan.TenantId) && !string.IsNullOrEmpty(newScan.TenantId) &&
            !oldScan.TenantId.Equals(newScan.TenantId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Scan #{oldScanId} ({oldScan.TenantDomain}) and scan #{newScanId} ({newScan.TenantDomain}) belong to different tenants and can't be compared.");

        var oldCoverage = GetCoverage(oldScan);
        var newCoverage = GetCoverage(newScan);
        var candidates = oldCoverage.Keys.Union(newCoverage.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(c => string.IsNullOrEmpty(category) || c.Equals(category, StringComparison.OrdinalIgnoreCase))
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList();
        if (candidates.Count == 0 && !string.IsNullOrEmpty(category))
            candidates.Add(category);

        var included = new List<string>();
        foreach (var cat in candidates)
        {
            var reason = ExclusionReason(cat, oldScan.Id, oldCoverage) ?? ExclusionReason(cat, newScan.Id, newCoverage);
            if (reason != null)
            {
                result.ExcludedCategories.Add(new CategoryCoverageNote { Category = cat, Reason = reason });
                continue;
            }
            included.Add(cat);
            var partial = new[] { (oldScan.Id, oldCoverage[cat]), (newScan.Id, newCoverage[cat]) }
                .Where(s => s.Item2.Equals("CompletedWithErrors", StringComparison.OrdinalIgnoreCase))
                .Select(s => $"#{s.Item1}").ToList();
            if (partial.Count > 0)
                result.FlaggedCategories.Add(new CategoryCoverageNote
                {
                    Category = cat,
                    Reason = $"Completed with errors in scan {string.Join(" and ", partial)}: differences may be incomplete"
                });
        }
        result.IncludedCategories.AddRange(included);
        return included;
    }

    private static string? ExclusionReason(string category, long scanId, Dictionary<string, string> coverage)
    {
        if (!coverage.TryGetValue(category, out var status))
            return $"Not scanned in scan #{scanId}";
        if (!ComparableStatuses.Contains(status))
            return $"{status} in scan #{scanId}";
        return null;
    }

    /// <summary>
    /// Per-category status of a scan: scan_progress when present; for older scans without progress
    /// rows, the scan's own status applied to its scan types and the categories it has rows for.
    /// </summary>
    private Dictionary<string, string> GetCoverage(ScanInfo scan)
    {
        var coverage = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in _scanRepo!.GetProgress(scan.Id))
            if (!string.IsNullOrEmpty(p.Category)) coverage[p.Category] = p.Status;

        var scanStatus = scan.Status.ToString();
        var fallback = coverage.Count == 0
            ? scanStatus
            : scan.Status is ScanStatus.Completed or ScanStatus.CompletedWithErrors ? "CompletedWithErrors" : scanStatus;
        foreach (var cat in scan.ScanTypes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Concat(_permRepo.GetCategories(scan.Id)))
            coverage.TryAdd(cat, fallback);
        return coverage;
    }

    private void DiffCategory(long oldScanId, long newScanId, string category, ComparisonResult result, int? limit)
    {
        var oldDict = BuildLookup(_permRepo.GetAll(oldScanId, category));
        var newDict = BuildLookup(_permRepo.GetAll(newScanId, category));

        foreach (var (key, newEntry) in newDict)
        {
            if (oldDict.TryGetValue(key, out var oldEntry))
            {
                var changedFields = GetChangedFields(oldEntry, newEntry);
                if (changedFields.Count == 0) continue;
                result.ChangedCount++;
                if (IsEscalationTo("Critical", oldEntry, newEntry)) result.NewCriticalCount++;
                if (IsEscalationTo("High", oldEntry, newEntry)) result.NewHighCount++;
                if (limit == null || result.Changed.Count < limit)
                    result.Changed.Add(new PermissionChange { Old = oldEntry, New = newEntry, ChangedFields = changedFields });
            }
            else
            {
                result.AddedCount++;
                if (newEntry.RiskLevel == "Critical") result.NewCriticalCount++;
                if (newEntry.RiskLevel == "High") result.NewHighCount++;
                if (limit == null || result.Added.Count < limit)
                    result.Added.Add(newEntry);
            }
        }

        foreach (var (key, oldEntry) in oldDict)
        {
            if (newDict.ContainsKey(key)) continue;
            result.RemovedCount++;
            if (limit == null || result.Removed.Count < limit)
                result.Removed.Add(oldEntry);
        }
    }

    private static bool IsEscalationTo(string level, PermissionEntry oldEntry, PermissionEntry newEntry)
        => newEntry.RiskLevel == level && oldEntry.RiskLevel != level;

    /// <summary>Identity of a principal for matching: Entra id, else system id, else UPN, else name.</summary>
    public static string PrincipalKey(PermissionEntry e)
    {
        var value = FirstNonEmpty(e.PrincipalEntraId, e.PrincipalSysId, e.PrincipalEntraUpn, e.PrincipalSysName);
        return value.Trim().ToLowerInvariant();
    }

    /// <summary>Readable principal for reports: UPN, else name, else system id, else Entra id.</summary>
    public static string PrincipalLabel(PermissionEntry e)
        => FirstNonEmpty(e.PrincipalEntraUpn, e.PrincipalSysName, e.PrincipalSysId, e.PrincipalEntraId);

    public static string BuildKey(PermissionEntry e)
    {
        var target = FirstNonEmpty(e.TargetId, e.TargetPath).Trim().ToLowerInvariant();
        return string.Join('|',
            e.Category.ToLowerInvariant(), target, PrincipalKey(e), e.ParentId.Trim().ToLowerInvariant(),
            e.PrincipalRole.Trim().ToLowerInvariant(), e.Through.Trim().ToLowerInvariant());
    }

    // Tie-breaker for rows sharing a key, so identical duplicates pair up the same way in both scans.
    private static string SecondaryKey(PermissionEntry e) => string.Join('|',
        e.TargetPath, e.TargetType, e.AccessType, e.Tenure, e.PrincipalType, e.PrincipalSysName,
        e.PrincipalEntraUpn, e.StartDateTime, e.EndDateTime);

    internal static Dictionary<string, PermissionEntry> BuildLookup(IEnumerable<PermissionEntry> entries)
    {
        var dict = new Dictionary<string, PermissionEntry>();
        var occurrences = new Dictionary<string, int>();
        foreach (var (baseKey, entry) in entries
                     .Select(e => (Key: BuildKey(e), Entry: e))
                     .OrderBy(x => x.Key, StringComparer.Ordinal)
                     .ThenBy(x => SecondaryKey(x.Entry), StringComparer.Ordinal))
        {
            var seen = occurrences.GetValueOrDefault(baseKey, 0);
            occurrences[baseKey] = seen + 1;
            dict[seen == 0 ? baseKey : $"{baseKey}#{seen}"] = entry;
        }
        return dict;
    }

    private static List<string> GetChangedFields(PermissionEntry old, PermissionEntry new_)
    {
        var changes = new List<string>();
        if (old.AccessType != new_.AccessType) changes.Add("AccessType");
        if (old.Tenure != new_.Tenure) changes.Add("Tenure");
        if (old.RiskLevel != new_.RiskLevel) changes.Add("RiskLevel");
        if (old.TargetPath != new_.TargetPath) changes.Add("TargetPath");
        if (old.TargetType != new_.TargetType) changes.Add("TargetType");
        if (old.PrincipalType != new_.PrincipalType) changes.Add("PrincipalType");
        if (old.PrincipalSysName != new_.PrincipalSysName) changes.Add("PrincipalSysName");
        if (old.PrincipalEntraUpn != new_.PrincipalEntraUpn) changes.Add("PrincipalEntraUpn");
        if (old.StartDateTime != new_.StartDateTime) changes.Add("StartDateTime");
        if (old.EndDateTime != new_.EndDateTime) changes.Add("EndDateTime");
        return changes;
    }

    private static string FirstNonEmpty(params string[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";
}
