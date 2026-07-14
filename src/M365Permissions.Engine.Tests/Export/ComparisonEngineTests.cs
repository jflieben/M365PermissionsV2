using M365Permissions.Engine.Database;
using M365Permissions.Engine.Export;
using M365Permissions.Engine.Models;
using Xunit;

namespace M365Permissions.Engine.Tests.Export;

/// <summary>
/// Guards A7: duplicate grants (same principal/path/role) must not be collapsed, so removing
/// one of two identical grants is still reported as a removal.
/// </summary>
public sealed class ComparisonEngineTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteDb _db;
    private readonly ScanRepository _scanRepo;
    private readonly PermissionRepository _permRepo;
    private readonly ComparisonEngine _engine;

    public ComparisonEngineTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"m365cmp_test_{Guid.NewGuid():N}.db");
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        _scanRepo = new ScanRepository(_db);
        _permRepo = new PermissionRepository(_db);
        _engine = new ComparisonEngine(_permRepo);
    }

    private long NewScan()
    {
        return _scanRepo.Create(new ScanInfo
        {
            TenantDomain = "test.onmicrosoft.com",
            Status = ScanStatus.Completed,
            ScanTypes = "OneDrive",
            StartedAt = DateTime.UtcNow.ToString("O"),
            ModuleVersion = "0.1.0"
        });
    }

    private static PermissionEntry Link(long scanId, string targetId) => new()
    {
        ScanId = scanId,
        Category = "OneDrive",
        TargetPath = "https://contoso-my.sharepoint.com/personal/user/Documents/plan.docx",
        TargetId = targetId,
        PrincipalSysName = "Sharing Link (anonymous)",
        PrincipalType = "Anonymous",
        PrincipalRole = "view",
        Through = "Direct",
        AccessType = "Allow"
    };

    [Fact]
    public void RemovingOneOfTwoDuplicateLinks_IsReportedAsRemoved()
    {
        // Old scan: two distinct anonymous links (different link ids) on the same file.
        var oldScan = NewScan();
        _permRepo.BulkInsert(new List<PermissionEntry> { Link(oldScan, "link-1"), Link(oldScan, "link-2") });

        // New scan: only one of them remains.
        var newScan = NewScan();
        _permRepo.BulkInsert(new List<PermissionEntry> { Link(newScan, "link-1") });

        var result = _engine.Compare(oldScan, newScan);

        Assert.Single(result.Removed);
        Assert.Empty(result.Added);
    }

    [Fact]
    public void IdenticalScans_ProduceNoChanges()
    {
        var oldScan = NewScan();
        _permRepo.BulkInsert(new List<PermissionEntry> { Link(oldScan, "link-1"), Link(oldScan, "link-2") });

        var newScan = NewScan();
        _permRepo.BulkInsert(new List<PermissionEntry> { Link(newScan, "link-1"), Link(newScan, "link-2") });

        var result = _engine.Compare(oldScan, newScan);

        Assert.Empty(result.Added);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Changed);
    }

    public void Dispose()
    {
        _db.Dispose();
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
