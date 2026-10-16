using M365Permissions.Engine.Database;
using M365Permissions.Engine.Export;
using M365Permissions.Engine.Models;
using Microsoft.Data.Sqlite;
using Xunit;

namespace M365Permissions.Engine.Tests.Export;

/// <summary>
/// Comparison keying (principal fallback, parent, target id) and coverage (only categories completed
/// in both scans are compared), plus CSV injection escaping and risk sort order.
/// </summary>
public sealed class ComparisonCoverageTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteDb _db;
    private readonly ScanRepository _scanRepo;
    private readonly PermissionRepository _permRepo;
    private readonly ComparisonEngine _engine;

    public ComparisonCoverageTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"m365cov_{Guid.NewGuid():N}.db");
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        _scanRepo = new ScanRepository(_db);
        _permRepo = new PermissionRepository(_db);
        _engine = new ComparisonEngine(_permRepo, _scanRepo);
    }

    private long Scan(string types, string tenant = "t1", ScanStatus status = ScanStatus.Completed, params (string Cat, string Status)[] progress)
    {
        var id = _scanRepo.Create(new ScanInfo { TenantId = tenant, TenantDomain = tenant + ".com", ScanTypes = types, StartedAt = DateTime.UtcNow.ToString("O") });
        _scanRepo.UpdateStatus(id, status);
        foreach (var (cat, st) in progress)
            _scanRepo.SaveProgress(new ScanProgress { ScanId = id, Category = cat, Status = st });
        return id;
    }

    private static PermissionEntry Mbx(long scanId, string upn, string role = "FullAccess", string parent = "") => new()
    {
        ScanId = scanId, Category = "Exchange", TargetPath = "shared@contoso.com", TargetId = "mbx-1", TargetType = "SharedMailbox",
        PrincipalEntraUpn = upn, PrincipalSysName = upn, PrincipalRole = role, Through = "MailboxPermission", ParentId = parent
    };

    [Fact]
    public void PrincipalsWithoutIds_AreKeyedByUpn_NotCollapsed()
    {
        var oldScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(oldScan, "anna@contoso.com"), Mbx(oldScan, "bob@contoso.com") });
        var newScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(newScan, "bob@contoso.com"), Mbx(newScan, "carl@contoso.com") });

        var result = _engine.Compare(oldScan, newScan);

        Assert.Equal("anna@contoso.com", Assert.Single(result.Removed).PrincipalEntraUpn);
        Assert.Equal("carl@contoso.com", Assert.Single(result.Added).PrincipalEntraUpn);
        Assert.Empty(result.Changed);
    }

    [Fact]
    public void PrincipalKey_FallsBack_EntraId_SysId_Upn_Name()
    {
        Assert.Equal("eid", ComparisonEngine.PrincipalKey(new PermissionEntry { PrincipalEntraId = "EID", PrincipalSysId = "sid", PrincipalEntraUpn = "u@x" }));
        Assert.Equal("sid", ComparisonEngine.PrincipalKey(new PermissionEntry { PrincipalSysId = "SID", PrincipalEntraUpn = "u@x" }));
        Assert.Equal("u@x", ComparisonEngine.PrincipalKey(new PermissionEntry { PrincipalEntraUpn = "U@x", PrincipalSysName = "User" }));
        Assert.Equal("user", ComparisonEngine.PrincipalKey(new PermissionEntry { PrincipalSysName = "User" }));
    }

    [Fact]
    public void SameMemberThroughTwoSharePointGroups_AreDistinct()
    {
        var oldScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(oldScan, "anna@contoso.com", parent: "G1"), Mbx(oldScan, "anna@contoso.com", parent: "G2") });
        var newScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(newScan, "anna@contoso.com", parent: "G2") });

        var result = _engine.Compare(oldScan, newScan);
        Assert.Equal("G1", Assert.Single(result.Removed).ParentId);
    }

    [Fact]
    public void MovedTarget_WithSameTargetId_IsChanged_NotAddedRemoved()
    {
        var oldScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(oldScan, "anna@contoso.com") });
        var newScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        var moved = Mbx(newScan, "anna@contoso.com");
        moved.TargetPath = "renamed@contoso.com";
        moved.RiskLevel = "Medium";
        _permRepo.BulkInsert(new List<PermissionEntry> { moved });

        var result = _engine.Compare(oldScan, newScan);
        var change = Assert.Single(result.Changed);
        Assert.Contains("TargetPath", change.ChangedFields);
        Assert.Contains("RiskLevel", change.ChangedFields);
        Assert.Empty(result.Added);
        Assert.Empty(result.Removed);
    }

    [Fact]
    public void FailedOrMissingCategory_IsExcluded_NotReportedAsRemoved()
    {
        var oldScan = Scan("Exchange,Entra", progress: new[] { ("Exchange", "Completed"), ("Entra", "Completed") });
        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            Mbx(oldScan, "anna@contoso.com"),
            new() { ScanId = oldScan, Category = "Entra", TargetPath = "Group/A", TargetId = "g", PrincipalEntraId = "u1", PrincipalRole = "Member" }
        });
        var newScan = Scan("Exchange,Entra", status: ScanStatus.CompletedWithErrors, progress: new[] { ("Exchange", "Failed"), ("Entra", "CompletedWithErrors") });
        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            new() { ScanId = newScan, Category = "Entra", TargetPath = "Group/A", TargetId = "g", PrincipalEntraId = "u1", PrincipalRole = "Member" }
        });

        var result = _engine.Compare(oldScan, newScan);

        Assert.Empty(result.Removed);
        Assert.Equal(new[] { "Entra" }, result.IncludedCategories);
        Assert.Equal("Exchange", Assert.Single(result.ExcludedCategories).Category);
        Assert.Equal("Entra", Assert.Single(result.FlaggedCategories).Category);
    }

    [Fact]
    public void CategoryNotInOldScan_IsExcluded()
    {
        var oldScan = Scan("Entra", progress: ("Entra", "Completed"));
        var newScan = Scan("Entra,Exchange", progress: new[] { ("Entra", "Completed"), ("Exchange", "Completed") });
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(newScan, "anna@contoso.com") });

        var result = _engine.Compare(oldScan, newScan);
        Assert.Empty(result.Added);
        Assert.Contains(result.ExcludedCategories, n => n.Category == "Exchange" && n.Reason.Contains($"#{oldScan}"));
    }

    [Fact]
    public void DifferentTenants_AreRefused()
    {
        var a = Scan("Entra", tenant: "t1", progress: ("Entra", "Completed"));
        var b = Scan("Entra", tenant: "t2", progress: ("Entra", "Completed"));
        Assert.Throws<ArgumentException>(() => _engine.Compare(a, b));
    }

    [Fact]
    public void Limit_CapsLists_ButCountsAreComplete()
    {
        var oldScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        var newScan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(Enumerable.Range(0, 10).Select(i => Mbx(newScan, $"u{i}@contoso.com")).ToList());

        var result = _engine.Compare(oldScan, newScan, limit: 3);
        Assert.Equal(3, result.Added.Count);
        Assert.Equal(10, result.AddedCount);
        Assert.True(result.Truncated);
    }

    [Theory]
    [InlineData("=1+1", "\"'=1+1\"")]
    [InlineData("+cmd", "\"'+cmd\"")]
    [InlineData("-2", "\"'-2\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("\tx", "\"'\tx\"")]
    [InlineData("plain \"q\"", "\"plain \"\"q\"\"\"")]
    [InlineData("", "\"\"")]
    public void Csv_EscapesFormulaInjection(string input, string expected)
        => Assert.Equal(expected, CsvExporter.Escape(input));

    [Fact]
    public void Csv_StartsWithHeader_AndHasCategory()
    {
        var csv = System.Text.Encoding.UTF8.GetString(new CsvExporter().Export(new[] { new PermissionEntry { Category = "Exchange", TargetPath = "x" } }))
            .TrimStart('﻿');
        Assert.StartsWith("Risk Level,Risk Reason,Category,", csv);
        Assert.Contains("\"Exchange\"", csv);
        Assert.DoesNotContain("#", csv.Split('\n')[0]);
    }

    [Fact]
    public void RiskSort_UsesSeverityOrder_WithIdTiebreak()
    {
        var scan = Scan("Entra", progress: ("Entra", "Completed"));
        var levels = new[] { "Low", "Critical", "Info", "High", "Medium", "Critical" };
        _permRepo.BulkInsert(levels.Select((l, i) => new PermissionEntry { ScanId = scan, Category = "Entra", TargetPath = $"t{i}", RiskLevel = l }).ToList());

        var asc = _permRepo.Query(scan, sortColumn: "risk_level", sortDirection: "asc").Items.Select(e => e.RiskLevel).ToArray();
        Assert.Equal(new[] { "Critical", "Critical", "High", "Medium", "Low", "Info" }, asc);
        var desc = _permRepo.Query(scan, sortColumn: "risk_level", sortDirection: "desc").Items.Select(e => e.RiskLevel).ToArray();
        Assert.Equal(new[] { "Info", "Low", "Medium", "High", "Critical", "Critical" }, desc);

        // Paging through a sort with ties returns every row exactly once.
        var paged = Enumerable.Range(1, 3).SelectMany(p => _permRepo.Query(scan, page: p, pageSize: 2, sortColumn: "risk_level").Items.Select(e => e.Id)).ToList();
        Assert.Equal(6, paged.Distinct().Count());
    }

    [Fact]
    public void Search_TreatsUnderscoreAndPercentLiterally_AndPageSizeIsClamped()
    {
        var scan = Scan("Entra", progress: ("Entra", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            new() { ScanId = scan, Category = "Entra", TargetPath = "a_b" },
            new() { ScanId = scan, Category = "Entra", TargetPath = "axb" },
        });
        Assert.Equal("a_b", Assert.Single(_permRepo.Query(scan, searchText: "a_b").Items).TargetPath);
        Assert.Equal(PermissionRepository.MaxPageSize, _permRepo.Query(scan, pageSize: 50_000).PageSize);
    }

    [Fact]
    public void DeleteScan_RemovesRowsProgressAndScan()
    {
        var scan = Scan("Exchange", progress: ("Exchange", "Completed"));
        _permRepo.BulkInsert(new List<PermissionEntry> { Mbx(scan, "anna@contoso.com") });

        Assert.True(_scanRepo.Delete(scan));
        Assert.Null(_scanRepo.GetById(scan));
        Assert.Equal(0, _permRepo.Count(scan));
        Assert.Empty(_scanRepo.GetProgress(scan));
        Assert.False(_scanRepo.Delete(scan));
    }

    [Fact]
    public void CompletedAt_IsIsoUtc()
    {
        var scan = Scan("Entra", progress: ("Entra", "Completed"));
        var completed = _scanRepo.GetById(scan)!.CompletedAt;
        Assert.EndsWith("Z", completed);
        Assert.Equal("2026-01-02T03:04:05.000Z", ScanRepository.NormalizeUtc("2026-01-02 03:04:05"));
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch { }
    }
}
