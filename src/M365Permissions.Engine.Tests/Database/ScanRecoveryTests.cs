using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;
using Xunit;

namespace M365Permissions.Engine.Tests.Database;

/// <summary>
/// Guards B13 (interrupted scans recovered on startup) and B15 (per-category progress persists).
/// </summary>
public sealed class ScanRecoveryTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteDb _db;
    private readonly ScanRepository _scanRepo;

    public ScanRecoveryTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"m365recover_{Guid.NewGuid():N}.db");
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        _scanRepo = new ScanRepository(_db);
    }

    private long NewScan(ScanStatus status)
    {
        var id = _scanRepo.Create(new ScanInfo
        {
            TenantDomain = "test.onmicrosoft.com",
            Status = ScanStatus.Pending,
            ScanTypes = "Entra",
            StartedAt = DateTime.UtcNow.ToString("O"),
            ModuleVersion = "0.1.0"
        });
        _scanRepo.UpdateStatus(id, status);
        return id;
    }

    [Fact]
    public void RecoverInterruptedScans_FailsRunningAndPending_LeavesCompletedAlone()
    {
        var running = NewScan(ScanStatus.Running);
        var pending = NewScan(ScanStatus.Pending);
        var completed = NewScan(ScanStatus.Completed);

        var recovered = _scanRepo.RecoverInterruptedScans();

        Assert.Equal(2, recovered);
        Assert.Equal(ScanStatus.Failed, _scanRepo.GetById(running)!.Status);
        Assert.Equal(ScanStatus.Failed, _scanRepo.GetById(pending)!.Status);
        Assert.Equal(ScanStatus.Completed, _scanRepo.GetById(completed)!.Status);
        Assert.Contains("Interrupted", _scanRepo.GetById(running)!.ErrorMessage);
    }

    [Fact]
    public void SaveProgress_UpsertsPerCategoryRow()
    {
        var scanId = NewScan(ScanStatus.Running);

        _scanRepo.SaveProgress(new ScanProgress { ScanId = scanId, Category = "Entra", TotalTargets = 10, CompletedTargets = 3, Status = "Running" });
        _scanRepo.SaveProgress(new ScanProgress { ScanId = scanId, Category = "Entra", TotalTargets = 10, CompletedTargets = 10, Status = "Completed" });
        _scanRepo.SaveProgress(new ScanProgress { ScanId = scanId, Category = "SharePoint", TotalTargets = 5, CompletedTargets = 5, Status = "Completed" });

        var progress = _scanRepo.GetProgress(scanId);

        Assert.Equal(2, progress.Count); // Entra upserted, not duplicated
        var entra = progress.Single(p => p.Category == "Entra");
        Assert.Equal(10, entra.CompletedTargets);
        Assert.Equal("Completed", entra.Status);
    }

    [Fact]
    public void CompletedWithErrors_IsPersistedAndReadBack()
    {
        var scanId = NewScan(ScanStatus.Running);
        _scanRepo.UpdateStatus(scanId, ScanStatus.CompletedWithErrors, error: "Exchange failed");

        var scan = _scanRepo.GetById(scanId)!;
        Assert.Equal(ScanStatus.CompletedWithErrors, scan.Status);
        Assert.Equal("Exchange failed", scan.ErrorMessage);
        Assert.NotEqual("", scan.CompletedAt); // completed_at was stamped
    }

    public void Dispose()
    {
        _db.Dispose();
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
