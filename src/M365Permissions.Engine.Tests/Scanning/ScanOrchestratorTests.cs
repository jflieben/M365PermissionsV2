using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class ScanOrchestratorTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"m365orch_{Guid.NewGuid():N}.db");
    private readonly SqliteDb _db;
    private readonly ScanRepository _scanRepo;
    private readonly ScanOrchestrator _orchestrator;

    public ScanOrchestratorTests()
    {
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        _scanRepo = new ScanRepository(_db);
        _orchestrator = new ScanOrchestrator(_db, _scanRepo, new PermissionRepository(_db),
            new PolicyRepository(_db), new LogRepository(_db));
    }

    private sealed class ThrowingProvider(string category, Exception ex) : IScanProvider
    {
        public string Category => category;

        public async IAsyncEnumerable<PermissionEntry> ScanAsync(ScanContext context,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await Task.Yield();
            throw ex;
#pragma warning disable CS0162 // makes this an iterator
            yield break;
#pragma warning restore CS0162
        }
    }

    private async Task<AggregatedProgress> RunAsync(string category, Exception ex)
    {
        _orchestrator.RegisterProvider(new ThrowingProvider(category, ex));
        var scanId = _scanRepo.Create(new ScanInfo { Status = ScanStatus.Pending, ScanTypes = category, StartedAt = DateTime.UtcNow.ToString("O") });
        _orchestrator.StartScan(new ScanContext
        {
            ScanId = scanId,
            TenantDomain = "contoso.onmicrosoft.com",
            UserPrincipalName = "admin@contoso.onmicrosoft.com",
            Config = new AppConfig(),
            ReportProgress = (_, _) => { },
            SetTotalTargets = _ => { },
            CompleteTarget = () => { },
            FailTarget = () => { }
        }, new List<string> { category });

        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (_orchestrator.IsScanning && DateTime.UtcNow < deadline)
            await Task.Delay(20);
        return _orchestrator.GetProgress();
    }

    [Fact]
    public async Task ServiceNotUsedInTenant_CompletesTheCategory()
    {
        var progress = await RunAsync("AzureDevOps", new ResourcePrincipalNotFoundException("azuredevops", "AADSTS650052", "Azure DevOps isn't set up in this tenant: sign-in returned AADSTS650052."));

        Assert.Equal(ScanStatus.Completed, progress.OverallStatus);
        Assert.Equal("Completed", Assert.Single(progress.Categories).Status);
        Assert.Contains(progress.RecentLogs, l => l.Contains("sign-in returned AADSTS650052"));
    }

    [Fact]
    public async Task OtherTokenProblems_StillSkipTheCategory()
    {
        var progress = await RunAsync("PowerBI", new ResourcePrincipalNotFoundException("powerbi", "InteractionRequired", "needs sign-in"));

        Assert.Equal(ScanStatus.CompletedWithErrors, progress.OverallStatus);
        Assert.Equal("Skipped", Assert.Single(progress.Categories).Status);
    }

    public void Dispose()
    {
        _orchestrator.Shutdown();
        _db.Dispose();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
            try { File.Delete(f); } catch { /* best effort */ }
    }
}
