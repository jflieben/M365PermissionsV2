using System.Collections.Concurrent;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Manages scan lifecycle: dispatches to IScanProvider implementations,
/// collects results via TPL parallelism, streams to SQLite, tracks progress.
/// </summary>
public sealed class ScanOrchestrator
{
    private readonly SqliteDb _db;
    private readonly ScanRepository _scanRepo;
    private readonly PermissionRepository _permRepo;
    private readonly PolicyRepository _policyRepo;
    private readonly LogRepository _logRepo;
    private readonly List<IScanProvider> _providers = new();

    // Max log level to persist to the DB, derived from config.LogLevel. -1 = persist nothing.
    private int _persistLogThreshold = 3;
    private int _timeoutMinutes;
    private DateTimeOffset _scanStartUtc;

    private CancellationTokenSource? _cts;
    private Task? _scanTask;
    private readonly ConcurrentDictionary<string, ScanProgress> _progress = new();
    private readonly List<string> _logBuffer = new();
    private readonly object _logLock = new();
    private long _activeScanId;
    private ScanStatus _finalStatus = ScanStatus.Pending;
    private readonly object _progressLock = new();

    private const int InsertBatchSize = 500;
    private const int MaxLogBufferSize = 500;
    private readonly object _insertLock = new();

    public bool IsScanning => _scanTask is { IsCompleted: false };
    public long ActiveScanId => _activeScanId;

    public ScanOrchestrator(SqliteDb db, ScanRepository scanRepo, PermissionRepository permRepo, PolicyRepository policyRepo, LogRepository logRepo)
    {
        _db = db;
        _scanRepo = scanRepo;
        _permRepo = permRepo;
        _policyRepo = policyRepo;
        _logRepo = logRepo;
    }

    // Map the configured LogLevel to a numeric max-level to persist (levels: 0=Critical..5=Debug).
    private static int MapLogThreshold(string? logLevel) => (logLevel ?? "Minimal").ToLowerInvariant() switch
    {
        "none" => -1,
        "minimal" => 2,   // Critical, Error, Warning
        "normal" => 3,    // + Info
        "full" => 5,      // everything
        _ => 3
    };

    public void RegisterProvider(IScanProvider provider)
    {
        _providers.Add(provider);
    }

    /// <summary>Start a scan across the specified categories. Throws if already scanning.</summary>
    public long StartScan(ScanContext context, List<string> scanTypes)
    {
        if (IsScanning)
            throw new InvalidOperationException("A scan is already in progress.");

        _cts = new CancellationTokenSource();
        _progress.Clear();
        ClearLogBuffer();
        _activeScanId = context.ScanId;
        _finalStatus = ScanStatus.Running;
        _persistLogThreshold = MapLogThreshold(context.Config?.LogLevel);
        _timeoutMinutes = context.Config?.DefaultTimeoutMinutes ?? 0;
        _scanStartUtc = DateTimeOffset.UtcNow;

        // Initialize progress entries for each requested type
        foreach (var type in scanTypes)
        {
            _progress[type] = new ScanProgress
            {
                ScanId = context.ScanId,
                Category = type,
                Status = "Pending",
                StartedAt = DateTime.UtcNow.ToString("O")
            };
        }

        _scanTask = Task.Run(async () =>
        {
            try
            {
                _scanRepo.UpdateStatus(context.ScanId, ScanStatus.Running);
                AddLog("Scan started", 3);
                await ExecuteScanAsync(context, scanTypes, _cts.Token);

                var totalPerms = _permRepo.Count(context.ScanId);

                // R1: if any category failed or was skipped, the dataset is partial — surface that
                // instead of a green "Completed" that hides missing data.
                var problem = _progress.Values.FirstOrDefault(p => p.Status is "Failed" or "Skipped");
                var status = problem != null ? ScanStatus.CompletedWithErrors : ScanStatus.Completed;
                var errorMsg = problem != null
                    ? $"One or more categories did not complete (e.g. {problem.Category}: {problem.Status}). Results are partial."
                    : null;

                _scanRepo.UpdateStatus(context.ScanId, status, error: errorMsg, totalPermissions: totalPerms);
                _finalStatus = status;
                AddLog($"Scan {(status == ScanStatus.Completed ? "completed" : "completed with errors")} — {totalPerms:N0} permissions found", status == ScanStatus.Completed ? 3 : 2);
            }
            catch (OperationCanceledException)
            {
                _scanRepo.UpdateStatus(context.ScanId, ScanStatus.Cancelled);
                _finalStatus = ScanStatus.Cancelled;
                AddLog("Scan cancelled by user", 2);
            }
            catch (Exception ex)
            {
                _scanRepo.UpdateStatus(context.ScanId, ScanStatus.Failed, error: ex.Message);
                _finalStatus = ScanStatus.Failed;
                AddLog($"Scan failed: {ex.Message}", 1);
            }
        });

        return context.ScanId;
    }

    public void CancelScan()
    {
        _cts?.Cancel();
    }

    /// <summary>Cancel any active scan and dispose resources. Safe to call multiple times.</summary>
    public void Shutdown()
    {
        CancelScan();
        try { _scanTask?.Wait(TimeSpan.FromSeconds(5)); } catch { /* best effort */ }
        _cts?.Dispose();
        _cts = null;
        _scanTask = null;
    }

    public AggregatedProgress GetProgress()
    {
        List<string> logs;
        lock (_logLock)
        {
            logs = new List<string>(_logBuffer);
        }

        var categories = _progress.Values.ToList();
        var totalTargets = categories.Sum(c => c.TotalTargets);
        var completedTargets = categories.Sum(c => c.CompletedTargets);

        // Determine overall status: use _finalStatus when scan task is done
        var overallStatus = IsScanning ? ScanStatus.Running : _finalStatus;

        // Force 100% when scan is done (whether clean or with errors)
        var percent = overallStatus is ScanStatus.Completed or ScanStatus.CompletedWithErrors
            ? 100.0
            : totalTargets > 0 ? Math.Round(100.0 * completedTargets / totalTargets, 1) : 0;

        return new AggregatedProgress
        {
            ScanId = _activeScanId,
            OverallStatus = overallStatus,
            Categories = categories,
            RecentLogs = logs,
            OverallPercent = percent,
            EstimatedTimeRemaining = EstimateEta(overallStatus, completedTargets, totalTargets)
        };
    }

    /// <summary>
    /// Simple linear ETA (U4): extrapolate remaining time from elapsed time and the fraction of
    /// targets already completed. Empty while there isn't enough signal yet.
    /// </summary>
    private string EstimateEta(ScanStatus overallStatus, int completedTargets, int totalTargets)
    {
        if (overallStatus != ScanStatus.Running || completedTargets <= 0 || totalTargets <= 0)
            return string.Empty;

        var frac = (double)completedTargets / totalTargets;
        if (frac <= 0 || frac >= 1) return string.Empty;

        var elapsed = DateTimeOffset.UtcNow - _scanStartUtc;
        var remaining = TimeSpan.FromSeconds(elapsed.TotalSeconds * (1 - frac) / frac);

        if (remaining.TotalHours >= 1) return $"~{(int)remaining.TotalHours}h {remaining.Minutes}m remaining";
        if (remaining.TotalMinutes >= 1) return $"~{(int)remaining.TotalMinutes}m remaining";
        return "~<1m remaining";
    }

    private async Task ExecuteScanAsync(ScanContext context, List<string> scanTypes, CancellationToken ct)
    {
        // Run all scan types in parallel — each category processes independently
        var tasks = new List<Task>();

        foreach (var scanType in scanTypes)
        {
            var provider = _providers.FirstOrDefault(p =>
                string.Equals(p.Category, scanType, StringComparison.OrdinalIgnoreCase));

            if (provider == null)
            {
                AddLog($"Unknown scan type: {scanType}", 2);
                continue;
            }

            tasks.Add(ExecuteCategoryAsync(context, scanType, provider, ct));
        }

        await Task.WhenAll(tasks);
    }

    private async Task ExecuteCategoryAsync(ScanContext context, string scanType, IScanProvider provider, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_progress.TryGetValue(scanType, out var progress))
        {
            progress.Status = "Running";
            PersistProgress(scanType);
        }

        AddLog($"Starting {scanType} scan...", 3, scanType);

        var catContext = new ScanContext
        {
            ScanId = context.ScanId,
            TenantDomain = context.TenantDomain,
            UserPrincipalName = context.UserPrincipalName,
            Config = context.Config,
            ReportProgress = (msg, level) => AddLog($"[{scanType}] {msg}", level, scanType),
            SetTotalTargets = count =>
            {
                if (_progress.TryGetValue(scanType, out var p)) { p.TotalTargets = count; PersistProgress(scanType); }
            },
            // CompleteTarget/FailTarget may be invoked from parallel per-target producers (P1),
            // so the counter increments must be serialized.
            CompleteTarget = () =>
            {
                if (_progress.TryGetValue(scanType, out var p))
                {
                    int done;
                    lock (_progressLock) { done = ++p.CompletedTargets; }
                    // Persist coarsely so the GUI survives an engine restart without a write per target.
                    if (done % 50 == 0) PersistProgress(scanType);
                }
            },
            FailTarget = () =>
            {
                if (_progress.TryGetValue(scanType, out var p))
                    lock (_progressLock) { p.FailedTargets++; }
            }
        };

        // R2: bound each category with the configured timeout so a hung paginated loop can't
        // stall a category forever. A per-category timeout (not per-scan) lets other categories
        // finish. User cancellation is distinguished from timeout via the outer token below.
        using var timeoutCts = _timeoutMinutes > 0
            ? CancellationTokenSource.CreateLinkedTokenSource(ct)
            : null;
        timeoutCts?.CancelAfter(TimeSpan.FromMinutes(_timeoutMinutes));
        var effectiveCt = timeoutCts?.Token ?? ct;

        var batch = new List<PermissionEntry>();
        var policies = _policyRepo.GetEnabled();
        var finalStatus = "Completed";

        try
        {
            await foreach (var entry in provider.ScanAsync(catContext, effectiveCt))
            {
                entry.ScanId = context.ScanId;
                entry.Category = scanType;
                batch.Add(entry);

                if (_progress.TryGetValue(scanType, out var pc))
                    pc.PermissionsFound++;

                if (batch.Count >= InsertBatchSize)
                {
                    PolicyEngine.ClassifyBatch(batch, policies);
                    lock (_insertLock) { _permRepo.BulkInsert(batch); }
                    batch.Clear();
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Category timed out (linked timeout token fired, but the user did not cancel).
            // Mark it failed and let other categories continue (R2).
            finalStatus = "Failed";
            AddLog($"[{scanType}] Timed out after {_timeoutMinutes} min — results for this category are partial.", 1, scanType);
        }
        catch (OperationCanceledException)
        {
            // User cancellation should propagate so the whole scan is marked cancelled.
            finalStatus = "Cancelled";
            throw;
        }
        catch (ResourcePrincipalNotFoundException ex)
        {
            // The resource (e.g. PowerBI, Azure DevOps, ASM) is not provisioned in this tenant.
            // Skip this scan but allow other scans to continue.
            finalStatus = "Skipped";
            AddLog($"[{scanType}] Skipped — {ex.Message}", 2);
        }
        catch (Exception ex)
        {
            // Per-scan failure: log and continue with other scan types.
            finalStatus = "Failed";
            AddLog($"[{scanType}] Failed: {ex.Message}", 1);
        }
        finally
        {
            if (batch.Count > 0)
            {
                try
                {
                    PolicyEngine.ClassifyBatch(batch, policies);
                    lock (_insertLock) { _permRepo.BulkInsert(batch); }
                }
                catch (Exception flushEx)
                {
                    AddLog($"[{scanType}] Failed to flush {batch.Count} remaining entries: {flushEx.Message}", 1);
                }
            }
        }

        if (_progress.TryGetValue(scanType, out var progressFinal))
        {
            progressFinal.Status = finalStatus;
            PersistProgress(scanType);
        }

        AddLog($"{(finalStatus == "Completed" ? "Completed" : finalStatus)} {scanType} scan.", finalStatus == "Completed" ? 3 : 2, scanType);
    }

    /// <summary>Persist a category's current progress row so the GUI survives an engine restart (B15).</summary>
    private void PersistProgress(string category)
    {
        if (!_progress.TryGetValue(category, out var p)) return;
        try { _scanRepo.SaveProgress(p); } catch { /* progress persistence is best-effort */ }
    }

    private void AddLog(string message, int level, string category = "")
    {
        var entry = $"[{DateTime.UtcNow:HH:mm:ss}] {message}";
        lock (_logLock)
        {
            _logBuffer.Add(entry);
            // Trim buffer to prevent unbounded growth
            while (_logBuffer.Count > MaxLogBufferSize)
                _logBuffer.RemoveAt(0);
        }

        // Persist to the logs table subject to the configured LogLevel (B15/O1).
        if (_persistLogThreshold >= 0 && level <= _persistLogThreshold)
        {
            try { _logRepo.Insert(_activeScanId == 0 ? null : _activeScanId, level, category, message); }
            catch { /* log persistence is best-effort */ }
        }
    }

    private void ClearLogBuffer()
    {
        lock (_logLock) { _logBuffer.Clear(); }
    }
}
