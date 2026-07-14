using System.Diagnostics;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Database;
using M365Permissions.Engine.Export;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Http;
using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;

namespace M365Permissions.Engine;

/// <summary>
/// Main entry point / facade for the M365Permissions engine.
/// Wires together all subsystems: database, auth, HTTP server, scanning, export.
/// Called from the PowerShell module wrapper.
/// </summary>
public sealed class Engine : IDisposable
{
    public static string ModuleVersion { get; } =
        typeof(Engine).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private readonly SqliteDb _db;
    private readonly ConfigRepository _configRepo;
    private readonly ScanRepository _scanRepo;
    private readonly PermissionRepository _permRepo;
    private readonly AuditRepository _auditRepo;
    private readonly PolicyRepository _policyRepo;
    private readonly LogRepository _logRepo;
    private readonly TokenCache _tokenCache;
    private readonly DelegatedAuth _auth;
    private readonly ExcelExporter _excelExporter;
    private readonly CsvExporter _csvExporter;
    private readonly ComparisonEngine _comparisonEngine;

    private GraphClient? _graphClient;
    private SharePointRestClient? _spClient;
    private ExchangeRestClient? _exoClient;
    private ScanOrchestrator? _orchestrator;
    private WebServer? _webServer;

    private AppConfig _config;
    private readonly Task _sessionRestoreTask;

    public Engine(string databasePath)
    {
        _db = new SqliteDb(databasePath);
        _db.Initialize();

        _configRepo = new ConfigRepository(_db);
        _scanRepo = new ScanRepository(_db);
        _permRepo = new PermissionRepository(_db);
        _auditRepo = new AuditRepository(_db);
        _policyRepo = new PolicyRepository(_db);
        _logRepo = new LogRepository(_db);

        // B13: any scan still marked Running/Pending belongs to a previous process that died
        // mid-scan (progress lives in the engine); mark them Failed so they don't show forever.
        _scanRepo.RecoverInterruptedScans();

        // Persist refresh tokens alongside the database
        var persistDir = Path.GetDirectoryName(databasePath) ?? ".";
        _tokenCache = new TokenCache(persistDir);

        _auth = new DelegatedAuth(_tokenCache);
        _excelExporter = new ExcelExporter();
        _csvExporter = new CsvExporter();
        _comparisonEngine = new ComparisonEngine(_permRepo);

        _config = LoadConfig();

        // Seed default policy rules if none exist yet
        SeedDefaultPolicies();

        // Try to restore previous session from persisted refresh token
        _sessionRestoreTask = Task.Run(async () =>
        {
            try
            {
                if (await _auth.TryRestoreSessionAsync())
                    InitializeClients();
            }
            catch { /* best effort — user can connect manually */ }
        });
    }

    /// <summary>Wait for session restore to complete (up to a timeout), so status is accurate.</summary>
    public async Task EnsureSessionRestoredAsync(int timeoutMs = 5000)
    {
        await Task.WhenAny(_sessionRestoreTask, Task.Delay(timeoutMs));
    }

    // ── Status ──────────────────────────────────────────────────

    public StatusResponse GetStatus() => new()
    {
        Connected = _auth.IsConnected,
        TenantId = _auth.TenantId,
        TenantDomain = _auth.TenantDomain,
        UserPrincipalName = _auth.UserPrincipalName,
        ModuleVersion = ModuleVersion,
        Scanning = _orchestrator?.IsScanning ?? false,
        ActiveScanId = _orchestrator?.IsScanning == true ? _orchestrator.ActiveScanId : null,
        RefreshTokenExpiry = _auth.RefreshTokenExpiry?.ToString("O")
    };

    // ── Authentication ──────────────────────────────────────────

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        await _auth.AuthenticateAsync(ct);
        InitializeClients();
    }

    /// <summary>
    /// Get the user count for the connected tenant (for licensing guidance).
    /// Returns null if the count cannot be determined.
    /// </summary>
    public async Task<UserCountInfo?> GetUserCountAsync(CancellationToken ct = default)
    {
        if (!_auth.IsConnected || _graphClient == null) return null;

        try
        {
            var result = await _graphClient.GetAsync("users?$count=true&$top=1&$select=id", eventualConsistency: true, ct: ct);
            if (result == null) return null;

            long count = 0;
            if (result.Value.TryGetProperty("@odata.count", out var countProp))
                count = countProp.GetInt64();

            string? recommendation = null;
            if (count > 1000)
                recommendation = "Your tenant has over 1,000 users. For tenants this large, consider using M365Permissions.com for faster scans, managed infrastructure, and advanced reporting.";
            else if (count > 500)
                recommendation = "Your tenant has over 500 users. For larger tenants, M365Permissions.com offers managed scanning infrastructure and is recommended for best performance.";
            else if (count > 250)
                recommendation = "For growing tenants (250+ users), M365Permissions.com offers scheduled scans and historical tracking out of the box.";

            return new UserCountInfo { UserCount = count, Recommendation = recommendation };
        }
        catch
        {
            return null;
        }
    }

    public void Disconnect()
    {
        _auth.SignOut();
        _graphClient = null;
        _spClient = null;
        _exoClient = null;
    }

    /// <summary>
    /// Trigger admin consent flow to re-grant permissions for the app registration.
    /// Opens browser with prompt=consent, then refreshes clients with new tokens.
    /// </summary>
    public async Task ReconsentAsync(List<string>? scanTypes = null, bool includeGraph = true, CancellationToken ct = default)
    {
        // Targeted re-consent (includeGraph=false) still needs an authenticated base session.
        // If not connected yet, bootstrap with Graph sign-in first.
        if (includeGraph || !_auth.IsConnected)
            await _auth.ReconsentAsync(ct);

        var categories = scanTypes is { Count: > 0 }
            ? scanTypes
            : new List<string>();

        // Re-consent selected non-Graph resources with explicit resource-specific prompts.
        if (categories.Count > 0)
            await _auth.ReconsentResourcesForCategoriesAsync(categories, ct);

        InitializeClients();
    }

    public async Task ReconsentAsync(CancellationToken ct = default)
    {
        await ReconsentAsync(scanTypes: null, includeGraph: true, ct);
    }

    private void InitializeClients()
    {
        _graphClient = new GraphClient(_auth, _config.MaxThreads, _config.MaxJobRetries);
        _spClient = new SharePointRestClient(_auth, _graphClient);
        _exoClient = new ExchangeRestClient(_auth);

        _orchestrator = new ScanOrchestrator(_db, _scanRepo, _permRepo, _policyRepo, _logRepo);
        _orchestrator.RegisterProvider(new SharePointScanner(_spClient, _graphClient, _auth));
        _orchestrator.RegisterProvider(new EntraScanner(_graphClient));
        _orchestrator.RegisterProvider(new TeamsScanner(_graphClient));
        _orchestrator.RegisterProvider(new ExchangeScanner(_exoClient, _graphClient));
        _orchestrator.RegisterProvider(new OneDriveScanner(_graphClient, _spClient, _auth));
        _orchestrator.RegisterProvider(new PowerBIScanner(_auth));
        _orchestrator.RegisterProvider(new PowerAutomateScanner(_auth));
        _orchestrator.RegisterProvider(new AzureScanner(_auth));
        _orchestrator.RegisterProvider(new AzureDevOpsScanner(_auth));
        _orchestrator.RegisterProvider(new PurviewScanner(_auth));
    }

    // ── Configuration ───────────────────────────────────────────

    public AppConfig GetConfig() => _config;

    public void UpdateConfig(Dictionary<string, JsonElement> updates)
    {
        foreach (var (key, value) in updates)
        {
            var strValue = value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : value.GetRawText();
            _configRepo.Set(key, strValue);
        }
        _config = LoadConfig();
    }

    public void UpdateConfig(AppConfig config)
    {
        _configRepo.Set("guiPort", config.GuiPort.ToString());
        _configRepo.Set("maxThreads", config.MaxThreads.ToString());
        _configRepo.Set("outputFormat", config.OutputFormat);
        _configRepo.Set("logLevel", config.LogLevel);
        _configRepo.Set("includeCurrentUser", config.IncludeCurrentUser.ToString());
        _configRepo.Set("defaultTimeoutMinutes", config.DefaultTimeoutMinutes.ToString());
        _configRepo.Set("maxJobRetries", config.MaxJobRetries.ToString());
        _config = LoadConfig();
    }

    private AppConfig LoadConfig()
    {
        var all = _configRepo.GetAll();
        return new AppConfig
        {
            GuiPort = GetInt(all, "guiPort", 8080),
            MaxThreads = GetInt(all, "maxThreads", 5),
            OutputFormat = GetStr(all, "outputFormat", "XLSX"),
            LogLevel = GetStr(all, "logLevel", "Minimal"),
            IncludeCurrentUser = GetBool(all, "includeCurrentUser", false),
            DefaultTimeoutMinutes = GetInt(all, "defaultTimeoutMinutes", 120),
            MaxJobRetries = GetInt(all, "maxJobRetries", 3)
        };
    }

    private static int GetInt(Dictionary<string, string> d, string key, int def)
        => d.TryGetValue(key, out var v) && int.TryParse(v, out var i) ? i : def;
    private static string GetStr(Dictionary<string, string> d, string key, string def)
        => d.TryGetValue(key, out var v) ? v : def;
    private static bool GetBool(Dictionary<string, string> d, string key, bool def)
        => d.TryGetValue(key, out var v) && bool.TryParse(v, out var b) ? b : def;

    // ── Scanning ────────────────────────────────────────────────

    public async Task<long> StartScanAsync(List<string> scanTypes, CancellationToken ct = default)
    {
        if (!_auth.IsConnected)
            throw new InvalidOperationException("Not connected. Call ConnectAsync first.");

        if (_orchestrator == null)
            InitializeClients();

        // Make sure the user has consented to the Graph permissions each selected scan needs.
        // This may open a browser tab for incremental consent on first use of a category.
        await _auth.EnsureGraphConsentForCategoriesAsync(scanTypes, ct);

        // Non-Graph APIs (Exchange, Azure, Power BI, DevOps, etc.) require separate resource consent.
        // Acquire these up front so scans don't fail later without ever prompting the user.
        await _auth.EnsureResourceConsentForCategoriesAsync(scanTypes, ct);

        var scan = new ScanInfo
        {
            TenantId = _auth.TenantId ?? "",
            TenantDomain = _auth.TenantDomain ?? "",
            Status = ScanStatus.Pending,
            ScanTypes = string.Join(",", scanTypes),
            StartedAt = DateTime.UtcNow.ToString("O"),
            StartedBy = _auth.UserPrincipalName ?? "",
            ConfigSnapshot = JsonSerializer.Serialize(_config),
            ModuleVersion = ModuleVersion
        };

        var scanId = _scanRepo.Create(scan);

        var context = new ScanContext
        {
            ScanId = scanId,
            TenantDomain = _auth.TenantDomain ?? "",
            UserPrincipalName = _auth.UserPrincipalName ?? "",
            Config = _config,
            ReportProgress = (_, _) => { },
            SetTotalTargets = _ => { },
            CompleteTarget = () => { },
            FailTarget = () => { }
        };

        _orchestrator!.StartScan(context, scanTypes);
        _auditRepo.Log("ScanStarted", _auth.UserPrincipalName ?? "", $"Scan started: {string.Join(", ", scanTypes)}", scanId);
        return scanId;
    }

    public void CancelScan() => _orchestrator?.CancelScan();

    public AggregatedProgress? GetScanProgress() => _orchestrator?.GetProgress();

    /// <summary>Persisted per-category progress for a scan — survives engine restarts (B15).</summary>
    public List<ScanProgress> GetPersistedProgress(long scanId) => _scanRepo.GetProgress(scanId);

    /// <summary>Persisted logs for a scan (B15/O1). Filter by max level and/or category.</summary>
    public List<LogEntry> GetScanLogs(long scanId, int? maxLevel = null, string? category = null, int limit = 1000)
        => _logRepo.GetByScan(scanId, maxLevel, category, limit);

    public ThrottleMetrics? GetThrottleMetrics() => _graphClient?.ThrottleManager.GetMetrics();

    /// <summary>Pre-check permissions for the requested scan types before starting.</summary>
    public async Task<Dictionary<string, List<string>>> CheckPermissionsAsync(List<string> scanTypes, CancellationToken ct = default)
    {
        if (!_auth.IsConnected || _graphClient == null)
            throw new InvalidOperationException("Not connected. Call ConnectAsync first.");

        // Make sure each requested scan's Graph scopes are consented before running pre-check probes,
        // otherwise the probes themselves would fail with 403/AADSTS errors that aren't really
        // permission gaps — they're just "user hasn't clicked Accept yet".
        await _auth.EnsureGraphConsentForCategoriesAsync(scanTypes, ct);

        // Also ensure non-Graph resource consent up front so pre-check reflects real access state.
        await _auth.EnsureResourceConsentForCategoriesAsync(scanTypes, ct);

        var checker = new PermissionPreChecker(_graphClient, _auth);
        return await checker.CheckAsync(scanTypes, ct);
    }

    /// <summary>
    /// Return the set of Graph delegated scopes required for the given scan categories that
    /// have NOT yet been consented. Empty list = no consent prompt is needed.
    /// </summary>
    public List<string> GetMissingGraphScopesForCategories(IEnumerable<string> categories)
    {
        var consented = _tokenCache.GetConsentedGraphScopes();
        var needed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in categories)
            foreach (var s in DelegatedAuth.GetRequiredGraphScopesForCategory(c))
                if (!consented.Contains(s))
                    needed.Add(s);
        return needed.OrderBy(s => s).ToList();
    }

    // ── Results ─────────────────────────────────────────────────

    public List<ScanInfo> GetScans(string? tenantId = null) => _scanRepo.GetAll(tenantId: tenantId);

    public PagedResult<PermissionEntry> QueryPermissions(long scanId, string? category = null,
        string? search = null, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
        => _permRepo.Query(scanId, category, search, page, pageSize, sortColumn, sortDirection, columnFilters);

    public List<string> GetCategories(long scanId)
        => _permRepo.GetCategories(scanId);

    public PagedResult<PermissionEntry> QueryUserPermissions(long scanId, string userSearch, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
        => _permRepo.QueryUserPermissions(scanId, userSearch, page, pageSize, sortColumn, sortDirection, columnFilters);

    public List<PermissionEntry> GetGroupMembers(long scanId, string groupId)
        => _permRepo.GetGroupMembers(scanId, groupId);

    public List<string> GetFilterOptions(long scanId, string column, string? category = null)
        => _permRepo.GetDistinctValues(scanId, column, category);

    // ── Export ───────────────────────────────────────────────────

    public (byte[] bytes, string fileName, string contentType) ExportScan(long scanId, string format, string? category = null)
    {
        var scan = _scanRepo.GetById(scanId)
            ?? throw new KeyNotFoundException($"Scan {scanId} not found");

        var catSuffix = category ?? "All";

        if (format.Equals("csv", StringComparison.OrdinalIgnoreCase))
        {
            // Stream the CSV a page at a time so a million-row scan doesn't materialise the whole
            // result set (entry objects + string) in a default PS session (P3).
            const int pageSize = 5000;
            var bytes = _csvExporter.ExportPaged(afterId => _permRepo.GetPage(scanId, category, afterId, pageSize));
            _auditRepo.Log("Export", _auth.UserPrincipalName ?? "", $"CSV export: scan {scanId}, category={catSuffix}");
            return (bytes, $"M365Permissions_{catSuffix}_{scanId}.csv", "text/csv");
        }
        else
        {
            // ClosedXML holds the whole workbook in memory. Above a threshold this OOMs, so steer
            // very large exports to CSV rather than failing opaquely (P3). Uses the whole-scan
            // count as a cheap upper bound.
            const long xlsxRowLimit = 250_000;
            var count = _permRepo.Count(scanId);
            if (count > xlsxRowLimit)
                throw new InvalidOperationException(
                    $"This scan has {count:N0} rows, which is too large for an XLSX export. Please export as CSV instead (or export a single category).");

            var entries = _permRepo.GetAll(scanId, category);
            var bytes = _excelExporter.Export(entries, catSuffix);
            _auditRepo.Log("Export", _auth.UserPrincipalName ?? "", $"XLSX export: scan {scanId}, category={catSuffix}");
            return (bytes, $"M365Permissions_{catSuffix}_{scanId}.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        }
    }

    // ── Comparison ──────────────────────────────────────────────

    public ComparisonResult CompareScans(long oldScanId, long newScanId, string? category = null)
        => _comparisonEngine.Compare(oldScanId, newScanId, category);

    /// <summary>
    /// Risk delta vs the previous completed scan of the same tenant (O3). Returns null with
    /// HasPrevious=false when there is no earlier scan to compare against.
    /// </summary>
    public RiskDelta GetRiskDelta(long scanId)
    {
        var scan = _scanRepo.GetById(scanId)
            ?? throw new KeyNotFoundException($"Scan {scanId} not found");

        var previous = _scanRepo.GetAll(50, scan.TenantId)
            .FirstOrDefault(s => s.Id < scanId &&
                (s.Status is ScanStatus.Completed or ScanStatus.CompletedWithErrors));

        var delta = new RiskDelta { ScanId = scanId, PreviousScanId = previous?.Id };
        if (previous == null) return delta;

        var cmp = _comparisonEngine.Compare(previous.Id, scanId);
        delta.NewCritical = cmp.Added.Count(e => e.RiskLevel == "Critical");
        delta.NewHigh = cmp.Added.Count(e => e.RiskLevel == "High");
        delta.TotalAdded = cmp.Added.Count;
        delta.TotalRemoved = cmp.Removed.Count;
        return delta;
    }

    // Cache the PSGallery lookup for 24h; the check is best-effort and must never block/throw ($4).
    private VersionInfo? _cachedVersion;
    private DateTimeOffset _versionCheckedAt = DateTimeOffset.MinValue;

    public async Task<VersionInfo> CheckForUpdateAsync(CancellationToken ct = default)
    {
        if (_cachedVersion != null && (DateTimeOffset.UtcNow - _versionCheckedAt).TotalHours < 24)
            return _cachedVersion;

        var info = new VersionInfo { Current = ModuleVersion };
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var xml = await http.GetStringAsync(
                "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='M365Permissions'&$filter=IsLatestVersion", ct);
            // Extract the newest <d:Version>…</d:Version> from the OData feed.
            Version? latest = null;
            foreach (System.Text.RegularExpressions.Match m in
                System.Text.RegularExpressions.Regex.Matches(xml, @"<d:Version>([^<]+)</d:Version>"))
            {
                if (Version.TryParse(m.Groups[1].Value.Split('-')[0], out var parsed) &&
                    (latest == null || parsed > latest))
                    latest = parsed;
            }
            if (latest != null)
            {
                info.Latest = latest.ToString();
                info.UpdateAvailable = Version.TryParse(ModuleVersion, out var cur) && latest > cur;
            }
        }
        catch { /* fail silent — never block the GUI on a gallery lookup */ }

        _cachedVersion = info;
        _versionCheckedAt = DateTimeOffset.UtcNow;
        return info;
    }

    // ── Comparison Export ───────────────────────────────────────

    public (byte[] bytes, string fileName, string contentType) ExportComparison(long oldScanId, long newScanId, string? category = null)
    {
        var result = _comparisonEngine.Compare(oldScanId, newScanId, category);
        var bytes = _excelExporter.ExportComparison(result);
        _auditRepo.Log("ComparisonExport", _auth.UserPrincipalName ?? "", $"Exported comparison: scan {oldScanId} vs {newScanId}");
        return (bytes, $"M365Permissions_Compare_{oldScanId}_vs_{newScanId}.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    }

    // ── Scan Notes & Tags ───────────────────────────────────────

    public void UpdateScanNotes(long scanId, string? notes, string? tags)
    {
        _scanRepo.UpdateNotes(scanId, notes, tags);
        _auditRepo.Log("ScanNotesUpdated", _auth.UserPrincipalName ?? "", $"Updated notes/tags on scan {scanId}", scanId);
    }

    // ── Risk Summary ────────────────────────────────────────────

    public Dictionary<string, int> GetRiskSummary(long scanId)
        => _scanRepo.GetRiskSummary(scanId);

    // ── Trends ──────────────────────────────────────────────────

    public List<TrendDataPoint> GetTrends(int limit = 20, string? tenantId = null)
        => _scanRepo.GetTrends(limit, tenantId);

    // ── Audit Log ───────────────────────────────────────────────

    public void AuditLog(string action, string details, long? scanId = null)
        => _auditRepo.Log(action, _auth.UserPrincipalName ?? "", details, scanId);

    public List<AuditEntry> GetAuditLog(int limit = 100, string? action = null, string? tenantId = null)
        => _auditRepo.GetRecent(limit, action, tenantId);

    // ── Database Management ─────────────────────────────────────

    public DatabaseInfo GetDatabaseInfo() => _db.GetDatabaseInfo();

    public void ResetDatabase()
    {
        if (_orchestrator?.IsScanning == true)
            throw new InvalidOperationException("Cannot reset database while a scan is running.");
        _db.ResetDatabase();
        AuditLog("database_reset", "Database cleared — all scans, permissions, and logs deleted");
    }

    // ── Policies ────────────────────────────────────────────────

    public List<Policy> GetPolicies() => _policyRepo.GetAll();

    public Policy? GetPolicy(long id) => _policyRepo.GetById(id);

    public long CreatePolicy(Policy policy)
    {
        var id = _policyRepo.Create(policy);
        _auditRepo.Log("PolicyCreated", _auth.UserPrincipalName ?? "", $"Created policy: {policy.Name}");
        return id;
    }

    public void UpdatePolicy(Policy policy)
    {
        _policyRepo.Update(policy);
        _auditRepo.Log("PolicyUpdated", _auth.UserPrincipalName ?? "", $"Updated policy: {policy.Name}");
    }

    public void DeletePolicy(long id)
    {
        _policyRepo.Delete(id);
        _auditRepo.Log("PolicyDeleted", _auth.UserPrincipalName ?? "", $"Deleted policy #{id}");
    }

    /// <summary>
    /// Delete all default policies and re-seed them from built-in definitions.
    /// Custom (non-default) policies are preserved.
    /// </summary>
    public int ResetDefaultPolicies()
    {
        _policyRepo.DeleteDefaults();
        var defaults = DefaultPolicies.GetAll();
        foreach (var p in defaults)
            _policyRepo.Create(p);
        _auditRepo.Log("PoliciesReset", _auth.UserPrincipalName ?? "", $"Reset {defaults.Count} default policies");
        return defaults.Count;
    }

    private void SeedDefaultPolicies()
    {
        if (_policyRepo.Count() > 0) return; // Already has policies
        var defaults = DefaultPolicies.GetAll();
        foreach (var p in defaults)
            _policyRepo.Create(p);
    }

    public PolicyEvaluationResult EvaluatePolicies(long scanId, string? category = null, int limit = 500)
    {
        var policies = _policyRepo.GetEnabled();
        if (policies.Count == 0) return new();

        var entries = _permRepo.GetAll(scanId, category);
        if (entries.Count > limit) entries = entries.Take(limit).ToList();

        var violations = PolicyEngine.EvaluateBatch(entries, policies);
        var matchingEntries = new Dictionary<int, PermissionEntry>();
        foreach (var idx in violations.Keys)
            matchingEntries[idx] = entries[idx];

        return new PolicyEvaluationResult { Violations = violations, Entries = matchingEntries };
    }

    // ── HTTP Server ─────────────────────────────────────────────

    public void StartServer(int port, string staticFilesPath, bool openBrowser = true)
    {
        // Dispose any previous server (e.g. failed start on different port)
        _webServer?.Dispose();

        var server = new WebServer(port, staticFilesPath);
        ApiRoutes.Register(server, this);
        server.Start();
        _webServer = server;

        if (openBrowser)
        {
            try
            {
                Process.Start(new ProcessStartInfo($"http://localhost:{port}") { UseShellExecute = true });
            }
            catch { /* best effort */ }
        }
    }

    public async Task StopServerAsync()
    {
        if (_webServer != null)
            await _webServer.StopAsync();
    }

    public void Dispose()
    {
        // Cancel running scans
        _orchestrator?.Shutdown();

        // Stop web server (synchronous fallback if StopServerAsync wasn't called)
        _webServer?.Dispose();

        // Close database (WAL checkpoint)
        _db.Dispose();
    }
}
