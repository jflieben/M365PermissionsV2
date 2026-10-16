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
    private readonly InsightRepository _insightRepo;
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
        _insightRepo = new InsightRepository(_db);

        // B13: any scan still marked Running/Pending belongs to a previous process that died
        // mid-scan (progress lives in the engine); mark them Failed so they don't show forever.
        _scanRepo.RecoverInterruptedScans();

        // Persist refresh tokens alongside the database
        var persistDir = Path.GetDirectoryName(databasePath) ?? ".";
        _tokenCache = new TokenCache(persistDir);

        _auth = new DelegatedAuth(_tokenCache);
        _excelExporter = new ExcelExporter();
        _csvExporter = new CsvExporter();
        _comparisonEngine = new ComparisonEngine(_permRepo, _scanRepo);

        _config = LoadConfig();

        // Insert missing built-in policies and upgrade the ones the user never edited.
        SyncDefaultPolicies();
        PolicyEngine.ConfigurationWarning += OnPolicyConfigurationWarning;

        // Try to restore previous session from persisted refresh token
        _sessionRestoreTask = Task.Run(async () =>
        {
            try
            {
                if (await _auth.TryRestoreSessionAsync() && _orchestrator?.IsScanning != true)
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
        RefreshTokenExpiry = _auth.RefreshTokenExpiry?.ToString("O"),
        SharePointAdminUrl = _auth.IsConnected ? _auth.SharePointAdminUrl : null
    };

    // ── Authentication ──────────────────────────────────────────

    /// <summary>Where sign-in URLs open; the GUI claims them while it drives a request.</summary>
    public BrowserPrompt Prompt => _auth.Prompt;

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        ThrowIfScanning();
        try
        {
            await _auth.AuthenticateAsync(ct);
        }
        finally
        {
            // Also after a partial failure: tokens may be stored, and stale clients would keep the old tenant's state.
            if (_auth.IsConnected) InitializeClients();
        }
    }

    /// <summary>Create the clients if they're missing (after Disconnect, or a connect that never finished).</summary>
    [System.Diagnostics.CodeAnalysis.MemberNotNull(nameof(_graphClient), nameof(_orchestrator))]
    private void EnsureClients()
    {
        if (_graphClient == null || _orchestrator == null)
            InitializeClients();
    }

    /// <summary>
    /// Get the user count for the connected tenant (for licensing guidance).
    /// Returns null if the count cannot be determined.
    /// </summary>
    public async Task<UserCountInfo?> GetUserCountAsync(CancellationToken ct = default)
    {
        if (!_auth.IsConnected) return null;
        EnsureClients();

        try
        {
            // Enabled member accounts: guests and disabled accounts barely add scan work.
            var result = await _graphClient.GetAsync(
                "users?$count=true&$top=1&$select=id&$filter=accountEnabled eq true and userType eq 'Member'", eventualConsistency: true, ct: ct);
            if (result == null) return null;

            long count = 0;
            if (result.Value.TryGetProperty("@odata.count", out var countProp))
                count = countProp.GetInt64();

            string? recommendation = null;
            if (count > 1000)
                recommendation = $"With {count:N0} accounts a full scan from this workstation can take hours, and it only runs while you are signed in. " +
                    "The M365Permissions Cloud Edition runs scheduled delta scans unattended from your own Azure subscription, " +
                    "with managed identity and extra scan nodes for large tenants.";
            else if (count > 250)
                recommendation = "The M365Permissions Cloud Edition schedules these scans (daily, weekly or continuous), compares every run with " +
                    "the previous one and emails the changes or sends them to Microsoft Sentinel. It runs in your own Azure subscription.";

            return new UserCountInfo { UserCount = count, Recommendation = recommendation };
        }
        catch
        {
            return null;
        }
    }

    public void Disconnect()
    {
        // A running scan can't continue without tokens.
        _orchestrator?.CancelScan();
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
        ThrowIfScanning();
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

    /// <summary>
    /// Re-connecting replaces the orchestrator and the shared auth state, which would orphan a running
    /// scan (cancel and progress stop reaching it) or let it write another tenant's data into its scan row.
    /// </summary>
    private void ThrowIfScanning()
    {
        if (_orchestrator?.IsScanning == true)
            throw new InvalidOperationException("A scan is running. Cancel it or wait for it to finish before connecting or re-consenting.");
    }

    [System.Diagnostics.CodeAnalysis.MemberNotNull(nameof(_graphClient), nameof(_spClient), nameof(_exoClient), nameof(_orchestrator))]
    private void InitializeClients()
    {
        _graphClient = new GraphClient(_auth, _config.MaxThreads, _config.MaxJobRetries);
        _spClient = new SharePointRestClient(_auth, _graphClient);
        _exoClient = new ExchangeRestClient(_auth);

        _orchestrator = new ScanOrchestrator(_db, _scanRepo, _permRepo, _policyRepo, _logRepo, _insightRepo);
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
        => (await StartScanDetailedAsync(scanTypes, ct)).ScanId;

    /// <summary>Start a scan and return its ID plus account-check warnings (missing roles or scopes).</summary>
    public async Task<ScanStartResult> StartScanDetailedAsync(List<string> scanTypes, CancellationToken ct = default)
    {
        if (!_auth.IsConnected)
            throw new InvalidOperationException("Not connected. Connect to a tenant first.");

        EnsureClients();

        // Checked here too so a second start doesn't run consent flows and leave an orphaned Pending scan row.
        if (_orchestrator!.IsScanning)
            throw new InvalidOperationException("A scan is already in progress.");

        // Fresh tokens carry the roles held now (e.g. a PIM activation since sign-in).
        _auth.DropCachedAccessTokens();

        // Make sure the user has consented to the Graph permissions each selected scan needs.
        // This may open a browser tab for incremental consent on first use of a category.
        await _auth.EnsureGraphConsentForCategoriesAsync(scanTypes, ct);

        // Non-Graph APIs (Exchange, Azure, Power BI, DevOps, etc.) require separate resource consent.
        // Acquire these up front so scans don't fail later without ever prompting the user.
        var unavailable = await _auth.EnsureResourceConsentForCategoriesAsync(scanTypes, ct);

        var accountNotes = await CheckAccountAsync(scanTypes, unavailable, ct);

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
            TenantId = _auth.TenantId ?? "",
            UserPrincipalName = _auth.UserPrincipalName ?? "",
            Config = _config,
            ReportProgress = (_, _) => { },
            SetTotalTargets = _ => { },
            CompleteTarget = () => { },
            FailTarget = () => { }
        };

        // Consent is settled; the scan task inherits this and never opens a sign-in window.
        using (_auth.SuppressInteraction())
            _orchestrator!.StartScan(context, scanTypes, accountNotes);
        _auditRepo.Log("ScanStarted", _auth.UserPrincipalName ?? "", $"Scan started: {string.Join(", ", scanTypes)}", scanId);
        return new ScanStartResult
        {
            ScanId = scanId,
            Warnings = accountNotes.Where(n => n.Level <= 2)
                .Select(n => string.IsNullOrEmpty(n.Category) ? n.Message : $"{n.Category}: {n.Message}")
                .ToList()
        };
    }

    /// <summary>Evaluate the roles and scopes in the tokens the selected categories use. Never prompts.</summary>
    private async Task<List<AccountNote>> CheckAccountAsync(List<string> scanTypes, List<ResourcePrincipalNotFoundException> unavailable, CancellationToken ct)
    {
        var claims = new Dictionary<string, TokenClaims?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // Consent was settled above, so this is a silent refresh-token redemption.
            claims["graph"] = TokenClaims.TryParse(await _auth.GetAccessTokenAsync("graph", ct));
        }
        catch (OperationCanceledException) { throw; }
        catch { /* the scan itself will report Graph failures */ }

        foreach (var category in scanTypes)
            foreach (var resource in DelegatedAuth.GetRequiredResourceKeysForCategory(category))
                claims.TryAdd(resource, _auth.GetCachedTokenClaims(resource));

        try { return AccountCheck.Evaluate(scanTypes, claims, unavailable); }
        catch { return new List<AccountNote>(); }
    }

    public void CancelScan() => _orchestrator?.CancelScan();

    public AggregatedProgress? GetScanProgress() => _orchestrator?.GetProgress();

    /// <summary>Persisted per-category progress for a scan — survives engine restarts (B15).</summary>
    public List<ScanProgress> GetPersistedProgress(long scanId) => _scanRepo.GetProgress(scanId);

    /// <summary>Persisted logs for a scan (B15/O1). Filter by max level and/or category.</summary>
    public List<LogEntry> GetScanLogs(long scanId, int? maxLevel = null, string? category = null, int limit = 1000)
        => _logRepo.GetByScan(scanId, maxLevel, category, limit);

    /// <summary>Coverage counters of a scan (category -> key -> value).</summary>
    public Dictionary<string, Dictionary<string, long>> GetScanInsights(long scanId)
        => _insightRepo.GetByScan(scanId);

    public ThrottleMetrics? GetThrottleMetrics() => _graphClient?.ThrottleManager.GetMetrics();

    /// <summary>Pre-check permissions for the requested scan types before starting.</summary>
    public async Task<Dictionary<string, List<string>>> CheckPermissionsAsync(List<string> scanTypes, CancellationToken ct = default)
    {
        if (!_auth.IsConnected)
            throw new InvalidOperationException("Not connected. Connect to a tenant first.");

        EnsureClients();

        // Fresh tokens, so roles activated since sign-in are seen.
        _auth.DropCachedAccessTokens();

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

    public List<ScanInfo> GetScans(string? tenantId = null, int limit = 50) => _scanRepo.GetAll(limit, tenantId);

    public ScanInfo? GetScan(long scanId) => _scanRepo.GetById(scanId);

    /// <summary>
    /// Scan the cmdlets use when none is given: the latest Completed/CompletedWithErrors scan of the
    /// connected tenant, else of any tenant.
    /// </summary>
    public long? GetDefaultScanId()
    {
        var tenantId = _auth.IsConnected ? _auth.TenantId : null;
        return (_scanRepo.GetLatestCompleted(tenantId) ?? (tenantId != null ? _scanRepo.GetLatestCompleted() : null))?.Id;
    }

    public PagedResult<PermissionEntry> QueryPermissions(long scanId, string? category = null,
        string? search = null, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
        => _permRepo.Query(scanId, category, search, page, pageSize, sortColumn, sortDirection, columnFilters);

    /// <summary>Every matching row of a scan, read a page at a time (for the -All cmdlet switch).</summary>
    public IEnumerable<PermissionEntry> StreamPermissions(long scanId, string? category = null,
        string[]? riskLevels = null, string? search = null)
        => _permRepo.Stream(scanId, category, riskLevels, search);

    public List<string> GetCategories(long scanId)
        => _permRepo.GetCategories(scanId);

    public UserPermissionsPage QueryUserPermissions(long scanId, string userSearch, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
        => _permRepo.QueryUserPermissions(scanId, userSearch, page, pageSize, sortColumn, sortDirection, columnFilters);

    public List<PermissionEntry> GetGroupMembers(long scanId, string groupId)
        => _permRepo.GetGroupMembers(scanId, groupId);

    public List<PermissionEntry> GetSharePointGroupMembers(long scanId, string groupName, string? targetPath, string? targetId)
        => _permRepo.GetSharePointGroupMembers(scanId, groupName, targetPath, targetId);

    public List<string> GetFilterOptions(long scanId, string column, string? category = null)
        => _permRepo.GetDistinctValues(scanId, column, category);

    /// <summary>Delete a scan and all its rows. Refused while that scan is running.</summary>
    public bool DeleteScan(long scanId)
    {
        if (_orchestrator?.IsScanning == true && _orchestrator.ActiveScanId == scanId)
            throw new InvalidOperationException("This scan is still running. Cancel it before deleting it.");
        var deleted = _scanRepo.Delete(scanId);
        if (deleted)
        {
            InvalidateRiskDeltas();
            _auditRepo.Log("ScanDeleted", _auth.UserPrincipalName ?? "", $"Deleted scan {scanId}");
        }
        return deleted;
    }

    // ── Export ───────────────────────────────────────────────────

    // ClosedXML holds the whole workbook in memory; above this, exports must use CSV.
    public const long XlsxRowLimit = 250_000;

    private const string XlsxContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

    public (byte[] bytes, string fileName, string contentType) ExportScan(long scanId, string format, string? category = null)
    {
        using var ms = new MemoryStream();
        string fileName = "", contentType = "";
        ExportScanToStream(scanId, format, category, ms, (f, c) => { fileName = f; contentType = c; });
        return (ms.ToArray(), fileName, contentType);
    }

    /// <summary>Export straight to a file (CSV is streamed, never held in memory). Returns the file name used.</summary>
    public string ExportScanToFile(long scanId, string format, string? category, string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 65536);
        string fileName = "";
        ExportScanToStream(scanId, format, category, fs, (f, _) => fileName = f);
        return fileName;
    }

    /// <summary>
    /// Validate, then call <paramref name="onStart"/> with file name and content type, then write the
    /// export to <paramref name="output"/>. Validation errors are thrown before anything is written.
    /// </summary>
    public void ExportScanToStream(long scanId, string format, string? category, Stream output, Action<string, string> onStart)
    {
        var scan = _scanRepo.GetById(scanId)
            ?? throw new KeyNotFoundException($"Scan {scanId} not found");
        if (string.IsNullOrWhiteSpace(category)) category = null;
        var catSuffix = category ?? "All";

        if (format.Equals("csv", StringComparison.OrdinalIgnoreCase))
        {
            onStart($"M365Permissions_{catSuffix}_{scanId}.csv", "text/csv; charset=utf-8");
            _csvExporter.Write(output, _permRepo.Stream(scanId, category));
            _auditRepo.Log("Export", _auth.UserPrincipalName ?? "", $"CSV export: scan {scanId}, category={catSuffix}");
            return;
        }

        var count = _permRepo.Count(scanId, category);
        if (count > XlsxRowLimit)
            throw new InvalidOperationException(category == null
                ? $"This scan has {count:N0} rows, which is too large for an XLSX export. Export as CSV instead, or export a single category."
                : $"Category {category} has {count:N0} rows, which is too large for an XLSX export. Export it as CSV instead.");

        var entries = _permRepo.GetAll(scanId, category);
        var bytes = _excelExporter.Export(entries, catSuffix, BuildExportMetadata(scan, category));
        onStart($"M365Permissions_{catSuffix}_{scanId}.xlsx", XlsxContentType);
        output.Write(bytes);
        _auditRepo.Log("Export", _auth.UserPrincipalName ?? "", $"XLSX export: scan {scanId}, category={catSuffix}");
    }

    private ExportMetadata BuildExportMetadata(ScanInfo scan, string? category)
    {
        var progress = _scanRepo.GetProgress(scan.Id)
            .Where(p => category == null || p.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();
        var notes = progress.Where(p => p.Status != "Completed")
            .Select(p => $"{p.Category}: {p.Status}{(p.FailedTargets > 0 ? $", {p.FailedTargets:N0} targets failed" : "")}")
            .ToList();
        try
        {
            foreach (var (cat, values) in _insightRepo.GetByScan(scan.Id))
            {
                if (category != null && !cat.Equals(category, StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var (key, value) in values)
                    if (InsightKeys.Describe(key, value) is { } text)
                        notes.Add($"{cat}: {text}");
            }
        }
        catch { /* coverage counters are optional */ }

        return new ExportMetadata
        {
            ScanId = scan.Id,
            TenantDomain = scan.TenantDomain,
            TenantId = scan.TenantId,
            StartedAt = scan.StartedAt,
            CompletedAt = scan.CompletedAt,
            Status = scan.Status.ToString(),
            ScanTypes = scan.ScanTypes,
            Category = category ?? "",
            ModuleVersion = ModuleVersion,
            CategoryStatus = progress,
            PartialNotes = notes,
            RiskSummary = _scanRepo.GetRiskSummary(scan.Id, category)
        };
    }

    // ── Comparison ──────────────────────────────────────────────

    /// <summary>
    /// Compare two scans of the same tenant. <paramref name="limit"/> caps each returned list; counts
    /// are complete. Throws ArgumentException for scans of different tenants.
    /// </summary>
    public ComparisonResult CompareScans(long oldScanId, long newScanId, string? category = null, int? limit = null)
        => _comparisonEngine.Compare(oldScanId, newScanId, string.IsNullOrWhiteSpace(category) ? null : category, limit);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<long, RiskDelta> _riskDeltaCache = new();

    private void InvalidateRiskDeltas() => _riskDeltaCache.Clear();

    /// <summary>
    /// Risk delta vs the previous Completed/CompletedWithErrors scan of the same tenant (O3), over the
    /// categories completed in both. HasPrevious is false when there is no earlier scan.
    /// </summary>
    public RiskDelta GetRiskDelta(long scanId)
    {
        if (_riskDeltaCache.TryGetValue(scanId, out var cached)) return cached;

        var scan = _scanRepo.GetById(scanId)
            ?? throw new KeyNotFoundException($"Scan {scanId} not found");

        var previous = _scanRepo.GetAll(200, scan.TenantId)
            .FirstOrDefault(s => s.Id < scanId &&
                (s.Status is ScanStatus.Completed or ScanStatus.CompletedWithErrors));

        var delta = new RiskDelta { ScanId = scanId, PreviousScanId = previous?.Id };
        if (previous == null) return delta;

        var cmp = _comparisonEngine.Compare(previous.Id, scanId, limit: 0);
        delta.NewCritical = cmp.NewCriticalCount;
        delta.NewHigh = cmp.NewHighCount;
        delta.TotalAdded = cmp.AddedCount;
        delta.TotalRemoved = cmp.RemovedCount;
        delta.TotalChanged = cmp.ChangedCount;
        delta.IncludedCategories = cmp.IncludedCategories;
        delta.ExcludedCategories = cmp.ExcludedCategories;
        delta.FlaggedCategories = cmp.FlaggedCategories;

        // Only finished scans are immutable enough to cache.
        if (scan.Status is ScanStatus.Completed or ScanStatus.CompletedWithErrors)
            _riskDeltaCache[scanId] = delta;
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
        // One row past the sheet limit is enough to know a sheet was cut off.
        var result = CompareScans(oldScanId, newScanId, category, ExcelExporter.ComparisonSheetRowLimit + 1);
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

    public Dictionary<string, int> GetRiskSummary(long scanId, string? category = null)
        => _scanRepo.GetRiskSummary(scanId, string.IsNullOrWhiteSpace(category) ? null : category);

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
        InvalidateRiskDeltas();
        AuditLog("database_reset", "Database cleared — all scans, permissions, and logs deleted");
    }

    // ── Policies ────────────────────────────────────────────────

    // Config key holding built-in policy keys the user deleted, so startup doesn't re-insert them.
    private const string SuppressedDefaultsKey = "suppressedDefaultPolicies";

    public List<Policy> GetPolicies()
    {
        var policies = _policyRepo.GetAll();
        PolicyRepository.AnnotateDefaults(policies, DefaultPolicies.GetAll());
        return policies;
    }

    public Policy? GetPolicy(long id)
    {
        var policy = _policyRepo.GetById(id);
        if (policy != null) PolicyRepository.AnnotateDefaults(new[] { policy }, DefaultPolicies.GetAll());
        return policy;
    }

    /// <summary>Create a custom policy. Throws PolicyValidationException when it is invalid.</summary>
    public long CreatePolicy(Policy policy)
    {
        policy.IsDefault = false;
        policy.DefaultKey = "";
        policy.DefaultHash = "";
        ThrowIfInvalid(policy);
        var id = _policyRepo.Create(policy);
        InvalidateRiskDeltas();
        _auditRepo.Log("PolicyCreated", _auth.UserPrincipalName ?? "", $"Created policy: {policy.Name}");
        return id;
    }

    /// <summary>Create a policy from a JSON body, rejecting unknown properties.</summary>
    public long CreatePolicy(JsonElement body)
    {
        var policy = new Policy();
        ApplyPolicyPatch(policy, body);
        return CreatePolicy(policy);
    }

    /// <summary>Replace a policy's definition. Built-in tracking fields are kept from the stored row.</summary>
    public void UpdatePolicy(Policy policy)
    {
        var existing = _policyRepo.GetById(policy.Id)
            ?? throw new KeyNotFoundException($"Policy {policy.Id} not found");
        policy.IsDefault = existing.IsDefault;
        policy.DefaultKey = existing.DefaultKey;
        policy.DefaultHash = existing.DefaultHash;
        ThrowIfInvalid(policy);
        _policyRepo.Update(policy);
        InvalidateRiskDeltas();
        _auditRepo.Log("PolicyUpdated", _auth.UserPrincipalName ?? "", $"Updated policy: {policy.Name}");
    }

    /// <summary>
    /// Merge the properties present in <paramref name="patch"/> onto the stored policy (missing
    /// properties keep their value), validate and save.
    /// </summary>
    public Policy UpdatePolicy(long id, JsonElement patch)
    {
        var policy = _policyRepo.GetById(id) ?? throw new KeyNotFoundException($"Policy {id} not found");
        ApplyPolicyPatch(policy, patch);
        UpdatePolicy(policy);
        return GetPolicy(id)!;
    }

    private static readonly HashSet<string> PolicyWritableProps = new(StringComparer.OrdinalIgnoreCase)
        { "name", "description", "enabled", "severity", "categoryFilter", "conditions", "remediation" };

    // Read-only properties a client may echo back from GET; ignored on write.
    private static readonly HashSet<string> PolicyReadOnlyProps = new(StringComparer.OrdinalIgnoreCase)
        { "id", "isDefault", "defaultKey", "defaultHash", "createdAt", "updatedAt", "isOutdatedDefault", "isModifiedDefault" };

    private static void ApplyPolicyPatch(Policy policy, JsonElement patch)
    {
        if (patch.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException(new() { "Request body must be a JSON object." });

        var errors = new List<string>();
        foreach (var prop in patch.EnumerateObject())
        {
            if (PolicyReadOnlyProps.Contains(prop.Name)) continue;
            if (!PolicyWritableProps.Contains(prop.Name)) { errors.Add($"Unknown property '{prop.Name}'."); continue; }
            try
            {
                switch (prop.Name.ToLowerInvariant())
                {
                    case "name": policy.Name = prop.Value.GetString() ?? ""; break;
                    case "description": policy.Description = prop.Value.GetString() ?? ""; break;
                    case "enabled": policy.Enabled = prop.Value.GetBoolean(); break;
                    case "severity": policy.Severity = prop.Value.GetString() ?? ""; break;
                    case "categoryfilter": policy.CategoryFilter = prop.Value.GetString() ?? ""; break;
                    case "remediation": policy.Remediation = prop.Value.GetString() ?? ""; break;
                    case "conditions": policy.Conditions = ParseConditions(prop.Value, errors); break;
                }
            }
            catch (InvalidOperationException)
            {
                errors.Add($"Property '{prop.Name}' has the wrong type.");
            }
        }
        if (errors.Count > 0) throw new PolicyValidationException(errors);
    }

    private static List<PolicyCondition> ParseConditions(JsonElement value, List<string> errors)
    {
        var list = new List<PolicyCondition>();
        if (value.ValueKind != JsonValueKind.Array) { errors.Add("Property 'conditions' must be an array."); return list; }
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) { errors.Add("Each condition must be an object."); continue; }
            var cond = new PolicyCondition();
            foreach (var p in item.EnumerateObject())
            {
                switch (p.Name.ToLowerInvariant())
                {
                    case "field": cond.Field = p.Value.GetString() ?? ""; break;
                    case "operator": cond.Operator = p.Value.GetString() ?? ""; break;
                    case "value": cond.Value = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText(); break;
                    default: errors.Add($"Unknown condition property '{p.Name}'."); break;
                }
            }
            list.Add(cond);
        }
        return list;
    }

    private static void ThrowIfInvalid(Policy policy)
    {
        var errors = PolicyEngine.Validate(policy);
        if (errors.Count > 0) throw new PolicyValidationException(errors);
    }

    public void DeletePolicy(long id)
    {
        var existing = _policyRepo.GetById(id);
        if (existing == null) return;
        _policyRepo.Delete(id);
        if (existing.IsDefault && existing.DefaultKey.Length > 0)
        {
            var suppressed = GetSuppressedDefaults();
            suppressed.Add(existing.DefaultKey);
            _configRepo.Set(SuppressedDefaultsKey, string.Join(",", suppressed));
        }
        InvalidateRiskDeltas();
        _auditRepo.Log("PolicyDeleted", _auth.UserPrincipalName ?? "", $"Deleted policy #{id} ({existing.Name})");
    }

    private HashSet<string> GetSuppressedDefaults()
        => new((_configRepo.Get(SuppressedDefaultsKey) ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Delete all default policies and re-seed them from built-in definitions (including ones the
    /// user deleted). Custom (non-default) policies are preserved.
    /// </summary>
    public int ResetDefaultPolicies()
    {
        _policyRepo.DeleteDefaults();
        _configRepo.Delete(SuppressedDefaultsKey);
        var report = _policyRepo.SyncDefaults(DefaultPolicies.GetAll(), DefaultPolicies.LegacyNames);
        InvalidateRiskDeltas();
        _auditRepo.Log("PoliciesReset", _auth.UserPrincipalName ?? "", $"Reset {report.Inserted.Count} default policies");
        return report.Inserted.Count;
    }

    /// <summary>What the startup sync of built-in policies changed (for diagnostics and tests).</summary>
    public DefaultPolicySyncReport? LastDefaultPolicySync { get; private set; }

    private void SyncDefaultPolicies()
    {
        try
        {
            var report = _policyRepo.SyncDefaults(DefaultPolicies.GetAll(), DefaultPolicies.LegacyNames, GetSuppressedDefaults());
            LastDefaultPolicySync = report;
            var changes = report.Upgraded.Count + report.LegacyReplaced.Count + report.LegacyRemoved.Count;
            if (changes > 0)
                _auditRepo.Log("PoliciesUpgraded", "system",
                    $"Built-in policies updated: {report.Upgraded.Count + report.LegacyReplaced.Count} upgraded, " +
                    $"{report.Inserted.Count} added, {report.LegacyRemoved.Count} obsolete removed, {report.KeptEdited.Count} edited kept");
        }
        catch (Exception ex)
        {
            try { _logRepo.Insert(null, 1, "Policies", $"Built-in policy upgrade failed: {ex.Message}"); } catch { }
        }
    }

    private void OnPolicyConfigurationWarning(string message)
    {
        try { _logRepo.Insert(_orchestrator?.IsScanning == true ? _orchestrator.ActiveScanId : null, 2, "Policies", message); }
        catch { /* best effort */ }
    }

    /// <summary>The enabled policies an entry matches, most severe first (with remediation advice).</summary>
    public List<PolicyViolation> MatchPolicies(PermissionEntry entry)
        => PolicyEngine.Evaluate(entry, _policyRepo.GetEnabled());

    /// <summary>
    /// Evaluate every row of a scan against the enabled policies, a page at a time. Returns match
    /// counts per policy and the first <paramref name="maxViolations"/> violating rows, most severe first.
    /// </summary>
    public PolicyEvaluationResult EvaluatePolicies(long scanId, string? category = null, int maxViolations = 500)
    {
        if (_scanRepo.GetById(scanId) == null) throw new KeyNotFoundException($"Scan {scanId} not found");
        if (string.IsNullOrWhiteSpace(category)) category = null;
        maxViolations = Math.Clamp(maxViolations, 0, 5000);

        var policies = _policyRepo.GetEnabled();
        var result = new PolicyEvaluationResult { ScanId = scanId, Category = category };
        foreach (var p in policies)
            foreach (var error in PolicyEngine.Validate(p))
                result.Warnings.Add($"{p.Name}: {error}");
        if (policies.Count == 0) return result;

        var counts = policies.ToDictionary(p => p.Id, p => new PolicyMatchCount { PolicyId = p.Id, PolicyName = p.Name, Severity = p.Severity });
        // Keep up to maxViolations rows per severity, then take the most severe overall.
        var buckets = new Dictionary<int, List<PolicyViolationRow>>();
        foreach (var entry in _permRepo.Stream(scanId, category))
        {
            result.EntriesEvaluated++;
            var violations = PolicyEngine.Evaluate(entry, policies);
            if (violations.Count == 0) continue;
            result.EntriesWithViolations++;
            foreach (var v in violations)
                if (counts.TryGetValue(v.PolicyId, out var c)) c.Count++;

            var rank = PolicyEngine.SeverityRank(violations[0].Severity);
            if (!buckets.TryGetValue(rank, out var bucket)) buckets[rank] = bucket = new();
            if (bucket.Count < maxViolations) bucket.Add(new PolicyViolationRow { Entry = entry, Violations = violations });
        }

        result.PerPolicy = counts.Values.Where(c => c.Count > 0)
            .OrderByDescending(c => PolicyEngine.SeverityRank(c.Severity)).ThenByDescending(c => c.Count).ToList();
        result.Violations = buckets.OrderByDescending(b => b.Key).SelectMany(b => b.Value).Take(maxViolations).ToList();
        result.Truncated = result.EntriesWithViolations > result.Violations.Count;
        return result;
    }

    /// <summary>
    /// Re-apply the current enabled policies to the stored rows of a scan (risk is otherwise frozen at
    /// scan time). Updates risk_level/risk_reason in batches.
    /// </summary>
    public RescoreResult RescoreScan(long scanId)
    {
        if (_scanRepo.GetById(scanId) == null) throw new KeyNotFoundException($"Scan {scanId} not found");
        if (_orchestrator?.IsScanning == true && _orchestrator.ActiveScanId == scanId)
            throw new InvalidOperationException("This scan is still running; re-score it after it finishes.");

        var policies = _policyRepo.GetEnabled();
        var result = new RescoreResult { ScanId = scanId };
        const int batchSize = 5000;
        long afterId = 0;
        while (true)
        {
            var page = _permRepo.GetPage(scanId, null, afterId, batchSize);
            if (page.Count == 0) break;
            PolicyEngine.ClassifyBatch(page, policies);
            result.EntriesChanged += _permRepo.UpdateRisk(page.Select(e => (e.Id, e.RiskLevel, e.RiskReason)).ToList());
            result.EntriesScored += page.Count;
            afterId = page[^1].Id;
        }

        result.RiskSummary = _scanRepo.GetRiskSummary(scanId);
        InvalidateRiskDeltas();
        _auditRepo.Log("ScanRescored", _auth.UserPrincipalName ?? "",
            $"Re-scored scan {scanId} with {policies.Count} policies: {result.EntriesChanged:N0} of {result.EntriesScored:N0} rows changed", scanId);
        return result;
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
        PolicyEngine.ConfigurationWarning -= OnPolicyConfigurationWarning;

        // Stop web server (synchronous fallback if StopServerAsync wasn't called)
        _webServer?.Dispose();

        // Close database (WAL checkpoint)
        _db.Dispose();
    }
}
