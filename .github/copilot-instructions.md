# M365Permissions — Copilot Instructions

PowerShell module with a compiled .NET 8 engine that scans Microsoft 365 permissions across SharePoint, Entra ID, Exchange Online, OneDrive, Power BI, Power Platform, Azure RBAC, and Azure DevOps.

## Tech Stack
- **Engine**: .NET 8 class library (C#), compiled to DLLs loaded by PowerShell
- **Database**: SQLite via Microsoft.Data.Sqlite (WAL mode, embedded schema)
- **Web GUI**: C# HttpListener server + Vanilla JS SPA (no frameworks, no build step)
- **Excel Export**: ClosedXML (replaces ImportExcel PowerShell module)
- **Auth**: OAuth2 PKCE delegated flow (browser popup → loopback callback)
- **APIs**: Microsoft Graph REST, SharePoint REST, Exchange Admin REST, Azure DevOps REST
- **Testing**: xUnit (C#) + Pester (PowerShell)
- **CI/CD**: GitHub Actions (build → test → artifact)
- **Publishing**: PSGallery

## Project Structure
```
M365Permissions/
  M365Permissions.sln           # Solution file
  src/
    M365Permissions.Engine/        # .NET 8 class library
      Models/                      # PermissionEntry, ScanInfo, AppConfig, etc.
      Database/                    # SqliteDb, Schema.sql, repositories
      Http/                        # WebServer, ApiRoutes, StaticFiles
      Auth/                        # DelegatedAuth (PKCE), TokenCache
      Graph/                       # GraphClient, SharePointRestClient, ExchangeRestClient
      Scanning/                    # IScanProvider, ScanOrchestrator, scanners
      Export/                      # ExcelExporter, CsvExporter, ComparisonEngine
      Engine.cs                    # Main facade wiring all subsystems
    M365Permissions.Engine.Tests/  # xUnit tests
  module/                          # PowerShell module (published to PSGallery)
    M365Permissions.psd1         # Module manifest
    M365Permissions.psm1         # Entry point (loads DLLs, auto-starts GUI)
    public/                        # 12 exported cmdlet wrappers
    gui/static/                    # SPA frontend (index.html, app.js, style.css)
    lib/                           # Compiled DLLs (created by Build-Module.ps1)
  build/                           # Build + publish scripts
  tests/                           # Pester + GUI smoke tests
```

## Development Workflow
1. Make code changes in `src/M365Permissions.Engine/`
2. Build: `dotnet build M365Permissions.sln`
3. Test C#: `dotnet test M365Permissions.sln`
4. Build module: `pwsh ./build/Build-Module.ps1` (or `-Configuration Debug` for dev)
5. Test PowerShell: `pwsh -c "Invoke-Pester ./tests/M365Permissions.Tests.ps1"`
8. Ensure all changes made would work efficiently and accurately and retries effectively in larger tenants
9. Test GUI manually: Import module → verify pages work in browser
10. Run all scans and verify results
11. Assess if readme or copilot instructions file needs updating


### Local Module Testing
The module requires compiled DLLs in `module/lib/` before it can be imported. Without them, you'll get "Could not load file or assembly" errors.

**Quick local test cycle:**
```powershell
dotnet publish src/M365Permissions.Engine -c Debug -o module/lib
pwsh -NoProfile -c "Import-Module ./module/M365Permissions.psd1 -Force; Get-M365Config"
```

**IMPORTANT: DLL locking**
- .NET DLLs loaded by PowerShell are locked for the lifetime of that PS process
- You CANNOT overwrite `module/lib/` DLLs while the module is loaded in any PS session
- `Remove-Module` frees PS references but does NOT release the .NET assembly lock
- You must **close the PowerShell process** that loaded the module before rebuilding
- The build script (`Build-Module.ps1`) pre-checks for locked DLLs and gives guidance and do so if necessary

## Key Architecture Decisions
- **No external PS module dependencies**: PnP.PowerShell, Pode, ImportExcel are all replaced by compiled C# equivalents
- **SQLite over JSON files**: Enables pagination, search, comparison without loading everything into memory
- **HttpListener over Pode**: Lightweight, no PowerShell runspace isolation issues, proper async/await
- **IAsyncEnumerable streaming**: Scan results stream into SQLite in batches of 500 — no memory bloat
- **OAuth2 PKCE**: Browser-based auth with loopback redirect — no client secrets needed

## API Routes
- `GET /api/status` — Connection status, tenantId, tenantDomain, module version, scan state, refresh token expiry
- `POST /api/connect` — Start OAuth2 PKCE browser auth
- `POST /api/disconnect` — Clear tokens, sign out
- `GET /api/config` / `PUT /api/config` — Read/update configuration
- `POST /api/scan/start` — Start permission scan (body: `{ scanTypes: [...] }`)
- `GET /api/scan/progress` — Current scan progress with logs
- `POST /api/scan/cancel` — Cancel running scan
- `GET /api/scans?tenantId=X` — List scans (filtered by tenant if tenantId provided)
- `GET /api/scans/:id/results` — Paginated results (query: category, search, page, pageSize)
- `GET /api/scans/:id/export` — Download XLSX/CSV (query: format)
- `GET /api/scans/:id/risk-summary` — Risk level distribution for a scan
- `PUT /api/scans/:id` — Update scan notes/tags (body: `{ notes, tags }`)
- `POST /api/compare` — Compare two scans (body: `{ oldScanId, newScanId }`)
- `POST /api/compare/export` — Export comparison as multi-sheet XLSX
- `GET /api/trends?limit=N&tenantId=X` — Trend data points (filtered by tenant if tenantId provided)
- `GET /api/audit?limit=N&action=X&tenantId=X` — Audit log entries (filtered by tenant if tenantId provided)

## Multi-Tenant Support
- Each scan stores `tenant_id` and `tenant_domain` in the scans table
- StatusResponse includes `tenantId` and `tenantDomain` for the currently connected tenant
- GUI stores `state.tenantId` from status polling and uses `tenantQuery()` helper to append `?tenantId=` to all aggregate API calls
- `/api/scans`, `/api/trends`, `/api/audit` all accept optional `tenantId` query parameter for server-side filtering
- Dashboard stats (scan count, total permissions, risk summary, auto-compare) are scoped to the connected tenant
- Scan selectors (results, compare, user lookup, policy evaluate) show only the current tenant's scans
- Trends page has a tenant filter dropdown for analyzing cross-tenant data
- When no tenantId is passed, all data is returned (for explicit "all tenants" views)

## Database Schema
7 tables: `config`, `scans`, `permissions`, `scan_progress`, `comparisons`, `logs`, `audit_log`
- Permissions table has indexes on scan_id, category, principal, target, risk_level
- Permissions have `risk_level` and `risk_reason` columns (populated by RiskClassifier)
- Scans have `notes` and `tags` columns for annotation
- WAL mode enabled for concurrent read/write during scans
- Schema auto-applied from embedded resource on first run

## Key Patterns
- **Risk scoring**: `RiskClassifier` evaluates each permission entry post-batch and assigns Critical/High/Medium/Low/Info risk levels with reasons
- **Audit trail**: All actions (scan start, export, config change) logged to `audit_log` table via `AuditRepository`
- **Database migrations**: `SqliteDb.ApplyMigrations()` adds missing columns/tables for backward compatibility with `AddColumnIfMissing()`
- **Graph pagination**: `IAsyncEnumerable` with `@odata.nextLink` following
- **Throttling**: 429 → Retry-After header, exponential backoff (5^attempt seconds)
- **Batch requests**: 20 requests per Graph $batch call
- **Exchange REST**: InvokeCommand pattern via `/adminapi/beta/{org}/InvokeCommand`
- **Scan orchestrator**: Sequential categories, internal parallelism with SemaphoreSlim
- **Permission entry key**: `{category}|{targetPath}|{principalKey}|{role}|{through}` for comparison

## SQLite Native Library Loading
SQLitePCLRaw's native `e_sqlite3.dll` is NOT automatically discovered when .NET assemblies are loaded inside PowerShell (unlike a standard .NET host). Two things are required in `SqliteDb.cs`:

1. **`NativeLibrary.SetDllImportResolver`** on the `SQLitePCLRaw.provider.e_sqlite3` assembly to probe `runtimes/{rid}/native/` relative to the DLL location
2. **`SQLitePCL.Batteries_V2.Init()`** called after the resolver is registered

Both are guarded by a static `_nativeInitialized` flag. The resolver must be registered **before** `Batteries_V2.Init()`. The `runtimes/` directory must be copied alongside the managed DLLs in `module/lib/`.

## Resource Lifecycle & Cleanup
Proper cleanup is critical because the module runs an HTTP server and holds SQLite connections:

**Cleanup chain on module unload:**
```
Remove-Module / PowerShell.Exiting
  → Cleanup-Engine (PSM1)
    → Engine.StopServerAsync()
      → WebServer.StopAsync() — cancels listen loop, stops HttpListener, awaits task
    → Engine.Dispose()
      → ScanOrchestrator.Shutdown() — cancels scan, disposes CTS, waits for task
      → WebServer.Dispose() — closes listener, disposes CTS
      → SqliteDb.Dispose() — WAL checkpoint + ClearAllPools() (releases file handles)
```

**Key rules:**
- `SqliteDb.Dispose()` must call `SqliteConnection.ClearAllPools()` — otherwise .db/.wal/.shm handles stay locked until GC
- PSM1 registers both `OnRemove` and `PowerShell.Exiting` events for cleanup
- `Remove-Module` does NOT release .NET assembly file locks — only closing the PS process does

## Engine.cs Facade
- Constructor: `Engine(string databasePath)` — single parameter
- `StartServer(int port, string staticFilesPath, bool openBrowser)` — starts HttpListener
- `UpdateConfig(AppConfig)` overload — for PowerShell cmdlets passing full config objects
- `UpdateConfig(Dictionary<string, JsonElement>)` — for API route JSON partial updates
- `StartScanAsync` returns `Task<long>` (wraps `Task.FromResult`) — scan runs via `Task.Run` in orchestrator

## GUI Frontend JSON Property Names
C# `JsonNamingPolicy.CamelCase` produces these names. JS must match exactly:
- `connected` (not `isConnected`), `scanning` (not `scanRunning`)
- `activeScanId` (not `currentScanId`), `overallPercent` (not `percentComplete`)

## Common Issues & Fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Unable to load DLL 'e_sqlite3'` | Native resolver not registered | Ensure `SetDllImportResolver` before `Batteries_V2.Init()` |
| `Could not load assembly 'M365Permissions.Engine'` | module/lib/ empty | Run `Build-Module.ps1` or `dotnet publish ... -o module/lib` |
| Build fails "file used by another process" | Module loaded elsewhere | Close that PS session, then rebuild |
| `yield return` in try/catch (CS1626) | C# limitation | Collect into List, yield outside try/catch |
| GUI shows no data | JS property name mismatch | Check `JsonNamingPolicy.CamelCase` output |

## Scanning Scope (Phase 1)
- **SharePoint**: Site admins, role assignments, Graph site permissions, drive item permissions
- **Entra**: Directory roles, app registrations (API permissions), OAuth2 grants, group memberships
- **Exchange**: Mailbox permissions (FullAccess), recipient permissions (SendAs), SendOnBehalf
- **OneDrive**: Site administrators, sharing permissions, external sharing
- **Power BI**: Workspace role assignments (Admin, Member, Contributor, Viewer)
- **Power Platform**: Environment roles, flow ownership/sharing, app permissions, connectors
- **Azure RBAC**: Subscription and resource group role assignments
- **Azure DevOps**: Organization and project-level security group memberships (delegated auth only — SPN org enumeration not supported)

## Azure DevOps Scanner Details
- Uses Azure DevOps REST API with OAuth2 delegated authentication
- Uses the M365Permissions app registration (`0ee7aa45-310d-4b82-9cb5-11cc01ad38e4`) — requires Azure DevOps API permission (`user_impersonation`) to be added to the app registration
- Resource ID: `499b84ac-1321-427f-aa17-267ca6975798` (scope: `user_impersonation`)
- Token acquired via normal refresh token flow (same as Azure RBAC, PowerBI, etc.)
- Enumerates orgs via VSSPS Profile API → Accounts API
- Per org: projects, security groups (VSSPS Graph API), users, group memberships
- Reports project-level roles (Contributors, Readers, Project Administrators, etc.) and org-level roles (Project Collection Administrators)
- SPN-based org enumeration is NOT supported by Azure DevOps — requires delegated auth
- **Setup**: In Entra ID → App registrations → `0ee7aa45-310d-4b82-9cb5-11cc01ad38e4` → API permissions → Add → Azure DevOps → Delegated → user_impersonation → Grant admin consent

## Future Phases
- Phase 2: Devices
- Phase 3: Service Principal auth, Managed Identity auth

## Validation
- After C# changes: `dotnet build && dotnet test`
- After PS changes: `Invoke-Pester ./tests/M365Permissions.Tests.ps1`
- Before publishing: Run full build pipeline via `./build/Build-Module.ps1`
- GUI changes: Refresh browser (no build step needed)
- After lifecycle/cleanup changes: Test full load → remove → re-import cycle in a single pwsh session
