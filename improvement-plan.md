# M365PermissionsV2 — Improvement Plan

Based on a full read of the codebase (engine, module, GUI, tests, build/CI) on 2026-07-07.
Organized as: verified bugs first (things that are wrong today), then security, accuracy/coverage,
performance, reliability, UX, MSP/multi-tenancy, monitoring, monetization, testing/CI, and docs.
Each item cites the file so it can be picked up directly. A phased roadmap is at the end.

---

## 1. Verified bugs — fix before anything else

These were confirmed by reading the code, not guessed.

### B1. Half the CLI is invisible: manifest exports only 6 of 12 cmdlets
`M365Permissions/M365Permissions.psd1` `FunctionsToExport` lists only `Connect-M365`,
`Disconnect-M365`, `Start-M365Scan`, `Stop-M365Scan`, `Start-M365GUI`, `Stop-M365GUI`.
`Get-M365Permissions`, `Export-M365Permissions`, `Compare-M365Scans`, `Get/Set-M365Config`,
`Get-M365ScanStatus` are dot-sourced but not exported, so users installing from PSGallery
can't call them. The Pester test even asserts all 12 — it would fail if it ran (see B9).

### B2. `Export-M365Permissions` is broken twice over
`M365Permissions/public/Export-M365Permissions.ps1` calls
`$engine.ExportScan($ScanId, $Format.ToLower())` but `Engine.ExportScan(long, string, string? category)`
(`src/M365Permissions.Engine/Engine.cs:367`) has **three required parameters** (no default on
`category`), so method resolution fails. Even with the right arity, the return value is a
`(byte[], string, string)` tuple, and the script writes the whole tuple to disk via
`WriteAllBytes`. This cmdlet can never have worked — a red flag that no end-to-end CLI test exists.

### B3. Several default risk policies can never fire (silent accuracy hole)
`Scanning/DefaultPolicies.cs` conditions don't match what the scanners actually emit:

| Policy | Condition | Scanner reality | Result |
|---|---|---|---|
| "Permanent active admin role" (Critical) | `through` regex `^(DirectoryRole\|Direct)$` | `EntraScanner` emits `Through = "DirectoryRoleAssignment"` | never fires |
| "PIM-eligible critical admin role" (High) | `tenure equals "Eligible"` | scanner emits `"Eligible-Permanent"` / `"Eligible (until …)"` | never fires |
| "Permanent non-critical directory role" (Medium) | `through equals "DirectoryRole"` | `"DirectoryRoleAssignment"` | never fires |
| "Admin-consented OAuth2 grant" (High) | `tenure equals "AllPrincipals"` | `AllPrincipals` is in `principal_type`; tenure is `"Permanent"` | never fires |
| "Anonymous sharing link" (High) | `through contains "Anonymous"` | OneDrive items emit `Through = "Direct"`, anonymity is in `principal_type`/name | never fires |
| "Organization-wide sharing link" (Medium) | `through contains "Organization"` | same as above | never fires |

Net effect: the headline risk features (permanent Global Admins! anonymous links!) silently
report nothing. Fix the conditions **and** add contract tests that run every default policy
against representative `PermissionEntry` objects produced by each scanner (see T2).

### B4. Directory role members truncated at ~20 per role
`EntraScanner.cs:30` uses `directoryRoles?$expand=members`. Graph caps `$expand` results
(20 for this endpoint) and provides no nextLink for the expanded collection. Tenants with
more than ~20 members in a role (very common for large orgs) silently lose members —
the worst possible failure mode for a permission auditing tool. Enumerate
`directoryRoles/{id}/members` per role with pagination (batchable, see P2).

### B5. Adaptive throttling never actually throttles down
`Graph/AdaptiveThrottleManager.cs`: `ReportThrottle()` lowers `_currentMaxConcurrency` but the
semaphore permit is always returned in `GraphClient.ExecuteWithRetry`'s `finally` →
effective concurrency never decreases. Meanwhile `ReportSuccess()` *releases extra permits*,
so concurrency only ratchets **up**. Under sustained 429s the client keeps hammering at max
concurrency. Rewrite with a gate that acquires-without-release when shrinking (or use a
`SemaphoreSlim` swap / token bucket). Add unit tests that assert effective concurrency drops
after `ReportThrottle`.

### B6. Exhausted retries silently produce partial scans marked "Completed"
`GraphClient.ExecuteWithRetry` returns `(null, null)` when `maxRetries` is exhausted
(`GraphClient.cs:222`), so `GetPaginatedAsync` just stops mid-pagination. The orchestrator
then marks the scan Completed. A heavily throttled tenant gets a silently truncated dataset.
Throw on retry exhaustion, let the category be marked Failed, and surface "partial data"
in scan status (see R1).

### B7. Exchange retry logic loses pages
`Graph/ExchangeRestClient.cs:104`: on a transient error the `break` exits the inner
pagination loop and falls straight to `return results` — the "retry from scratch" comment is
wrong; it returns **partial results as success**. In the `catch` path, `results.Clear()` runs
but `nextLink` is not reset, so the retry resumes from the failed page having discarded pages
1..n-1. Either way data is silently lost. Reset `nextLink = null` + `results.Clear()` together
and re-enter via the retry loop only.

### B8. Cancelled scans can leave the scanning account as Site Collection Admin
`SharePointScanner.cs` / `OneDriveScanner.cs` remove the temporary admin in `finally`, but pass
the **same already-cancelled `CancellationToken`** into `RemoveSiteAdmin*(…, ct)`. On user
cancellation the removal request throws immediately and the account stays elevated on that
site/OneDrive — a real tenant-security side effect. Use `CancellationToken.None` (or a fresh
short-timeout token) for cleanup, log a persistent "orphaned elevation" record when cleanup
fails, and add a sweep at scan start that removes leftovers from previous runs.

### B9. Tests are stale and CI publishes without running any tests
- `tests/M365PermissionsV2.Tests.ps1` points at `../module/` which doesn't exist (module lives
  in `M365Permissions/`) — every Pester test errors in `BeforeAll`.
- `.github/workflows/publish.yml` has no `dotnet test`, no Pester, no PSScriptAnalyzer; it
  builds and publishes to PSGallery **on every push to main**. Any push without a version bump
  makes the publish step fail (duplicate version), and a bad commit ships straight to users.
  Gate publishing on version change (or tags), and run the full test matrix first (see T1).

### B10. `IgnoredTemplates` is dead code
`SharePointScanner.cs:21` defines the V1 site-template skip list (`REDIRECTSITE`, `SRCHCEN`,
`APPCATALOG`, …) but never uses it — redirect sites and app catalogs get scanned (wasted time,
noisy results, elevation writes on system sites). `getAllSites` doesn't return the template, so
either fetch it or filter by URL patterns.

### B11. Graph `$batch` drops failures silently and doesn't handle 429
`GraphClient.BatchAsync` ignores non-2xx sub-responses ("can be retried individually by the
caller" — no caller does) and has no batch-level 429/Retry-After handling. Currently unused by
scanners, which is itself the problem — see P2.

### B12. Purview role parsing: dangling-else bug
`PurviewScanner.cs:285-301`: the `else if (rolesVal.ValueKind == JsonValueKind.String)` binds
to the **inner** `if` inside the `foreach`, so a string-valued `Roles`/`RoleAssignments`
property is never captured. Add braces; same for the `RoleAssignments` block.

### B13. Crashed scans stay "Running" forever
Nothing marks stale `Running` scans as Failed on engine startup, and progress lives only in
memory (`scan_progress` table is never written — see B15). Kill the PS window mid-scan and the
scan shows Running forever in the GUI. Add startup recovery: any scan in `Running`/`Pending`
state at `Engine` construction → `Failed ("interrupted")`.

### B14. Five of seven settings are dead
`LogLevel`, `OutputFormat`, `IncludeCurrentUser`, `DefaultTimeoutMinutes`, `MaxJobRetries` are
stored, surfaced in GUI/README… and never read by any code path (verified by grep). Either wire
them up (timeout → per-category `CancellationTokenSource.CancelAfter`; retries → clients;
LogLevel → log filtering; IncludeCurrentUser → scanner-identity filtering that is currently
always-on) or remove them. Shipping visible-but-ignored settings erodes trust.

### B15. `logs` and `scan_progress` tables exist but are never written
Schema + copilot-instructions describe them; orchestrator keeps a 500-line in-memory buffer
instead. Persist logs (respecting LogLevel) so post-mortem debugging of long scans is possible,
and persist progress so the GUI survives engine restarts.

### B16. Assorted small ones
- `Engine.ConnectAsync` fires a `users/$count` request and ignores the result (dead call).
- `ExchangeScanner._graphClient` is injected and never used.
- `OneDriveScanner` fetches `users/{id}/drive` **twice** per user (once for webUrl, once for id).
- `Build-Module.ps1` ends with hard-coded `Import-Module C:\git\M365PermissionsV2\…` — breaks
  on any other machine/path; make it `$repoRoot`-relative.
- `publish-module.ps1` contains an empty `$apiKey = ""` placeholder — delete the file (CI owns
  publishing) before someone pastes a key into it and commits.
- `gui/static/app.js.bak` (74 KB) ships to PSGallery inside the module payload.
- `AzureScanner` loads role definitions only for the first subscription
  (`if (roleCache.Count == 0)`), so custom roles in other subscriptions render as raw GUIDs.
- PowerBI admin call uses `$top=5000` with no pagination — >5000 workspaces are silently cut.
- `PolicyEngine`: `regex` conditions compile a `Regex` per entry per policy — cache compiled
  regexes (matters at 1M+ rows).

---

## 2. Security hardening

### S1. The localhost API is unauthenticated with `Access-Control-Allow-Origin: *` — highest-priority fix
`Http/WebServer.cs:94` sets wildcard CORS on every response, and no endpoint requires any
credential. Consequence: **any web page the user visits** can silently call
`http://localhost:8080/api/scans/{id}/results` and *read the tenant's entire permission
inventory*, call `POST /api/database/reset` (destructive), change config, start/cancel scans,
or trigger `/api/connect` phishing prompts. For a security product this is the first thing a
reviewer will find. Fix:
1. Generate a per-session random token at `StartServer`; inject it into `index.html` (or a
   bootstrap endpoint served only to same-origin requests) and require it on every `/api/*` call.
2. Remove the CORS wildcard entirely — the GUI is same-origin; no CORS is needed.
3. Validate the `Origin`/`Host` headers against `localhost:{port}`.
4. Optional: default to a random free port instead of well-known 8080 (also fixes port
   conflicts, R4).

### S2. OAuth loopback flow lacks `state` validation
`Auth/DelegatedAuth.cs` builds authorize URLs without a `state` parameter and accepts whatever
request hits the loopback listener first. PKCE protects the code exchange, but without `state`
an attacker can complete a *login CSRF* (swap in their own code → the tool ends up signed into
an attacker-controlled tenant, and subsequent "scan results" could be attacker-supplied). Add a
random `state`, verify it on callback, and reject non-matching requests without consuming the
listener. RFC 8252 also recommends binding the listener only for the duration of one flow —
today three near-identical interactive flows exist (`AuthenticateAsync`, `ReconsentAsync`,
`AcquireTokenInteractiveAsync`); collapse them into one parameterized method (~200 lines saved,
one place to add `state`).

### S3. Refresh tokens stored effectively in plaintext on macOS/Linux
`Auth/TokenCache.cs:169`: non-Windows persistence is just base64 in a world-readable file.
These are long-lived refresh tokens for an account that is typically a Global Admin. Use OS
keychains (Keychain / libsecret) or at minimum `File.SetUnixFileMode(path, UserRead|UserWrite)`
(600) and document the residual risk. On Windows, DPAPI is fine.

### S4. GUI loads Chart.js from a CDN
`gui/static/index.html:9` pulls `cdn.jsdelivr.net`. For a security/audit tool this is a
supply-chain and privacy problem (admin workstations often block CDNs; air-gapped tenants get a
broken Trends page). Bundle `chart.umd.min.js` into `gui/static/` (~80 KB) and add basic
security headers to `StaticFiles.Serve` (`Content-Security-Policy: default-src 'self'`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).

### S5. Tenant-modifying elevation should be opt-in and audited
`SharePointRestClient.EnsureSiteAdmin*` **writes** to every site/OneDrive in the tenant
(temporarily adding the scanner as admin). This is defensible (V1 did the same) but today it's
implicit. Make it a visible config switch (`AllowElevation`, default on but shown in the Scan
UI with a warning), write an `audit_log` row for **every** add/remove (today only in transient
logs), and pair with the B8 cleanup fix. This is also an easy differentiator to document
("what will this tool change in my tenant?" is the #1 security-review question).

### S6. Session restore races the first status call
`Engine` constructor kicks off `TryRestoreSessionAsync` on a background task; `GetStatus` waits
up to 5s. Fine — but `_graphClient`/`_orchestrator` initialization inside `InitializeClients()`
is not synchronized against a concurrent `ConnectAsync` (two browser flows can race on the same
fixed port 1985). Serialize interactive auth with a `SemaphoreSlim(1,1)` and fail fast with a
clear message if the loopback port is taken (today: opaque `HttpListenerException`).

---

## 3. Accuracy & coverage gaps (what the scan misses)

### A1. Entra: requested ≠ granted application permissions
`EntraScanner` reads `applications.requiredResourceAccess` — that's what apps *request*, not
what's *granted*. The actually granted app-role assignments live at
`servicePrincipals/{id}/appRoleAssignments`. Today a consented-but-removed-from-manifest
permission is invisible, and a requested-but-never-consented one shows as a finding. Scan
`appRoleAssignments` (+ resolve appRole GUIDs to names via the resource SP's `appRoles`) and
mark entries as Requested vs Granted. This is the single biggest accuracy win in Entra.

### A2. Entra: group owners, transitive membership, guest detection
- Group **owners** are not scanned (owners can add members → privilege path).
- Only direct members are listed; a user in a nested group holding a directory role is missed.
  Use `transitiveMembers` (or flag nested groups distinctly).
- Guests: `userType` is never fetched, so the "Guest/external user access" default policy can
  only match SharePoint's `#ext#` heuristic — Entra/Exchange/Azure guests are never flagged.
  Add `$select=userType` where users are enumerated and set `PrincipalType = "Guest"`.

### A3. SharePoint: README oversells item-level coverage
README claims "Drive/item permissions (sharing links, direct grants)" for SharePoint, but
`SharePointScanner` only reads site admins + web-level role assignments + Graph site
permissions. `GetListsAsync`/`GetDriveItemPermissionsAsync` exist on the client and are never
called. fix the README.
Same for OneDrive

### A4. Exchange: folder-level permissions plumbed but unused
`ExchangeRestClient.GetMailboxFolderStatisticsAsync`/`GetMailboxFolderPermissionsAsync` accepted, no need to fix.

### A5. Azure: management groups, PIM, and per-sub custom roles
Only subscription-scope `atScope()` assignments are scanned. Missing: management-group
assignments (often where Owner lives!), Azure PIM eligible role assignments
(`roleEligibilitySchedules` on ARM), and resource-scope assignments. Plus the per-subscription
custom-role cache bug (B16).

### A6. Teams is absent
For a "360° permission visibility" pitch, Teams (team owners/members/guests, channel
memberships incl. private/shared channels) is the most conspicuous missing category — and it's
cheap: it's all Graph (`/teams`, `/channels`, `/members`), no elevation tricks needed. High
marketing value per engineering hour.

### A7. Comparison engine can mislead
`Export/ComparisonEngine.cs` keys on `category|target_path|principal|role|through` and
`TryAdd`s — duplicate keys (e.g. same principal with two sharing links on one path) are
silently collapsed, so a removed second grant is invisible. Include a discriminator (target_id,
link id) or count duplicates. Also loads both scans fully into memory — do it in SQL
(`LEFT JOIN` on the key) to survive million-row scans.

---

## 4. Performance & large-tenant scalability

### P1. Parallelize per-target work — the #1 wall-clock win
Every scanner iterates targets **sequentially** (sites, mailboxes, users, groups). With ~6
round-trips per SharePoint site and 4 per OneDrive user, a 10k-user tenant takes days. The
`MaxThreads` setting only sizes the Graph semaphore, which sequential callers never saturate —
it's effectively a no-op today. Introduce a shared `Parallel.ForEachAsync(targets,
MaxDegreeOfParallelism = config.MaxThreads)` pattern per scanner (yielding through a
`Channel<PermissionEntry>` since `IAsyncEnumerable` writers can't be concurrent). This
composes with the throttle-manager fix (B5): concurrency ramps down on 429s.

### P2. Use Graph `$batch` for the N+1 hotspots
Group members (1 call/group), directory-role members (B4 fix), OneDrive drive lookups —
batching 20 requests per call cuts Entra scan requests ~20x. `BatchAsync` exists; fix B11 and
actually use it.

### P3. Streamed export instead of full materialization
`Engine.ExportScan` → `PermissionRepository.GetAll` loads the entire scan into RAM, then
ClosedXML holds the whole workbook. At 1M+ rows this OOMs a default PS session. Stream: page
through SQLite (`ORDER BY id LIMIT/OFFSET` or a cursor), write CSV incrementally to the
response stream; for XLSX use OpenXML SAX writing or cap with a "use CSV above N rows" warning.
Same for `EvaluatePolicies` (loads all, then `Take(limit)` — push `LIMIT` into SQL).

### P4. FTS for search
Results search uses `LIKE '%x%'` across four columns — full table scan per keystroke on large
scans. Add an FTS5 shadow table (or at least debounce + require 3 chars in the GUI, which costs
nothing).

### P5. Non-Graph clients have zero retry/throttle handling
PowerBI, Flow/PowerApps/BAP, ARM, DevOps calls are raw `HttpClient` sends: no 429 handling, no
retry, no metrics. Power Platform APIs throttle aggressively. Extract a small
`ResilientHttpClient` (shared retry/backoff/Retry-After + throttle metrics) and route all
scanners through it — also fixes the "one `HttpClient` per scanner class, never disposed"
pattern.

---

## 5. Reliability

- **R1. Partial-failure visibility**: a category that fails mid-scan still yields a scan marked
  `Completed` (orchestrator swallows the exception; only a transient log line notes it). Add a
  `CompletedWithErrors` status + per-category status persisted on the scan row; show a warning
  banner in Results/exports ("Exchange failed after 40%").
- **R2. Honor `DefaultTimeoutMinutes`** with a per-scan `CancelAfter`; a hung HTTP call
  currently stalls a category forever (HttpClient default 100s helps but paginated loops can
  run unbounded).
- **R3. Crash recovery** (B13) + persistent progress/logs (B15).
- **R4. GUI port conflicts**: `StartServer(8080)` throws if the port is busy (another PS session,
  or IIS Express). Auto-increment to the next free port and print the actual URL; combine with
  S1's random-port option.
- **R5. Graceful client disconnects**: the catch-all in `WebServer.ListenLoop` writes a 500 to a
  response that may already be broken (`HttpListenerException` on client abort) — swallow those
  specifically so logs aren't polluted.
- **R6. Refresh-token expiry UX**: the dashboard shows expiry, but nothing warns before it
  lapses. Toast + audit entry at <7 days; proactively refresh the RT during long scans (rolling
  refresh already happens implicitly per token grant — verify and test it).

---

## 6. Usability & UX

- **U1. CLI parity and polish**: export the missing cmdlets (B1), fix `Export-M365Permissions`
  (B2), add `-Category/-OutputPath` tab completion, a `-Wait` switch on `Start-M365Scan` with a
  progress bar (poll `GetScanProgress`), and `Get-M365Permissions -All` that streams pages.
  Add a `format.ps1xml` so `PagedResult`/`PermissionEntry` render as tables, not property soup.
- **U2. Settings page honesty**: after B14, every visible setting does something; add inline
  descriptions of what each affects ("MaxThreads: parallel targets per category").
- **U3. First-run experience**: on first GUI load, a 3-step wizard — connect → pick scan types
  (with pre-check results inline and "you're missing role X" remediation links) → start. The
  pre-checker (`PermissionPreChecker`) is excellent; surfacing it *before* a 6-hour scan fails
  is the payoff.
- **U4. Scan ETA**: totals are known after enumeration; show "≈ N targets, ~M req/target at
  current RPS ⇒ ETA hh:mm" using existing throttle metrics.
- **U5. Results deep links**: hash-router already exists; encode scan id + filters in the URL so
  a finding can be shared/bookmarked ("here's the anonymous-links view").
- **U6. Accessibility & i18n basics**: the SPA uses emoji-only buttons (`⏏`) — add `aria-label`s;
  color-only risk badges need text labels for color-blind users (they have text — verify contrast
  in both themes).
- **U7. Drop `app.js.bak` from the shipped module** and consider splitting the 128 KB `app.js`
  into modules loaded via `<script type="module">` (still no build step).

---

## 7. Multi-tenancy & MSP scenarios

Current model: one token cache (`.rt` file), one DB; switching tenants = disconnect+reconnect;
scans are tagged with tenant_id and the GUI filters on the connected tenant. Good foundation —
next steps, in order of MSP value:

- **M1. Named tenant profiles**: per-tenant token cache files (`.rt.{tenantId}`) so switching
  tenants doesn't force re-auth every time. A tenant dropdown in the nav bar (populated from
  profiles) replacing disconnect→reconnect. This alone converts "multi-tenant capable" into
  "MSP-friendly".
- **M2. Unattended/scheduled runs**: an app-only (client credential) auth mode is the real MSP
  unlock, but it changes the permission model (application perms + Sites.Read.All app consent,
  and elevation tricks stop working) — position it as *the* m365permissions.com upsell instead
- **M3. Cross-tenant rollup**: an "All tenants" dashboard view (the API already supports
  `tenantId=null`) with per-tenant risk score cards — the MSP screenshot for reports.
- **M4. Per-tenant DB option** (`data.{tenantId}.db`) for MSPs with data-isolation requirements,
  selectable in Settings.
- **M5. Comparison guardrails**: auto-compare already restricts to same tenant; make manual
  compare warn when scans span tenants.

---

## 8. Monitoring & observability

- **O1. Persist logs** (B15) with level filtering honored (`LogLevel` setting) and a Logs page
  in the GUI (filter by scan/category/level).
- **O2. Completion notifications**: config for a webhook URL (Teams/Slack-compatible card) +
  optional SMTP — fired on scan complete/fail with risk-summary delta vs previous scan. This is
  the retention feature: it turns a one-shot tool into a monitoring loop. -> skip this item
- **O3. Risk-delta alerts**: "N new Critical findings since last scan" as the notification
  headline (the comparison engine already computes this).
- **O4. Metrics history**: persist per-scan throttle metrics (total requests, throttle count,
  RPS, duration) to give large-tenant users tuning feedback and give support ("send me the scan
  stats") a tool.
- **O5. Optional anonymous telemetry** (opt-in, documented): version, scan sizes, durations,
  error codes. Directly informs which scanners break in the wild. -> skip this one

---

## 9. Monetization / upsell to m365permissions.com

The user-count-based recommendation (`Engine.GetUserCountAsync`) exists; make the funnel
contextual instead of demographic:

- **$1. Trigger on experienced pain, not tenant size**: after a scan that took >2h, was
  throttled >100 times, or hit >250k permissions — "This scan took 6h and was throttled 312
  times. The hosted version scans with app-only auth on managed infra." Convert at the moment
  of pain, quietly (dismissible toast + a dashboard card, never a modal), but also keep the pre-scan advice.
- **$2. Feature-shaped upsell**: greyed-out "Scheduled scans", "Email/Teams alerts",
  "Item level scan" buttons in the GUI → one-line explainer + link. Honest scope:
  local = interactive top level snapshots; hosted = continuous item level monitoring.
- **$3. Report footer**: exported XLSX Summary sheet + CSV header comment gain a
  "Generated by M365Permissions — Enterprise version: m365permissions.com" line. Reports travel to
  execs; the module doesn't.
- **$4. Version/update check**: on GUI load, check PSGallery for a newer version (cache 24h,
  fail silent); a changelog toast keeps users current and gives a periodic branded touchpoint.
- **$5. License clarity in-product**: Settings page shows the "free for non-commercial use"
  line with the commercial-use link — converts the compliance-minded (exactly the audience).

---

## 10. Testing & CI

- **T1. Fix the pipeline order**: `publish.yml` should run `dotnet build` → `dotnet test` →
  fixed Pester suite (`module/` → `M365Permissions/`) → PSScriptAnalyzer → publish, and publish
  only when `ModuleVersion` changed (compare against PSGallery) or on a tag. Keep the
  preview/production switch.
- **T2. Policy⇄scanner contract tests**: for each scanner, a fixture `PermissionEntry` set (the
  values it actually emits) evaluated against `DefaultPolicies.GetAll()` asserting which
  policies fire. This makes B3-class regressions impossible.
- **T3. Scanner mapping tests with recorded JSON**: the mappers (`MapRoleAssignment`,
  `MapMailboxPermission`, `MapDriveItemPermission`, …) are pure functions taking `JsonElement` —
  ideal for fixture-based tests using anonymized captured API responses. Cheap, high coverage
  of the trickiest code.
- **T4. Throttle manager tests** (B5) and retry-path tests for Graph/EXO clients using a fake
  `HttpMessageHandler` (429 sequences, mid-pagination failures ⇒ assert no data loss).
- **T5. Cmdlet smoke tests**: import built module in CI, call every exported cmdlet against a
  temp DB with the engine mocked/offline where needed — would have caught B1/B2 immediately.
- **T6. GUI**: extend `test-gui.ps1` to assert the security headers/token from S1, and add it to CI
  (it only needs the engine, no tenant).

---

## 11. Documentation

- **D1. Fix drift**: READMEINTERNAL/copilot-instructions say `module/`, "12 exported cmdlets",
  "sequential categories", `M365Permissions.sln` — all wrong vs reality (`M365Permissions/`,
  6 exported, parallel categories, `M365PermissionsV2.sln`). Stale agent instructions actively
  mislead future AI/contributor sessions.
- **D2. "What does this tool change in my tenant?" section**: document the temporary site-admin
  elevation (S5), consent grants per scan type (the `GraphScopesByCategory` /
  `ResourceKeysByCategory` tables render nicely as a permissions matrix), and token storage
  locations. Security reviewers approve tools that answer this up front.
- **D3. Scan-coverage honesty** (A3): align README claims with implemented coverage, and add a
  roadmap section for gaps — under-promising beats a customer discovering the gap in an audit.
- **D4. Troubleshooting page**: port-in-use, DLL locking (already well documented internally —
  surface it), consent loops, "scan shows Running forever" (until B13 lands).

---

## Suggested roadmap

**Phase 0 — stop the bleeding (days)**
B1, B2, B3, B8, B9/T1, S1, S2, B16 quick wins (`.bak`, publish-module.ps1, hardcoded path).
Ship as 2.0.6. Everything here is either broken-today or exploitable-today.

**Phase 1 — accuracy you can defend (1–2 weeks)**
B4, B6, B7, B10, B12, A1, A2 (guests + owners), A7, T2/T3/T4, D1/D3.
Theme: "the numbers in the report are right." For an audit tool this is the brand.

**Phase 2 — large-tenant performance (1–2 weeks)**
B5, P1, P2, P5, P3, R1, R2, B13/B15, U4.
Theme: 10k-user tenants finish overnight instead of over a weekend, and failures are visible.

**Phase 3 — retention & MSP (2–3 weeks)**
O1–O3, M1, M2 (scheduled local runs), M3, U1, U3, U5, $1–$4, A6 (Teams scanner — headline
feature for the release notes).
Theme: from one-shot audit to recurring monitoring habit, with a natural hosted-version funnel.

**Phase 4 — depth (ongoing)**
A3 item-level SharePoint/OneDrive (config-gated), A4 folder permissions, A5 management
groups/Azure PIM, P4 FTS, M4, S3 keychain integration, O4/O5.

---

*Plan generated from full source review; every bug cited was verified by reading the code path,
not inferred. Companion references: `src/M365Permissions.Engine/**`, `M365Permissions/**`,
`tests/**`, `build/**`, `.github/workflows/publish.yml`.*
