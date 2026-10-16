using System.Text.Json;
using M365Permissions.Engine.Database;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;

namespace M365Permissions.Engine.Http;

/// <summary>
/// Registers all REST API routes on the WebServer.
/// Each route delegates to the Engine facade for actual logic.
/// </summary>
public static class ApiRoutes
{
    public static void Register(WebServer server, Engine engine)
    {
        // ── Status ──────────────────────────────────────────────
        server.Route("GET", "/api/status", async (ctx, _) =>
        {
            await engine.EnsureSessionRestoredAsync();
            var status = engine.GetStatus();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<StatusResponse>.Ok(status));
        });

        // ── Authentication ──────────────────────────────────────
        server.Route("POST", "/api/connect", async (ctx, _) =>
        {
            using var prompt = BeginPrompt(ctx, engine);
            try
            {
                await engine.ConnectAsync(prompt?.Token ?? default);
                var status = engine.GetStatus();
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<StatusResponse>.Ok(status));
            }
            catch (OperationCanceledException)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(SignInCancelled));
            }
            catch (Exception ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // Sign-in URL the GUI should open in its popup (see BeginPrompt), or no data.
        server.Route("GET", "/api/auth/prompt", async (ctx, _) =>
        {
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<Auth.PendingPrompt?>.Ok(engine.Prompt.Claim()));
        });

        server.Route("POST", "/api/auth/cancel", async (ctx, _) =>
        {
            engine.Prompt.CancelGuiOperations();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
        });

        server.Route("POST", "/api/disconnect", async (ctx, _) =>
        {
            engine.Disconnect();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
        });

        server.Route("POST", "/api/reconsent", async (ctx, _) =>
        {
            using var prompt = BeginPrompt(ctx, engine);
            try
            {
                var body = await WebServer.ReadJson<JsonElement>(ctx.Request);
                var scanTypes = new List<string>();
                var includeGraph = true;

                if (body.ValueKind == JsonValueKind.Object)
                {
                    if (body.TryGetProperty("scanTypes", out var st) && st.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var t in st.EnumerateArray())
                            if (t.GetString() is string s) scanTypes.Add(s);
                    }

                    if (body.TryGetProperty("includeGraph", out var ig) &&
                        (ig.ValueKind == JsonValueKind.True || ig.ValueKind == JsonValueKind.False))
                    {
                        includeGraph = ig.GetBoolean();
                    }
                }

                await engine.ReconsentAsync(scanTypes.Count > 0 ? scanTypes : null, includeGraph, prompt?.Token ?? default);
                var status = engine.GetStatus();
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<StatusResponse>.Ok(status));
            }
            catch (OperationCanceledException)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(SignInCancelled));
            }
            catch (Exception ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // ── Configuration ───────────────────────────────────────
        server.Route("GET", "/api/config", async (ctx, _) =>
        {
            var config = engine.GetConfig();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<AppConfig>.Ok(config));
        });

        server.Route("PUT", "/api/config", async (ctx, _) =>
        {
            var update = await WebServer.ReadJson<Dictionary<string, JsonElement>>(ctx.Request);
            if (update == null)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid request body"));
                return;
            }
            engine.UpdateConfig(update);
            var config = engine.GetConfig();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<AppConfig>.Ok(config));
        });

        // ── Scanning ────────────────────────────────────────────
        server.Route("POST", "/api/scan/start", async (ctx, _) =>
        {
            var request = await WebServer.ReadJson<ScanStartRequest>(ctx.Request);
            if (request?.ScanTypes == null || request.ScanTypes.Count == 0)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify at least one scan type"));
                return;
            }

            using var prompt = BeginPrompt(ctx, engine);
            try
            {
                var result = await engine.StartScanDetailedAsync(request.ScanTypes, prompt?.Token ?? default);
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<ScanStartResult>.Ok(result));
            }
            catch (OperationCanceledException)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(SignInCancelled));
            }
            catch (InvalidOperationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 409, ApiResponse.Fail(ex.Message));
            }
            catch (Auth.OAuthCallbackException ex)
            {
                // Consent/sign-in returned an error (e.g. the user declined, or an admin-consent
                // requirement the signed-in account can't satisfy). Without this, the scan-start
                // POST surfaced only a generic 500 and the "Start Scan" button looked dead.
                await WebServer.WriteJson(ctx.Response, 403, ApiResponse.Fail(
                    $"Consent required to start this scan but it did not complete: {ex.Message}. " +
                    "Ask a Global Administrator to grant consent, or deselect the scan types that need it."));
            }
            catch (TimeoutException ex)
            {
                // The interactive consent/sign-in that runs before the scan waits up to 5 minutes
                // for the browser redirect. If it never comes back (tab closed, consent blocked),
                // report that plainly instead of hanging behind a generic 500.
                await WebServer.WriteJson(ctx.Response, 504, ApiResponse.Fail(
                    $"Timed out waiting for sign-in/consent to start the scan: {ex.Message}"));
            }
            catch (Exception ex)
            {
                await WebServer.WriteJson(ctx.Response, 500, ApiResponse.Fail(
                    $"Failed to start scan: {ex.Message}"));
            }
        });

        server.Route("GET", "/api/scan/progress", async (ctx, _) =>
        {
            var progress = engine.GetScanProgress();
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<AggregatedProgress?>.Ok(progress));
        });

        server.Route("POST", "/api/scan/cancel", async (ctx, _) =>
        {
            engine.CancelScan();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
        });

        // Persisted per-category progress + logs (survive engine restarts / long scans).
        server.Route("GET", "/api/scans/:id/progress", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId)) { await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID")); return; }
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<ScanProgress>>.Ok(engine.GetPersistedProgress(scanId)));
        });

        server.Route("GET", "/api/scans/:id/logs", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId)) { await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID")); return; }
            var q = ctx.Request.QueryString;
            int? maxLevel = int.TryParse(q["level"], out var lv) ? lv : null;
            var category = q["category"];
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<LogEntry>>.Ok(engine.GetScanLogs(scanId, maxLevel, category)));
        });

        server.Route("GET", "/api/scans/:id/risk-delta", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId)) { await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID")); return; }
            try
            {
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<RiskDelta>.Ok(engine.GetRiskDelta(scanId)));
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
        });

        // Re-apply the current policies to a scan's stored rows.
        server.Route("POST", "/api/scans/:id/rescore", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId)) { await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID")); return; }
            try
            {
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<RescoreResult>.Ok(engine.RescoreScan(scanId)));
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
            catch (InvalidOperationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 409, ApiResponse.Fail(ex.Message));
            }
        });

        server.Route("DELETE", "/api/scans/:id", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId)) { await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID")); return; }
            try
            {
                if (engine.DeleteScan(scanId))
                    await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
                else
                    await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail("Scan not found"));
            }
            catch (InvalidOperationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 409, ApiResponse.Fail(ex.Message));
            }
        });

        server.Route("GET", "/api/scans/:id/insights", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<Dictionary<string, Dictionary<string, long>>>.Ok(engine.GetScanInsights(scanId)));
        });

        server.Route("GET", "/api/version", async (ctx, _) =>
        {
            var info = await engine.CheckForUpdateAsync();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<VersionInfo>.Ok(info));
        });

        server.Route("GET", "/api/scan/throttle", async (ctx, _) =>
        {
            var metrics = engine.GetThrottleMetrics();
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<ThrottleMetrics?>.Ok(metrics));
        });

        server.Route("POST", "/api/scan/precheck", async (ctx, _) =>
        {
            var body = await WebServer.ReadJson<JsonElement>(ctx.Request);
            var scanTypes = new List<string>();
            if (body.TryGetProperty("scanTypes", out var st) && st.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in st.EnumerateArray())
                    if (t.GetString() is string s) scanTypes.Add(s);
            }

            if (scanTypes.Count == 0)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("No scan types specified"));
                return;
            }

            using var prompt = BeginPrompt(ctx, engine);
            try
            {
                var results = await engine.CheckPermissionsAsync(scanTypes, prompt?.Token ?? default);
                await WebServer.WriteJson(ctx.Response, 200,
                    ApiResponse<Dictionary<string, List<string>>>.Ok(results));
            }
            catch (OperationCanceledException)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(SignInCancelled));
            }
            catch (Auth.OAuthCallbackException ex)
            {
                await WebServer.WriteJson(ctx.Response, 403, ApiResponse.Fail(
                    $"Consent required for the pre-check but it did not complete: {ex.Message}"));
            }
            catch (Exception ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail($"Pre-check failed: {ex.Message}"));
            }
        });

        // ── Scan Results ────────────────────────────────────────
        server.Route("GET", "/api/scans", async (ctx, _) =>
        {
            var tenantId = ctx.Request.QueryString["tenantId"];
            if (!int.TryParse(ctx.Request.QueryString["limit"], out var limit) || limit < 1) limit = 50;
            var scans = engine.GetScans(tenantId, Math.Min(limit, 1000));
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<ScanInfo>>.Ok(scans));
        });

        server.Route("GET", "/api/scans/:id/categories", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var categories = engine.GetCategories(scanId);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<string>>.Ok(categories));
        });

        server.Route("GET", "/api/scans/:id/results", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }

            var qs = ctx.Request.QueryString;
            var category = qs["category"];
            var search = qs["search"];
            int.TryParse(qs["page"], out var page); if (page < 1) page = 1;
            int.TryParse(qs["pageSize"], out var pageSize); if (pageSize < 1) pageSize = 100;
            var sortColumn = qs["sortColumn"];
            var sortDirection = qs["sortDirection"];

            // Column filters: f_target_type=Site|List, f_access_type=Allow, etc.
            var columnFilters = new Dictionary<string, string>();
            foreach (string? key in qs.AllKeys)
            {
                if (key != null && key.StartsWith("f_", StringComparison.Ordinal))
                {
                    var col = key[2..]; // strip "f_" prefix
                    var val = qs[key];
                    if (!string.IsNullOrEmpty(val))
                        columnFilters[col] = val;
                }
            }

            var results = engine.QueryPermissions(scanId, category, search, page, pageSize,
                sortColumn, sortDirection, columnFilters.Count > 0 ? columnFilters : null);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<PagedResult<PermissionEntry>>.Ok(results));
        });

        server.Route("GET", "/api/scans/:id/export", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }

            var format = ctx.Request.QueryString["format"] ?? "xlsx";
            var category = ctx.Request.QueryString["category"];

            var started = false;
            try
            {
                // CSV is streamed with chunked encoding; validation errors are thrown before onStart.
                await Task.Run(() => engine.ExportScanToStream(scanId, format, category, ctx.Response.OutputStream, (fileName, contentType) =>
                {
                    started = true;
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = contentType;
                    ctx.Response.SendChunked = true;
                    ctx.Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{fileName}\"");
                }));
                ctx.Response.Close();
            }
            catch (KeyNotFoundException) when (!started)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail("Scan not found"));
            }
            catch (InvalidOperationException ex) when (!started)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
            catch when (started)
            {
                try { ctx.Response.Abort(); } catch { /* client gone */ }
            }
        });

        // ── User Permissions Lookup ─────────────────────────────
        server.Route("GET", "/api/scans/:id/user-permissions", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var qs = ctx.Request.QueryString;
            var user = qs["user"];
            if (string.IsNullOrWhiteSpace(user))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify a user search term"));
                return;
            }
            int.TryParse(qs["page"], out var page); if (page < 1) page = 1;
            int.TryParse(qs["pageSize"], out var pageSize); if (pageSize < 1) pageSize = 100;
            var sortColumn = qs["sortColumn"];
            var sortDirection = qs["sortDirection"];

            // Column filters: f_target_type=Site|List, f_access_type=Allow, etc.
            var columnFilters = new Dictionary<string, string>();
            foreach (string? key in qs.AllKeys)
            {
                if (key != null && key.StartsWith("f_", StringComparison.Ordinal))
                {
                    var col = key[2..];
                    var val = qs[key];
                    if (!string.IsNullOrEmpty(val))
                        columnFilters[col] = val;
                }
            }

            var results = engine.QueryUserPermissions(scanId, user, page, pageSize,
                sortColumn, sortDirection, columnFilters.Count > 0 ? columnFilters : null);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<UserPermissionsPage>.Ok(results));
        });

        // Members of a SharePoint group, emitted as rows with Through=SharePointGroup and ParentId=group name.
        server.Route("GET", "/api/scans/:id/sharepoint-group-members", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var qs = ctx.Request.QueryString;
            var group = qs["group"];
            if (string.IsNullOrWhiteSpace(group) || (string.IsNullOrWhiteSpace(qs["targetPath"]) && string.IsNullOrWhiteSpace(qs["targetId"])))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify group and targetPath or targetId"));
                return;
            }
            var members = engine.GetSharePointGroupMembers(scanId, group, qs["targetPath"], qs["targetId"]);
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<List<PermissionEntry>>.Ok(members));
        });

        // ── Group Members Lookup ────────────────────────────────
        server.Route("GET", "/api/scans/:id/group-members", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var groupId = ctx.Request.QueryString["groupId"];
            if (string.IsNullOrWhiteSpace(groupId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify groupId"));
                return;
            }
            var members = engine.GetGroupMembers(scanId, groupId);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<PermissionEntry>>.Ok(members));
        });

        // ── Filter Options ──────────────────────────────────────
        server.Route("GET", "/api/scans/:id/filter-options", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var column = ctx.Request.QueryString["column"];
            var category = ctx.Request.QueryString["category"];
            if (string.IsNullOrWhiteSpace(column))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify column"));
                return;
            }
            var values = engine.GetFilterOptions(scanId, column, category);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<string>>.Ok(values));
        });

        // ── Comparison ──────────────────────────────────────────
        server.Route("POST", "/api/compare", async (ctx, _) =>
        {
            var request = await WebServer.ReadJson<CompareRequest>(ctx.Request);
            if (request == null || request.OldScanId <= 0 || request.NewScanId <= 0)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify oldScanId and newScanId"));
                return;
            }

            try
            {
                // Lists are capped (default 500 each); the counts in the result are complete.
                var limit = Math.Clamp(request.Limit ?? 500, 0, 10_000);
                var result = engine.CompareScans(request.OldScanId, request.NewScanId, request.Category, limit);
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<ComparisonResult>.Ok(result));
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
            catch (ArgumentException ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // ── Comparison Export ───────────────────────────────────
        server.Route("POST", "/api/compare/export", async (ctx, _) =>
        {
            var request = await WebServer.ReadJson<CompareRequest>(ctx.Request);
            if (request == null || request.OldScanId <= 0 || request.NewScanId <= 0)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify oldScanId and newScanId"));
                return;
            }

            try
            {
                var (bytes, fileName, contentType) = engine.ExportComparison(request.OldScanId, request.NewScanId, request.Category);
                ctx.Response.ContentType = contentType;
                ctx.Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{fileName}\"");
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
            catch (ArgumentException ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // ── Risk Summary ────────────────────────────────────────
        server.Route("GET", "/api/scans/:id/risk-summary", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var summary = engine.GetRiskSummary(scanId, ctx.Request.QueryString["category"]);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<Dictionary<string, int>>.Ok(summary));
        });

        // ── Scan Notes & Tags ───────────────────────────────────
        server.Route("PUT", "/api/scans/:id", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var scanId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid scan ID"));
                return;
            }
            var body = await WebServer.ReadJson<JsonElement>(ctx.Request);
            string? notes = null, tags = null;
            if (body.TryGetProperty("notes", out var n)) notes = n.GetString();
            if (body.TryGetProperty("tags", out var t)) tags = t.GetString();

            engine.UpdateScanNotes(scanId, notes, tags);
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
        });

        // ── Trends ──────────────────────────────────────────────
        server.Route("GET", "/api/trends", async (ctx, _) =>
        {
            int.TryParse(ctx.Request.QueryString["limit"], out var limit);
            if (limit < 1) limit = 20;
            var tenantId = ctx.Request.QueryString["tenantId"];
            var trends = engine.GetTrends(limit, tenantId);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<TrendDataPoint>>.Ok(trends));
        });

        // ── User Count ───────────────────────────────────────────
        server.Route("GET", "/api/user-count", async (ctx, _) =>
        {
            var info = await engine.GetUserCountAsync();
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<UserCountInfo?>.Ok(info));
        });

        // ── Audit Log ───────────────────────────────────────────
        server.Route("GET", "/api/audit", async (ctx, _) =>
        {
            int.TryParse(ctx.Request.QueryString["limit"], out var limit);
            if (limit < 1) limit = 100;
            var action = ctx.Request.QueryString["action"];
            var tenantId = ctx.Request.QueryString["tenantId"];
            var entries = engine.GetAuditLog(limit, action, tenantId);
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<AuditEntry>>.Ok(entries));
        });
        // ── Policies ────────────────────────────────────────────────
        server.Route("GET", "/api/policies", async (ctx, _) =>
        {
            var policies = engine.GetPolicies();
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<List<Policy>>.Ok(policies));
        });

        server.Route("POST", "/api/policies", async (ctx, _) =>
        {
            try
            {
                var body = await ReadJsonBody(ctx);
                var id = engine.CreatePolicy(body);
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<object>.Ok(new { id }));
            }
            catch (PolicyValidationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // Properties missing from the body keep their stored value (PATCH semantics).
        server.Route("PUT", "/api/policies/:id", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var policyId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid policy ID"));
                return;
            }
            try
            {
                var body = await ReadJsonBody(ctx);
                var updated = engine.UpdatePolicy(policyId, body);
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<Policy>.Ok(updated));
            }
            catch (PolicyValidationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
        });

        server.Route("DELETE", "/api/policies/:id", async (ctx, p) =>
        {
            if (!long.TryParse(p.GetValueOrDefault("id"), out var policyId))
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Invalid policy ID"));
                return;
            }
            engine.DeletePolicy(policyId);
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse.Ok());
        });

        // Whole-scan evaluation: counts per policy plus the first violating rows (most severe first).
        server.Route("POST", "/api/policies/evaluate", async (ctx, _) =>
        {
            try
            {
                var body = await ReadJsonBody(ctx);
                long scanId = 0;
                string? category = null;
                int maxViolations = 500;
                if (body.ValueKind == JsonValueKind.Object)
                {
                    if (body.TryGetProperty("scanId", out var sid) && sid.ValueKind == JsonValueKind.Number) scanId = sid.GetInt64();
                    if (body.TryGetProperty("category", out var cat) && cat.ValueKind == JsonValueKind.String) category = cat.GetString();
                    if (body.TryGetProperty("maxViolations", out var mv) && mv.ValueKind == JsonValueKind.Number) maxViolations = mv.GetInt32();
                }
                if (scanId <= 0)
                {
                    await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Specify scanId"));
                    return;
                }
                var result = await Task.Run(() => engine.EvaluatePolicies(scanId, category, maxViolations));
                await WebServer.WriteJson(ctx.Response, 200, ApiResponse<PolicyEvaluationResult>.Ok(result));
            }
            catch (KeyNotFoundException ex)
            {
                await WebServer.WriteJson(ctx.Response, 404, ApiResponse.Fail(ex.Message));
            }
            catch (PolicyValidationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail(ex.Message));
            }
        });

        // Enabled policies a permission row matches (with remediation), for the detail panel.
        server.Route("POST", "/api/policies/match", async (ctx, _) =>
        {
            PermissionEntry? entry;
            try { entry = await WebServer.ReadJson<PermissionEntry>(ctx.Request); }
            catch (JsonException) { entry = null; }
            if (entry == null)
            {
                await WebServer.WriteJson(ctx.Response, 400, ApiResponse.Fail("Send a permission entry"));
                return;
            }
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<List<PolicyViolation>>.Ok(engine.MatchPolicies(entry)));
        });

        server.Route("POST", "/api/policies/reset-defaults", async (ctx, _) =>
        {
            var count = engine.ResetDefaultPolicies();
            await WebServer.WriteJson(ctx.Response, 200,
                ApiResponse<object>.Ok(new { count, message = $"Reset {count} default policies" }));
        });

        // ── Database Management ─────────────────────────────────

        server.Route("GET", "/api/database", async (ctx, _) =>
        {
            var info = engine.GetDatabaseInfo();
            await WebServer.WriteJson(ctx.Response, 200, ApiResponse<DatabaseInfo>.Ok(info));
        });

        server.Route("POST", "/api/database/reset", async (ctx, _) =>
        {
            try
            {
                engine.ResetDatabase();
                await WebServer.WriteJson(ctx.Response, 200,
                    ApiResponse<object>.Ok(new { message = "Database reset successfully" }));
            }
            catch (InvalidOperationException ex)
            {
                await WebServer.WriteJson(ctx.Response, 409,
                    ApiResponse<object?>.Fail(ex.Message));
            }
        });
    }

    private const string SignInCancelled = "Sign-in was cancelled.";

    /// <summary>
    /// For requests sent with X-M365-Prompt: gui, hand sign-in URLs to the GUI (which opens and closes
    /// its own popup) instead of the system browser, until the returned operation is disposed.
    /// </summary>
    /// <summary>Read the request body as JSON; malformed JSON becomes a PolicyValidationException (400).</summary>
    private static async Task<JsonElement> ReadJsonBody(System.Net.HttpListenerContext ctx)
    {
        try { return await WebServer.ReadJson<JsonElement>(ctx.Request); }
        catch (JsonException ex) { throw new PolicyValidationException(new() { $"Invalid JSON: {ex.Message}" }); }
    }

    private static Auth.BrowserPrompt.GuiOperation? BeginPrompt(System.Net.HttpListenerContext ctx, Engine engine)
        => string.Equals(ctx.Request.Headers["X-M365-Prompt"], "gui", StringComparison.OrdinalIgnoreCase)
            ? engine.Prompt.BeginGuiOperation()
            : null;

    // ── Request DTOs ────────────────────────────────────────────
    private sealed class ScanStartRequest
    {
        public List<string> ScanTypes { get; set; } = new();
    }

    private sealed class CompareRequest
    {
        public long OldScanId { get; set; }
        public long NewScanId { get; set; }
        public string? Category { get; set; }
        public int? Limit { get; set; }
    }
}
