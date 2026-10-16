using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Azure DevOps organizations, projects, and group memberships.
/// Uses the Azure DevOps REST API with delegated (user_impersonation) authentication.
/// SPN-based org enumeration is not supported by Azure DevOps, so this requires delegated auth.
/// </summary>
public sealed class AzureDevOpsScanner : IScanProvider
{
    public string Category => "AzureDevOps";

    private readonly DelegatedAuth _auth;
    private readonly ResilientHttpClient _http;

    public AzureDevOpsScanner(DelegatedAuth auth)
    {
        _auth = auth;
        _http = new ResilientHttpClient(auth);
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Connecting to Azure DevOps...", 3);

        // Step 1: Get the authenticated user's member ID
        string memberId;
        try
        {
            memberId = await GetMemberIdAsync(ct);
        }
        catch (ResourcePrincipalNotFoundException)
        {
            // DevOps not usable in this context (HTML sign-in page / no org). Let the orchestrator
            // mark the category Skipped with a clear reason rather than a cryptic JSON crash.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException($"Cannot access Azure DevOps profile: {ex.Message}", ex);
        }

        // Step 2: Enumerate organizations the user has access to
        List<(string AccountId, string AccountName, string AccountUri)> organizations;
        try
        {
            organizations = await GetOrganizationsAsync(memberId, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ResourcePrincipalNotFoundException)
        {
            throw new InvalidOperationException($"Failed to enumerate Azure DevOps organizations: {ex.Message}", ex);
        }

        if (organizations.Count == 0)
        {
            context.ReportProgress("No Azure DevOps organizations found for this user.", 3);
            yield break;
        }

        context.ReportProgress($"Found {organizations.Count} Azure DevOps organization(s).", 3);

        var totals = new ScanTotals();
        foreach (var (accountId, orgName, _) in organizations)
        {
            ct.ThrowIfCancellationRequested();
            context.ReportProgress($"Scanning organization: {orgName}...", 3);

            List<PermissionEntry> orgEntries;
            try
            {
                orgEntries = await ScanOrganizationAsync(accountId, orgName, totals, context, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                context.MarkPartial($"Azure DevOps organization '{orgName}' could not be scanned: {ex.Message}");
                continue;
            }

            totals.Entries += orgEntries.Count;
            foreach (var entry in orgEntries)
                yield return entry;
        }

        context.ReportProgress($"Completed Azure DevOps scan. Found {totals.Entries} permission entries.", 3);
    }

    /// <summary>Collect all entries for one organization. Throws when projects or groups cannot be listed.</summary>
    private async Task<List<PermissionEntry>> ScanOrganizationAsync(
        string accountId, string orgName, ScanTotals totals, ScanContext context, CancellationToken ct)
    {
        var projects = await GetProjectsAsync(orgName, ct);
        var groups = await GetOrgGroupsAsync(orgName, ct);
        context.ReportProgress($"Found {projects.Count} project(s) and {groups.Count} security group(s) in '{orgName}'.", 4);

        totals.Projects += projects.Count;
        context.SetTotalTargets(totals.Projects);

        var org = new OrgScan(orgName, context);

        // Project-scoped groups
        foreach (var (projectId, projectName, _) in projects)
        {
            ct.ThrowIfCancellationRequested();

            var ok = true;
            foreach (var group in groups.Where(g => g.PrincipalName.StartsWith($"[{projectName}]\\", StringComparison.OrdinalIgnoreCase)))
                ok &= await AddGroupEntriesAsync(org, group, $"AzureDevOps/{orgName}/{projectName}", "Project", projectId, ct);

            if (ok) context.CompleteTarget();
            else context.FailTarget();
        }

        // Org-level groups
        var orgGroups = groups.Where(g =>
            g.PrincipalName.StartsWith($"[{orgName}]\\", StringComparison.OrdinalIgnoreCase) ||
            g.PrincipalName.StartsWith("[TEAM FOUNDATION]\\", StringComparison.OrdinalIgnoreCase));
        foreach (var group in orgGroups)
        {
            ct.ThrowIfCancellationRequested();
            if (!await AddGroupEntriesAsync(org, group, $"AzureDevOps/{orgName}", "Organization", accountId, ct))
                context.MarkPartial($"Members of Azure DevOps group '{group.PrincipalName}' could not be read");
        }

        if (org.Unresolved.Count > 0)
            context.ReportProgress($"{org.Unresolved.Count} member(s) in '{orgName}' could not be resolved by the subject lookup and were not reported.", 2);

        return org.Entries;
    }

    /// <summary>
    /// Expand a group to its users (deduplicated) plus any nested Entra groups and add one entry per principal.
    /// Returns false (after a warning) when the group's membership could not be read.
    /// </summary>
    private async Task<bool> AddGroupEntriesAsync(
        OrgScan org, DevOpsGroup group, string targetPath, string targetType, string targetId, CancellationToken ct)
    {
        Expansion expansion;
        try
        {
            expansion = await ExpandAsync(org, group.Descriptor, new HashSet<string>(StringComparer.OrdinalIgnoreCase), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            org.Context.ReportProgress($"Failed to read members of '{group.PrincipalName}' in '{org.Name}': {ex.Message}", 2);
            return false;
        }

        // Entra groups first: DevOps Graph only returns their members that already exist in the org, so the
        // group row lets the user view resolve access through Entra group membership.
        foreach (var desc in expansion.EntraGroups.Concat(expansion.Users))
        {
            if (org.Subjects.TryGetValue(desc, out var subject))
                org.Entries.Add(MapMember(subject, group, targetPath, targetType, targetId));
            else
                org.Unresolved.Add(desc);
        }
        return true;
    }

    /// <summary>
    /// Recursively expand a group's membership, memoised per descriptor. Users/service principals go into
    /// Users; nested Entra groups are recorded and also expanded. The path set guards against cycles.
    /// </summary>
    private async Task<Expansion> ExpandAsync(OrgScan org, string groupDescriptor, HashSet<string> path, CancellationToken ct)
    {
        if (org.Expansions.TryGetValue(groupDescriptor, out var cached)) return cached;
        if (!path.Add(groupDescriptor)) return Expansion.Empty;

        var direct = await GetGroupMemberDescriptorsAsync(org.Name, groupDescriptor, ct);
        await ResolveMissingAsync(org, direct, ct);

        var result = new Expansion();
        foreach (var memberDesc in direct)
        {
            if (!org.Subjects.TryGetValue(memberDesc, out var subject) ||
                !subject.SubjectKind.Equals("group", StringComparison.OrdinalIgnoreCase))
            {
                result.Users.Add(memberDesc); // unresolved ones are counted when emitting
                continue;
            }

            Expansion nested;
            if (subject.Origin.Equals("aad", StringComparison.OrdinalIgnoreCase))
            {
                result.EntraGroups.Add(memberDesc);
                try
                {
                    nested = await ExpandAsync(org, memberDesc, path, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // The Entra group row itself is still reported.
                    org.Context.ReportProgress($"Could not expand Entra group '{subject.DisplayName}' in '{org.Name}': {ex.Message}", 4);
                    continue;
                }
            }
            else
            {
                nested = await ExpandAsync(org, memberDesc, path, ct);
            }
            result.Users.UnionWith(nested.Users);
            result.EntraGroups.UnionWith(nested.EntraGroups);
        }

        path.Remove(groupDescriptor);
        org.Expansions[groupDescriptor] = result;
        return result;
    }

    // ── API methods ────────────────────────────────────────────

    /// <summary>
    /// Send a request with 429/5xx retry. Throws on any other non-success status; returns a null document
    /// only when a 2xx body is not JSON (the HTML sign-in page Azure DevOps serves for unaccepted tokens).
    /// </summary>
    private async Task<DevOpsResponse> SendAsync(HttpMethod method, string url, string? jsonBody, CancellationToken ct)
    {
        var token = await _auth.GetAccessTokenAsync("azuredevops", ct);
        using var resp = await _http.SendAsync(() =>
        {
            var req = new HttpRequestMessage(method, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (jsonBody != null)
                req.Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
            return req;
        }, ct);

        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Azure DevOps returned HTTP {(int)resp.StatusCode} for {new Uri(url).AbsolutePath}", null, resp.StatusCode);

        var continuation = resp.Headers.TryGetValues("X-MS-ContinuationToken", out var values) ? values.FirstOrDefault() : null;
        var body = await resp.Content.ReadAsStringAsync(ct);
        return new DevOpsResponse(TryParseJson(body), continuation);
    }

    /// <summary>Same as SendAsync but a non-JSON body is an error (used once the token is known to work).</summary>
    private async Task<DevOpsResponse> SendJsonAsync(HttpMethod method, string url, string? jsonBody, CancellationToken ct)
    {
        var resp = await SendAsync(method, url, jsonBody, ct);
        return resp.Doc != null ? resp
            : throw new InvalidOperationException($"Azure DevOps returned a sign-in page instead of data for {new Uri(url).AbsolutePath}.");
    }

    private static ResourcePrincipalNotFoundException NotAccessible() =>
        new("azuredevops", "AzureDevOpsNotAccessible",
            "Azure DevOps returned a sign-in page instead of data. The delegated token was not accepted. " +
            "This usually means the organization requires interactive sign-in (MFA/Conditional Access) or the " +
            "user has no Azure DevOps organization. Skipping Azure DevOps.");

    /// <summary>
    /// Get the authenticated user's member ID from the VSSPS profile API.
    /// </summary>
    private async Task<string> GetMemberIdAsync(CancellationToken ct)
    {
        DevOpsResponse resp;
        try
        {
            resp = await SendAsync(HttpMethod.Get,
                "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1-preview.3", null, ct);
        }
        catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw NotAccessible();
        }

        using (resp)
        {
            if (resp.Doc == null) throw NotAccessible();
            return resp.Doc.RootElement.TryGetProperty("publicAlias", out var alias) ? alias.GetString() ?? ""
                : throw new ResourcePrincipalNotFoundException("azuredevops", "AzureDevOpsNoProfile",
                    "Azure DevOps profile did not include a member id. Skipping Azure DevOps.");
        }
    }

    /// <summary>
    /// Parse a response body as JSON, tolerating the non-JSON responses Azure DevOps sometimes returns
    /// with a 2xx status (an HTML sign-in/error page). Returns null when the body is not JSON.
    /// </summary>
    internal static JsonDocument? TryParseJson(string body)
    {
        var trimmed = body.TrimStart();
        if (trimmed.Length == 0 || trimmed[0] is '<')
            return null;
        try { return JsonDocument.Parse(body); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// Enumerate Azure DevOps organizations accessible to the given member.
    /// </summary>
    private async Task<List<(string AccountId, string AccountName, string AccountUri)>> GetOrganizationsAsync(
        string memberId, CancellationToken ct)
    {
        using var resp = await SendAsync(HttpMethod.Get,
            $"https://app.vssps.visualstudio.com/_apis/accounts?memberId={Uri.EscapeDataString(memberId)}&api-version=7.1-preview.1", null, ct);
        if (resp.Doc == null) throw NotAccessible();

        var results = new List<(string, string, string)>();
        if (resp.Doc.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
        {
            foreach (var acct in val.EnumerateArray())
            {
                var accountId = GetString(acct, "accountId");
                var accountName = GetString(acct, "accountName");
                var accountUri = GetString(acct, "accountUri");
                if (!string.IsNullOrEmpty(accountName))
                    results.Add((accountId, accountName, accountUri));
            }
        }

        return results;
    }

    /// <summary>
    /// Get all projects in an Azure DevOps organization.
    /// </summary>
    private async Task<List<(string Id, string Name, string State)>> GetProjectsAsync(
        string orgName, CancellationToken ct)
    {
        var results = new List<(string, string, string)>();
        var baseUrl = $"https://dev.azure.com/{Uri.EscapeDataString(orgName)}/_apis/projects?$top=500&api-version=7.1";
        string? url = baseUrl;

        while (!string.IsNullOrEmpty(url))
        {
            ct.ThrowIfCancellationRequested();
            using var resp = await SendJsonAsync(HttpMethod.Get, url, null, ct);
            if (resp.Doc!.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
            {
                foreach (var proj in val.EnumerateArray())
                {
                    var id = GetString(proj, "id");
                    var name = GetString(proj, "name");
                    var state = GetString(proj, "state");
                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name))
                        results.Add((id, name, state));
                }
            }

            // Projects - List returns the continuation token in the x-ms-continuationtoken header.
            url = string.IsNullOrEmpty(resp.ContinuationToken)
                ? null
                : $"{baseUrl}&continuationToken={Uri.EscapeDataString(resp.ContinuationToken)}";
        }

        return results;
    }

    /// <summary>
    /// Batch-resolve descriptors not yet in the org's subject cache via the Graph Subject Lookup API.
    /// Descriptors the lookup does not return are remembered so they are not queried again.
    /// </summary>
    private async Task ResolveMissingAsync(OrgScan org, IEnumerable<string> descriptors, CancellationToken ct)
    {
        var missing = descriptors.Where(d => !org.Subjects.ContainsKey(d) && org.LookedUp.Add(d)).Distinct().ToList();
        if (missing.Count == 0) return;

        // Subject Lookup accepts batches; process in chunks to stay within limits
        const int batchSize = 500;
        for (int i = 0; i < missing.Count; i += batchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch = missing.Skip(i).Take(batchSize);
            var json = JsonSerializer.Serialize(new { lookupKeys = batch.Select(d => new { descriptor = d }).ToArray() });

            using var resp = await SendJsonAsync(HttpMethod.Post,
                $"https://vssps.dev.azure.com/{Uri.EscapeDataString(org.Name)}/_apis/graph/subjectlookup?api-version=7.1-preview.1", json, ct);
            if (resp.Doc!.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in val.EnumerateObject())
                    org.Subjects[prop.Name] = ParseSubject(prop.Value, prop.Name);
            }
        }
    }

    internal static DevOpsUser ParseSubject(JsonElement subject, string fallbackDescriptor) => new()
    {
        Descriptor = GetString(subject, "descriptor") is { Length: > 0 } d ? d : fallbackDescriptor,
        DisplayName = GetString(subject, "displayName"),
        MailAddress = GetString(subject, "mailAddress"),
        PrincipalName = GetString(subject, "principalName"),
        OriginId = GetString(subject, "originId"),
        Origin = GetString(subject, "origin"),
        SubjectKind = GetString(subject, "subjectKind"),
        MetaType = GetString(subject, "metaType")
    };

    /// <summary>
    /// Get all security groups in an Azure DevOps organization via the VSSPS Graph API.
    /// </summary>
    private async Task<List<DevOpsGroup>> GetOrgGroupsAsync(string orgName, CancellationToken ct)
    {
        var results = new List<DevOpsGroup>();
        var baseUrl = $"https://vssps.dev.azure.com/{Uri.EscapeDataString(orgName)}/_apis/graph/groups?api-version=7.1-preview.1";
        string? url = baseUrl;

        while (!string.IsNullOrEmpty(url))
        {
            ct.ThrowIfCancellationRequested();
            using var resp = await SendJsonAsync(HttpMethod.Get, url, null, ct);
            if (resp.Doc!.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
            {
                foreach (var group in val.EnumerateArray())
                {
                    results.Add(new DevOpsGroup
                    {
                        Descriptor = GetString(group, "descriptor"),
                        DisplayName = GetString(group, "displayName"),
                        PrincipalName = GetString(group, "principalName"),
                        Domain = GetString(group, "domain"),
                        Origin = GetString(group, "origin")
                    });
                }
            }

            url = string.IsNullOrEmpty(resp.ContinuationToken)
                ? null
                : $"{baseUrl}&continuationToken={Uri.EscapeDataString(resp.ContinuationToken)}";
        }

        return results;
    }

    /// <summary>
    /// Get the member descriptors for a given group (direct members only, direction=Down).
    /// </summary>
    private async Task<List<string>> GetGroupMemberDescriptorsAsync(
        string orgName, string groupDescriptor, CancellationToken ct)
    {
        using var resp = await SendJsonAsync(HttpMethod.Get,
            $"https://vssps.dev.azure.com/{Uri.EscapeDataString(orgName)}/_apis/graph/memberships/{Uri.EscapeDataString(groupDescriptor)}?direction=Down&api-version=7.1-preview.1", null, ct);

        var results = new List<string>();
        if (resp.Doc!.RootElement.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.Array)
        {
            foreach (var membership in val.EnumerateArray())
            {
                var memberDescriptor = GetString(membership, "memberDescriptor");
                if (!string.IsNullOrEmpty(memberDescriptor))
                    results.Add(memberDescriptor);
            }
        }

        return results;
    }

    // ── Helper types ────────────────────────────────────────────

    private sealed class DevOpsResponse(JsonDocument? doc, string? continuationToken) : IDisposable
    {
        public JsonDocument? Doc { get; } = doc;
        public string? ContinuationToken { get; } = continuationToken;
        public void Dispose() => Doc?.Dispose();
    }

    private sealed class ScanTotals
    {
        public int Projects;
        public int Entries;
    }

    /// <summary>Per-organization caches: resolved subjects and memoised group expansions.</summary>
    private sealed class OrgScan(string name, ScanContext context)
    {
        public string Name { get; } = name;
        public ScanContext Context { get; } = context;
        public Dictionary<string, DevOpsUser> Subjects { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LookedUp { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Expansion> Expansions { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Unresolved { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<PermissionEntry> Entries { get; } = new();
    }

    private sealed class Expansion
    {
        public static readonly Expansion Empty = new();
        public HashSet<string> Users { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> EntraGroups { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    internal sealed class DevOpsUser
    {
        public string Descriptor { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string MailAddress { get; set; } = "";
        public string PrincipalName { get; set; } = "";
        public string OriginId { get; set; } = "";
        public string Origin { get; set; } = "";
        public string SubjectKind { get; set; } = "";
        public string MetaType { get; set; } = "";
    }

    internal sealed class DevOpsGroup
    {
        public string Descriptor { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string PrincipalName { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Origin { get; set; } = "";
    }

    // ── Mapping helpers ─────────────────────────────────────────

    internal static PermissionEntry MapMember(DevOpsUser subject, DevOpsGroup group, string targetPath, string targetType, string targetId)
    {
        // originId is the Entra object id only for Entra-backed identities (msa/vsts carry other ids).
        var isEntra = subject.Origin.Length == 0 || subject.Origin.Equals("aad", StringComparison.OrdinalIgnoreCase);
        var isUser = subject.SubjectKind.Equals("user", StringComparison.OrdinalIgnoreCase);
        var upn = isUser && subject.PrincipalName.Contains('@') ? subject.PrincipalName : subject.MailAddress;

        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = targetType,
            TargetId = targetId,
            PrincipalEntraId = isEntra ? subject.OriginId : "",
            PrincipalEntraUpn = upn,
            PrincipalSysId = subject.Descriptor,
            PrincipalSysName = subject.DisplayName,
            PrincipalType = MapPrincipalType(subject.SubjectKind, subject.MetaType),
            PrincipalRole = ExtractRoleName(group.PrincipalName),
            Through = $"Group: {group.DisplayName}",
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }

    /// <summary>
    /// Extract the role name from a principalName like "[ProjectName]\Contributors" to "Contributors"
    /// </summary>
    internal static string ExtractRoleName(string principalName)
    {
        var idx = principalName.LastIndexOf('\\');
        return idx >= 0 ? principalName[(idx + 1)..] : principalName;
    }

    internal static string MapPrincipalType(string? subjectKind, string? metaType = null) => subjectKind?.ToLowerInvariant() switch
    {
        "user" when string.Equals(metaType, "guest", StringComparison.OrdinalIgnoreCase) => "Guest",
        "user" => "User",
        "group" => "SecurityGroup",
        "serviceprincipal" => "Application",
        _ => "Unknown"
    };

    private static string GetString(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
