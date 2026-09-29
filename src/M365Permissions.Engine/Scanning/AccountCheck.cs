using M365Permissions.Engine.Auth;

namespace M365Permissions.Engine.Scanning;

/// <summary>A scan-start finding about the signed-in account. Level uses the log scale (1=Error, 2=Warning, 3=Info).</summary>
public sealed record AccountNote(string Category, string Message, int Level);

/// <summary>
/// Checks the roles (wids) and scopes (scp) in the access tokens a scan will use, so a scan that is
/// bound to return nothing says why up front instead of logging a 403 per target.
/// </summary>
public static class AccountCheck
{
    private static readonly Dictionary<string, string> RoleImpact = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sharepoint"] = "it cannot make itself site collection admin, so sites it does not already own return no permission data",
        ["onedrive"] = "it cannot make itself admin of other users' OneDrives, so those return no permission data",
        ["exchange"] = "Exchange rejects the mailbox queries (HTTP 401/403)",
        ["powerbi"] = "only workspaces the account is a member of are scanned",
        ["powerautomate"] = "only environments, flows and apps the account can see are scanned",
        ["purview"] = "compliance role groups may not be readable"
    };

    /// <param name="categories">Selected scan categories.</param>
    /// <param name="claimsByResource">Parsed access tokens by resource key ("graph", "sharepoint", "exchange", ...). Missing or null entries are skipped.</param>
    /// <param name="unavailable">Resources that could not be used at all (no service principal, consent refused).</param>
    public static List<AccountNote> Evaluate(IEnumerable<string> categories, IReadOnlyDictionary<string, TokenClaims?> claimsByResource,
        IEnumerable<ResourcePrincipalNotFoundException>? unavailable = null)
    {
        var notes = new List<AccountNote>();
        var cats = categories.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var ex in unavailable ?? Enumerable.Empty<ResourcePrincipalNotFoundException>())
            foreach (var cat in cats.Where(c => DelegatedAuth.GetRequiredResourceKeysForCategory(c).Contains(ex.Resource, StringComparer.OrdinalIgnoreCase)))
                notes.Add(ex.NotProvisioned
                    ? new AccountNote(cat, ex.Message, 3)
                    : new AccountNote(cat, ex.Message, 2));

        // Roles: every token belongs to the same user, so pool them. No wids anywhere means unknown, not "none".
        var tokens = claimsByResource.Values.Where(c => c != null).Select(c => c!).ToList();
        var roleSets = tokens.Where(c => c.RoleTemplateIds != null).Select(c => c.RoleTemplateIds!).ToList();
        HashSet<string>? roles = roleSets.Count == 0
            ? null
            : new HashSet<string>(roleSets.SelectMany(r => r), StringComparer.OrdinalIgnoreCase);

        if (roles != null)
        {
            var active = roles.Where(r => !r.Equals(DirectoryRoles.DefaultUserRole, StringComparison.OrdinalIgnoreCase)).ToList();
            var shown = active.Where(DirectoryRoles.IsKnown).Select(DirectoryRoles.NameOf).OrderBy(n => n).ToList();
            if (active.Count > shown.Count) shown.Add($"{active.Count - shown.Count} other role(s)");
            notes.Add(new AccountNote("", shown.Count == 0
                ? "The signed-in account has no active admin roles."
                : $"Active roles: {string.Join(", ", shown)}.", 3));

            foreach (var cat in cats)
            {
                var required = DirectoryRoles.RequiredForCategory(cat);
                if (required.Count == 0 || required.Any(roles.Contains)) continue;

                var impact = RoleImpact.TryGetValue(cat, out var i) ? i : "results will be incomplete";
                notes.Add(new AccountNote(cat,
                    $"The signed-in account is not {DirectoryRoles.DescribeAny(required)}, so {impact}. " +
                    "If the role is PIM-eligible, activate it and start the scan again (tokens are renewed at every scan start).", 1));
            }
        }

        foreach (var cat in cats)
        {
            var gaps = new List<string>();

            foreach (var resource in DelegatedAuth.GetRequiredResourceKeysForCategory(cat))
            {
                if (!claimsByResource.TryGetValue(resource, out var c) || c == null) continue;
                var missing = DelegatedAuth.GetRequiredResourceScopes(resource).Where(s => !c.HasScope(s)).ToList();
                if (missing.Count > 0) gaps.Add(DescribeGap(resource, c, missing));
            }

            if (claimsByResource.TryGetValue("graph", out var graph) && graph != null)
            {
                var missing = DelegatedAuth.GetRequiredGraphScopesForCategory(cat).Where(s => !graph.HasScope(s)).ToList();
                if (missing.Count > 0) gaps.Add(DescribeGap("graph", graph, missing));
            }

            if (gaps.Count > 0)
                notes.Add(new AccountNote(cat,
                    $"{string.Join(" ", gaps)} " +
                    "Run 'Pre-check Permissions' on the Scan page and use 'Re-consent App Permissions'; a Global Administrator may have to approve it.", 2));
        }

        return notes;
    }

    /// <summary>"The SharePoint token lacks AllSites.FullControl (it has: User.Read.All)."</summary>
    private static string DescribeGap(string resource, TokenClaims claims, IEnumerable<string> missing)
    {
        var scopes = claims.Scopes.OrderBy(s => s).ToList();
        var has = scopes.Count == 0 ? "no scopes"
            : string.Join(", ", scopes.Take(10)) + (scopes.Count > 10 ? $" and {scopes.Count - 10} more" : "");
        return $"The {DelegatedAuth.ServiceName(resource)} token lacks {string.Join(", ", missing)} (it has: {has}).";
    }
}
