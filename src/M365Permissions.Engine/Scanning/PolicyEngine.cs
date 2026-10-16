using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Evaluates permission entries against policy rules (multi-condition AND logic).
/// Used for both risk classification and compliance flagging.
/// </summary>
public static class PolicyEngine
{
    // Map policy field names to PermissionEntry property accessor
    private static readonly Dictionary<string, Func<PermissionEntry, string>> FieldAccessors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["category"] = e => e.Category,
        ["target_path"] = e => e.TargetPath,
        ["target_type"] = e => e.TargetType,
        ["target_id"] = e => e.TargetId,
        ["principal_entra_id"] = e => e.PrincipalEntraId,
        ["principal_entra_upn"] = e => e.PrincipalEntraUpn,
        ["principal_sys_id"] = e => e.PrincipalSysId,
        ["principal_sys_name"] = e => e.PrincipalSysName,
        ["principal_type"] = e => e.PrincipalType,
        ["principal_role"] = e => e.PrincipalRole,
        ["through"] = e => e.Through,
        ["access_type"] = e => e.AccessType,
        ["tenure"] = e => e.Tenure,
        ["parent_id"] = e => e.ParentId,
    };

    public static IReadOnlyCollection<string> Fields => FieldAccessors.Keys;

    public static readonly IReadOnlyList<string> Operators = new[] { "equals", "notEquals", "contains", "notContains", "startsWith", "regex" };

    public static readonly IReadOnlyList<string> Severities = new[] { "Critical", "High", "Medium", "Low", "Info" };

    // Severity ordering: higher number = more severe
    private static readonly Dictionary<string, int> SeverityOrder = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Info"] = 0, ["Low"] = 1, ["Medium"] = 2, ["High"] = 3, ["Critical"] = 4
    };

    public const string NoRiskReason = "No specific risk identified";
    public const string DenyReason = "Deny entry: blocks access rather than granting it";

    /// <summary>
    /// Raised once per distinct misconfiguration (unknown field, invalid regex) seen while evaluating.
    /// Such a condition never matches, so the policy is silently inert otherwise.
    /// </summary>
    public static event Action<string>? ConfigurationWarning;

    private static readonly ConcurrentDictionary<string, byte> WarnedOnce = new();

    private static void WarnOnce(string message)
    {
        if (WarnedOnce.TryAdd(message, 0))
        {
            try { ConfigurationWarning?.Invoke(message); } catch { /* logging must never break scoring */ }
        }
    }

    /// <summary>
    /// Classify a single permission entry: evaluate all enabled policies, pick highest severity.
    /// Sets entry.RiskLevel and entry.RiskReason. Deny rows are Info: they remove access.
    /// </summary>
    public static void Classify(PermissionEntry entry, IReadOnlyList<Policy> policies)
    {
        if (IsDeny(entry))
        {
            entry.RiskLevel = "Info";
            entry.RiskReason = DenyReason;
            return;
        }

        string bestSeverity = "Info";
        string bestReason = NoRiskReason;
        int bestOrder = -1;

        foreach (var policy in policies)
        {
            if (!PolicyMatches(policy, entry)) continue;

            var order = SeverityOrder.GetValueOrDefault(policy.Severity, 1);
            if (order > bestOrder)
            {
                bestOrder = order;
                bestSeverity = policy.Severity;
                bestReason = string.IsNullOrEmpty(policy.Description) ? policy.Name : policy.Description;
            }
        }

        entry.RiskLevel = bestSeverity;
        entry.RiskReason = bestReason;
    }

    /// <summary>
    /// Classify a batch of permission entries using policy rules.
    /// </summary>
    public static void ClassifyBatch(IReadOnlyList<PermissionEntry> entries, IReadOnlyList<Policy> policies)
    {
        foreach (var entry in entries) Classify(entry, policies);
    }

    /// <summary>
    /// Evaluate a single permission entry against all enabled policies.
    /// Returns the matching policies, most severe first (empty if none, always empty for Deny rows).
    /// </summary>
    public static List<PolicyViolation> Evaluate(PermissionEntry entry, IReadOnlyList<Policy> policies)
    {
        var violations = new List<PolicyViolation>();
        if (IsDeny(entry)) return violations;

        foreach (var policy in policies)
        {
            if (!PolicyMatches(policy, entry)) continue;
            violations.Add(new PolicyViolation
            {
                PolicyId = policy.Id,
                PolicyName = policy.Name,
                Severity = policy.Severity,
                Description = policy.Description,
                Remediation = policy.Remediation
            });
        }

        return violations.OrderByDescending(v => SeverityOrder.GetValueOrDefault(v.Severity, 1)).ToList();
    }

    /// <summary>
    /// Evaluate a batch of entries. Returns a dictionary of entry index to violations.
    /// Only entries with violations are included.
    /// </summary>
    public static Dictionary<int, List<PolicyViolation>> EvaluateBatch(
        IReadOnlyList<PermissionEntry> entries, IReadOnlyList<Policy> policies)
    {
        var results = new Dictionary<int, List<PolicyViolation>>();
        for (int i = 0; i < entries.Count; i++)
        {
            var violations = Evaluate(entries[i], policies);
            if (violations.Count > 0)
                results[i] = violations;
        }
        return results;
    }

    public static int SeverityRank(string severity) => SeverityOrder.GetValueOrDefault(severity, -1);

    /// <summary>
    /// Validate a policy before it is saved. Returns human-readable errors (empty = valid) and
    /// normalises severity and operator casing in place.
    /// </summary>
    public static List<string> Validate(Policy policy)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(policy.Name))
            errors.Add("Name is required.");

        var severity = Severities.FirstOrDefault(s => s.Equals(policy.Severity?.Trim(), StringComparison.OrdinalIgnoreCase));
        if (severity == null)
            errors.Add($"Severity '{policy.Severity}' is not valid. Use one of: {string.Join(", ", Severities)}.");
        else
            policy.Severity = severity;

        if (policy.Conditions == null || policy.Conditions.Count == 0)
        {
            errors.Add("At least one condition is required.");
            return errors;
        }

        for (int i = 0; i < policy.Conditions.Count; i++)
        {
            var cond = policy.Conditions[i];
            var label = $"Condition {i + 1}";
            if (cond == null) { errors.Add($"{label} is empty."); continue; }
            if (!FieldAccessors.ContainsKey(cond.Field ?? ""))
                errors.Add($"{label}: unknown field '{cond.Field}'. Use one of: {string.Join(", ", FieldAccessors.Keys)}.");

            var op = Operators.FirstOrDefault(o => o.Equals(cond.Operator?.Trim(), StringComparison.OrdinalIgnoreCase));
            if (op == null)
                errors.Add($"{label}: unknown operator '{cond.Operator}'. Use one of: {string.Join(", ", Operators)}.");
            else
                cond.Operator = op;

            cond.Value ??= "";
            if (op == "regex")
            {
                try { _ = new Regex(cond.Value, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)); }
                catch (ArgumentException ex) { errors.Add($"{label}: invalid regular expression ({ex.Message})."); }
            }
            else if (op != null && op != "notEquals" && op != "notContains" && cond.Value.Length == 0)
            {
                errors.Add($"{label}: a value is required for '{op}'.");
            }
        }

        return errors;
    }

    private static bool IsDeny(PermissionEntry entry)
        => string.Equals(entry.AccessType, "Deny", StringComparison.OrdinalIgnoreCase);

    private static bool PolicyMatches(Policy policy, PermissionEntry entry)
    {
        if (!policy.Enabled || policy.Conditions.Count == 0) return false;

        if (!string.IsNullOrEmpty(policy.CategoryFilter))
        {
            var categories = policy.CategoryFilter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (!categories.Any(c => c.Equals(entry.Category, StringComparison.OrdinalIgnoreCase)))
                return false;
        }

        foreach (var cond in policy.Conditions)
        {
            if (!FieldAccessors.TryGetValue(cond.Field, out var accessor))
            {
                WarnOnce($"Policy '{policy.Name}' uses unknown field '{cond.Field}' and never matches.");
                return false;
            }
            if (!Matches(accessor(entry) ?? "", cond.Operator, cond.Value ?? "", policy.Name))
                return false;
        }
        return true;
    }

    private static bool Matches(string fieldValue, string op, string pattern, string policyName)
    {
        switch (op.ToLowerInvariant())
        {
            case "equals": return fieldValue.Equals(pattern, StringComparison.OrdinalIgnoreCase);
            case "notequals": return !fieldValue.Equals(pattern, StringComparison.OrdinalIgnoreCase);
            case "contains": return fieldValue.Contains(pattern, StringComparison.OrdinalIgnoreCase);
            case "notcontains": return !fieldValue.Contains(pattern, StringComparison.OrdinalIgnoreCase);
            case "startswith": return fieldValue.StartsWith(pattern, StringComparison.OrdinalIgnoreCase);
            case "regex": return TryRegexMatch(fieldValue, pattern, policyName);
            default:
                WarnOnce($"Policy '{policyName}' uses unknown operator '{op}' and never matches.");
                return false;
        }
    }

    // Policies run against every row (1M+), so compiled regexes are cached by pattern.
    private static readonly ConcurrentDictionary<string, Regex?> RegexCache = new();

    private static bool TryRegexMatch(string input, string pattern, string policyName)
    {
        var regex = RegexCache.GetOrAdd(pattern, static p =>
        {
            try { return new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1)); }
            catch { return null; }
        });
        if (regex == null)
        {
            WarnOnce($"Policy '{policyName}' has an invalid regular expression and never matches: {pattern}");
            return false;
        }
        try { return regex.IsMatch(input); }
        catch { return false; } // regex timeout on pathological input
    }
}
