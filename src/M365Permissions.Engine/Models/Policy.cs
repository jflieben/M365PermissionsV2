using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace M365Permissions.Engine.Models;

/// <summary>
/// A policy rule that flags permission entries matching a set of conditions (AND logic).
/// Used for both risk scoring and compliance flagging.
/// </summary>
public sealed class Policy
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Severity { get; set; } = "High";           // Critical, High, Medium, Low, Info
    public string CategoryFilter { get; set; } = "";          // Empty = all categories
    public bool IsDefault { get; set; }                       // True = pre-seeded built-in policy
    public List<PolicyCondition> Conditions { get; set; } = new(); // All conditions must match (AND)
    public string Remediation { get; set; } = "";             // What to do about a match, and where
    public string DefaultKey { get; set; } = "";              // Stable key of the built-in definition
    public string DefaultHash { get; set; } = "";             // Hash of the built-in definition last seeded
    public string CreatedAt { get; set; } = "";
    public string UpdatedAt { get; set; } = "";

    /// <summary>Built-in policy the user edited, for which a newer built-in definition exists.</summary>
    public bool IsOutdatedDefault { get; set; }

    /// <summary>Built-in policy whose definition differs from the one that was seeded (user edit).</summary>
    public bool IsModifiedDefault { get; set; }

    /// <summary>
    /// Hash over the fields that define the rule (not Enabled, ids or timestamps), so toggling a
    /// policy doesn't count as an edit.
    /// </summary>
    public string ComputeDefinitionHash()
    {
        var canonical = JsonSerializer.Serialize(new object[]
        {
            Name.Trim(), Description.Trim(), Severity.Trim(), CategoryFilter.Trim(), Remediation.Trim(),
            Conditions.Select(c => new[] { c.Field.Trim(), c.Operator.Trim(), c.Value }).ToArray()
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..16];
    }
}

/// <summary>
/// A single condition within a policy rule.
/// </summary>
public sealed class PolicyCondition
{
    public string Field { get; set; } = "";                   // Column to match: principal_role, through, tenure, target_path, etc.
    public string Operator { get; set; } = "equals";          // equals, notEquals, contains, notContains, startsWith, regex
    public string Value { get; set; } = "";
}

/// <summary>
/// A policy that matched a permission entry.
/// </summary>
public sealed class PolicyViolation
{
    public long PolicyId { get; set; }
    public string PolicyName { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
    public string Remediation { get; set; } = "";
}

/// <summary>Matches per policy in an evaluation run.</summary>
public sealed class PolicyMatchCount
{
    public long PolicyId { get; set; }
    public string PolicyName { get; set; } = "";
    public string Severity { get; set; } = "";
    public long Count { get; set; }
}

/// <summary>One permission entry with the policies it violates.</summary>
public sealed class PolicyViolationRow
{
    public PermissionEntry Entry { get; set; } = new();
    public List<PolicyViolation> Violations { get; set; } = new();
}

/// <summary>
/// Result of evaluating every row of a scan against the enabled policies: counts per policy plus
/// the first rows that violate one (most severe first).
/// </summary>
public sealed class PolicyEvaluationResult
{
    public long ScanId { get; set; }
    public string? Category { get; set; }
    public long EntriesEvaluated { get; set; }
    public long EntriesWithViolations { get; set; }
    public List<PolicyMatchCount> PerPolicy { get; set; } = new();
    public List<PolicyViolationRow> Violations { get; set; } = new();
    public bool Truncated { get; set; }
    public List<string> Warnings { get; set; } = new();
}

/// <summary>Result of re-applying the current policies to the stored rows of a scan.</summary>
public sealed class RescoreResult
{
    public long ScanId { get; set; }
    public long EntriesScored { get; set; }
    public long EntriesChanged { get; set; }
    public Dictionary<string, int> RiskSummary { get; set; } = new();
}

/// <summary>What the default-policy sync did on startup (or on reset).</summary>
public sealed class DefaultPolicySyncReport
{
    public List<string> Inserted { get; } = new();
    public List<string> Upgraded { get; } = new();
    public List<string> LegacyReplaced { get; } = new();
    public List<string> LegacyRemoved { get; } = new();
    public List<string> KeptEdited { get; } = new();
}

/// <summary>A policy failed validation; Errors lists every problem.</summary>
public sealed class PolicyValidationException : ArgumentException
{
    public List<string> Errors { get; }

    public PolicyValidationException(List<string> errors) : base(string.Join(" ", errors)) => Errors = errors;
}
