using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Microsoft.Data.Sqlite;
using Xunit;

namespace M365Permissions.Engine.Tests.Database;

/// <summary>
/// Built-in policy upgrade: unedited defaults follow the shipped definition, edited ones are kept
/// and flagged, legacy (keyless) seeds are replaced by name, user-deleted defaults stay deleted.
/// </summary>
public sealed class DefaultPolicySyncTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteDb _db;
    private readonly PolicyRepository _repo;

    public DefaultPolicySyncTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"m365policysync_{Guid.NewGuid():N}.db");
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        _repo = new PolicyRepository(_db);
    }

    private static Policy Def(string key, string name, string value, string severity = "High") => new()
    {
        DefaultKey = key, Name = name, Severity = severity, IsDefault = true, Remediation = "Fix it.",
        Conditions = new() { new() { Field = "principal_role", Operator = "equals", Value = value } }
    };

    private static readonly IReadOnlyDictionary<string, string> NoLegacy = new Dictionary<string, string>();

    [Fact]
    public void FreshDatabase_InsertsAll_AndSecondSyncIsNoOp()
    {
        var defaults = DefaultPolicies.GetAll();
        var first = _repo.SyncDefaults(defaults, DefaultPolicies.LegacyNames);
        Assert.Equal(defaults.Count, first.Inserted.Count);

        var second = _repo.SyncDefaults(defaults, DefaultPolicies.LegacyNames);
        Assert.Empty(second.Inserted);
        Assert.Empty(second.Upgraded);
        Assert.Equal(defaults.Count, _repo.Count());
    }

    [Fact]
    public void UneditedDefault_IsUpgraded_AndKeepsEnabledFlag()
    {
        _repo.SyncDefaults(new[] { Def("k1", "Policy one", "Old") }, NoLegacy);
        var row = _repo.GetAll().Single();
        row.Enabled = false;
        _repo.Update(row); // toggling enabled is not an edit

        var report = _repo.SyncDefaults(new[] { Def("k1", "Policy one", "New") }, NoLegacy);

        Assert.Contains("k1", report.Upgraded);
        var upgraded = _repo.GetAll().Single();
        Assert.Equal("New", upgraded.Conditions[0].Value);
        Assert.False(upgraded.Enabled);
        Assert.Equal(upgraded.ComputeDefinitionHash(), upgraded.DefaultHash);
    }

    [Fact]
    public void EditedDefault_IsKept_AndFlaggedOutdated()
    {
        _repo.SyncDefaults(new[] { Def("k1", "Policy one", "Old") }, NoLegacy);
        var row = _repo.GetAll().Single();
        row.Severity = "Low"; // user edit
        _repo.Update(row);

        var shipped = new[] { Def("k1", "Policy one", "New") };
        var report = _repo.SyncDefaults(shipped, NoLegacy);

        Assert.Contains("k1", report.KeptEdited);
        var kept = _repo.GetAll().Single();
        Assert.Equal("Low", kept.Severity);
        Assert.Equal("Old", kept.Conditions[0].Value);

        PolicyRepository.AnnotateDefaults(new[] { kept }, shipped);
        Assert.True(kept.IsModifiedDefault);
        Assert.True(kept.IsOutdatedDefault);
    }

    [Fact]
    public void EditedDefault_WithoutNewShippedVersion_IsModifiedButNotOutdated()
    {
        var shipped = new[] { Def("k1", "Policy one", "Same") };
        _repo.SyncDefaults(shipped, NoLegacy);
        var row = _repo.GetAll().Single();
        row.Description = "My wording";
        _repo.Update(row);

        var annotated = _repo.GetAll().Single();
        PolicyRepository.AnnotateDefaults(new[] { annotated }, shipped);
        Assert.True(annotated.IsModifiedDefault);
        Assert.False(annotated.IsOutdatedDefault);
    }

    [Fact]
    public void LegacyRows_AreReplacedByName_UnknownLegacyRemoved_CustomUntouched()
    {
        // Seeds from before default_key existed.
        InsertLegacy("Organization-wide sharing link", "principal_type", "AllInternalUsers", isDefault: true, enabled: false);
        InsertLegacy("Some removed default", "principal_type", "Whatever", isDefault: true, enabled: true);
        InsertLegacy("My custom rule", "principal_type", "Guest", isDefault: false, enabled: true);

        var report = _repo.SyncDefaults(DefaultPolicies.GetAll(), DefaultPolicies.LegacyNames);

        Assert.Contains("sp-organization-link", report.LegacyReplaced);
        Assert.Contains("Some removed default", report.LegacyRemoved);
        var all = _repo.GetAll();
        var org = all.Single(p => p.DefaultKey == "sp-organization-link");
        Assert.False(org.Enabled);
        Assert.DoesNotContain(org.Conditions, c => c.Value == "AllInternalUsers");
        Assert.Contains(all, p => p.Name == "My custom rule" && !p.IsDefault);
        Assert.DoesNotContain(all, p => p.Name == "Some removed default");
        Assert.Single(all, p => p.DefaultKey == "sp-organization-link");
    }

    [Fact]
    public void SuppressedKey_IsNotReinserted()
    {
        var report = _repo.SyncDefaults(new[] { Def("k1", "One", "a"), Def("k2", "Two", "b") }, NoLegacy,
            new HashSet<string> { "k2" });
        Assert.Equal(new[] { "k1" }, report.Inserted);
    }

    private void InsertLegacy(string name, string field, string value, bool isDefault, bool enabled)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO policies (name, severity, conditions, is_default, enabled) VALUES (@n, 'Medium', @c, @d, @e)";
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@c", $"[{{\"field\":\"{field}\",\"operator\":\"equals\",\"value\":\"{value}\"}}]");
        cmd.Parameters.AddWithValue("@d", isDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@e", enabled ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch { }
    }
}

public sealed class PolicyValidationTests
{
    private static Policy Valid() => new()
    {
        Name = "Test", Severity = "high",
        Conditions = new() { new() { Field = "principal_role", Operator = "Regex", Value = "^Owner$" } }
    };

    [Fact]
    public void ValidPolicy_PassesAndIsNormalised()
    {
        var p = Valid();
        Assert.Empty(PolicyEngine.Validate(p));
        Assert.Equal("High", p.Severity);
        Assert.Equal("regex", p.Conditions[0].Operator);
    }

    [Fact]
    public void UnknownField_IsRejected()
    {
        var p = Valid();
        p.Conditions[0].Field = "principal_colour";
        Assert.Contains(PolicyEngine.Validate(p), e => e.Contains("unknown field"));
    }

    [Fact]
    public void InvalidRegex_IsRejected()
    {
        var p = Valid();
        p.Conditions[0].Value = "(unclosed";
        Assert.Contains(PolicyEngine.Validate(p), e => e.Contains("invalid regular expression"));
    }

    [Theory]
    [InlineData("Severe")]
    [InlineData("")]
    public void BadSeverity_IsRejected(string severity)
    {
        var p = Valid();
        p.Severity = severity;
        Assert.Contains(PolicyEngine.Validate(p), e => e.Contains("Severity"));
    }

    [Fact]
    public void UnknownOperator_AndNoConditions_AreRejected()
    {
        var p = Valid();
        p.Conditions[0].Operator = "like";
        Assert.Contains(PolicyEngine.Validate(p), e => e.Contains("unknown operator"));
        p.Conditions.Clear();
        Assert.Contains(PolicyEngine.Validate(p), e => e.Contains("At least one condition"));
    }

    [Fact]
    public void InvalidPolicyAtEvaluation_WarnsOnce_AndNeverMatches()
    {
        var warnings = new List<string>();
        void Handler(string m) { lock (warnings) warnings.Add(m); }
        PolicyEngine.ConfigurationWarning += Handler;
        try
        {
            var bad = new Policy
            {
                Id = 1, Name = $"Broken {Guid.NewGuid():N}", Severity = "High", Enabled = true,
                Conditions = new() { new() { Field = "no_such_field", Operator = "equals", Value = "x" } }
            };
            var entry = new PermissionEntry { PrincipalRole = "x" };
            Assert.Empty(PolicyEngine.Evaluate(entry, new[] { bad }));
            Assert.Empty(PolicyEngine.Evaluate(entry, new[] { bad }));
            Assert.Single(warnings, w => w.Contains(bad.Name));
        }
        finally { PolicyEngine.ConfigurationWarning -= Handler; }
    }
}
