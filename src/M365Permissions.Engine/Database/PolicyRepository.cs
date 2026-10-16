using System.Text.Json;
using M365Permissions.Engine.Models;
using Microsoft.Data.Sqlite;

namespace M365Permissions.Engine.Database;

/// <summary>
/// CRUD operations for the policies table. Conditions are stored as JSON.
/// </summary>
public sealed class PolicyRepository
{
    private readonly SqliteDb _db;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public PolicyRepository(SqliteDb db) => _db = db;

    private const string SelectColumns =
        "id, name, description, enabled, severity, category_filter, conditions, is_default, created_at, updated_at, default_key, default_hash, remediation";

    public List<Policy> GetAll()
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {SelectColumns} FROM policies ORDER BY id";
        return ReadAll(cmd);
    }

    public Policy? GetById(long id)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {SelectColumns} FROM policies WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadPolicy(reader) : null;
    }

    public List<Policy> GetEnabled()
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {SelectColumns} FROM policies WHERE enabled = 1 ORDER BY id";
        return ReadAll(cmd);
    }

    public long Create(Policy policy)
    {
        using var conn = _db.CreateConnection();
        return Insert(conn, policy);
    }

    public void Update(Policy policy)
    {
        using var conn = _db.CreateConnection();
        UpdateRow(conn, policy);
    }

    public void Delete(long id)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM policies WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteNonQuery();
    }

    public void DeleteDefaults()
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM policies WHERE is_default = 1";
        cmd.ExecuteNonQuery();
    }

    public int Count()
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM policies";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    /// <summary>
    /// Bring the built-in policies up to date:
    /// - missing defaults are inserted (unless their key is in <paramref name="suppressedKeys"/>, i.e. the user deleted them);
    /// - defaults the user never edited (stored definition hash == hash last seeded) are upgraded to the current definition;
    /// - edited defaults are kept as they are;
    /// - legacy default rows (no key, from versions before keys existed) are matched by name and replaced, since
    ///   there is no way to tell whether they were edited; unmatched legacy defaults are removed.
    /// The enabled flag is always preserved.
    /// </summary>
    public DefaultPolicySyncReport SyncDefaults(IReadOnlyList<Policy> defaults, IReadOnlyDictionary<string, string> legacyNames,
        ISet<string>? suppressedKeys = null)
    {
        var report = new DefaultPolicySyncReport();
        using var conn = _db.CreateConnection();
        using var tx = conn.BeginTransaction();

        List<Policy> existing;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = $"SELECT {SelectColumns} FROM policies ORDER BY id";
            existing = ReadAll(cmd);
        }

        var byKey = existing.Where(p => p.DefaultKey.Length > 0)
            .GroupBy(p => p.DefaultKey, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var legacy = existing.Where(p => p.IsDefault && p.DefaultKey.Length == 0).ToList();
        var defaultsByName = defaults.ToDictionary(d => d.Name, d => d.DefaultKey, StringComparer.OrdinalIgnoreCase);

        foreach (var def in defaults)
        {
            var hash = def.ComputeDefinitionHash();
            if (byKey.TryGetValue(def.DefaultKey, out var row))
            {
                if (row.ComputeDefinitionHash() == row.DefaultHash || row.DefaultHash.Length == 0)
                {
                    if (row.DefaultHash != hash || row.ComputeDefinitionHash() != hash)
                    {
                        ReplaceDefinition(conn, tx, row, def, hash);
                        report.Upgraded.Add(def.DefaultKey);
                    }
                }
                else
                {
                    report.KeptEdited.Add(def.DefaultKey);
                }
                continue;
            }

            var legacyRow = legacy.FirstOrDefault(p =>
                (legacyNames.TryGetValue(p.Name, out var k) && k.Equals(def.DefaultKey, StringComparison.OrdinalIgnoreCase)) ||
                (defaultsByName.TryGetValue(p.Name, out var k2) && k2.Equals(def.DefaultKey, StringComparison.OrdinalIgnoreCase)));
            if (legacyRow != null)
            {
                legacy.Remove(legacyRow);
                ReplaceDefinition(conn, tx, legacyRow, def, hash);
                report.LegacyReplaced.Add(def.DefaultKey);
                continue;
            }

            if (suppressedKeys != null && suppressedKeys.Contains(def.DefaultKey)) continue;

            var insert = Clone(def);
            insert.DefaultHash = hash;
            Insert(conn, insert, tx);
            report.Inserted.Add(def.DefaultKey);
        }

        // Old seeds that no current default replaces.
        foreach (var row in legacy)
        {
            using var del = conn.CreateCommand();
            del.Transaction = tx;
            del.CommandText = "DELETE FROM policies WHERE id = @id";
            del.Parameters.AddWithValue("@id", row.Id);
            del.ExecuteNonQuery();
            report.LegacyRemoved.Add(row.Name);
        }

        tx.Commit();
        return report;
    }

    /// <summary>Set IsOutdatedDefault / IsModifiedDefault against the current built-in definitions.</summary>
    public static void AnnotateDefaults(IEnumerable<Policy> policies, IReadOnlyList<Policy> defaults)
    {
        var current = defaults.ToDictionary(d => d.DefaultKey, d => d.ComputeDefinitionHash(), StringComparer.OrdinalIgnoreCase);
        foreach (var p in policies)
        {
            if (!p.IsDefault || p.DefaultKey.Length == 0) continue;
            p.IsModifiedDefault = p.DefaultHash.Length > 0 && p.ComputeDefinitionHash() != p.DefaultHash;
            p.IsOutdatedDefault = p.IsModifiedDefault && current.TryGetValue(p.DefaultKey, out var h) && h != p.DefaultHash;
        }
    }

    private static void ReplaceDefinition(SqliteConnection conn, SqliteTransaction tx, Policy row, Policy def, string hash)
    {
        var updated = Clone(def);
        updated.Id = row.Id;
        updated.Enabled = row.Enabled;
        updated.DefaultHash = hash;
        UpdateRow(conn, updated, tx);
    }

    private static Policy Clone(Policy p) => new()
    {
        Id = p.Id,
        Name = p.Name,
        Description = p.Description,
        Enabled = p.Enabled,
        Severity = p.Severity,
        CategoryFilter = p.CategoryFilter,
        IsDefault = p.IsDefault,
        Conditions = p.Conditions.Select(c => new PolicyCondition { Field = c.Field, Operator = c.Operator, Value = c.Value }).ToList(),
        Remediation = p.Remediation,
        DefaultKey = p.DefaultKey,
        DefaultHash = p.DefaultHash
    };

    private static long Insert(SqliteConnection conn, Policy policy, SqliteTransaction? tx = null)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"INSERT INTO policies (name, description, enabled, severity, category_filter, conditions, is_default, default_key, default_hash, remediation)
            VALUES (@name, @desc, @enabled, @severity, @catFilter, @conditions, @isDefault, @key, @hash, @remediation);
            SELECT last_insert_rowid();";
        AddParameters(cmd, policy);
        return (long)cmd.ExecuteScalar()!;
    }

    private static void UpdateRow(SqliteConnection conn, Policy policy, SqliteTransaction? tx = null)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"UPDATE policies SET name=@name, description=@desc, enabled=@enabled, severity=@severity,
            category_filter=@catFilter, conditions=@conditions, is_default=@isDefault, default_key=@key, default_hash=@hash,
            remediation=@remediation, updated_at=datetime('now')
            WHERE id=@id";
        cmd.Parameters.AddWithValue("@id", policy.Id);
        AddParameters(cmd, policy);
        cmd.ExecuteNonQuery();
    }

    private static void AddParameters(SqliteCommand cmd, Policy policy)
    {
        cmd.Parameters.AddWithValue("@name", policy.Name ?? "");
        cmd.Parameters.AddWithValue("@desc", policy.Description ?? "");
        cmd.Parameters.AddWithValue("@enabled", policy.Enabled ? 1 : 0);
        cmd.Parameters.AddWithValue("@severity", policy.Severity ?? "");
        cmd.Parameters.AddWithValue("@catFilter", policy.CategoryFilter ?? "");
        cmd.Parameters.AddWithValue("@conditions", SerializeConditions(policy.Conditions ?? new()));
        cmd.Parameters.AddWithValue("@isDefault", policy.IsDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@key", policy.DefaultKey ?? "");
        cmd.Parameters.AddWithValue("@hash", policy.DefaultHash ?? "");
        cmd.Parameters.AddWithValue("@remediation", policy.Remediation ?? "");
    }

    private static List<Policy> ReadAll(SqliteCommand cmd)
    {
        using var reader = cmd.ExecuteReader();
        var list = new List<Policy>();
        while (reader.Read())
            list.Add(ReadPolicy(reader));
        return list;
    }

    private static Policy ReadPolicy(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        Name = reader.GetString(1),
        Description = reader.GetString(2),
        Enabled = reader.GetInt64(3) == 1,
        Severity = reader.GetString(4),
        CategoryFilter = reader.GetString(5),
        Conditions = DeserializeConditions(reader.GetString(6)),
        IsDefault = reader.GetInt64(7) == 1,
        CreatedAt = reader.GetString(8),
        UpdatedAt = reader.GetString(9),
        DefaultKey = reader.GetString(10),
        DefaultHash = reader.GetString(11),
        Remediation = reader.GetString(12)
    };

    private static string SerializeConditions(List<PolicyCondition> conditions)
        => JsonSerializer.Serialize(conditions, JsonOpts);

    private static List<PolicyCondition> DeserializeConditions(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || json == "[]") return new();
        try { return JsonSerializer.Deserialize<List<PolicyCondition>>(json, JsonOpts) ?? new(); }
        catch { return new(); }
    }
}
