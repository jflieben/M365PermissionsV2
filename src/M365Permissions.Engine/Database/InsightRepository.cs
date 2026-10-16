using Microsoft.Data.Sqlite;

namespace M365Permissions.Engine.Database;

/// <summary>Per-scan coverage counters (scan_insights): what a scan saw but did not itemize.</summary>
public sealed class InsightRepository
{
    private readonly SqliteDb _db;

    public InsightRepository(SqliteDb db) => _db = db;

    public void Save(long scanId, string category, IReadOnlyDictionary<string, long> values)
    {
        if (values.Count == 0) return;
        using var conn = _db.CreateConnection();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
            INSERT INTO scan_insights (scan_id, category, key, value) VALUES (@scan, @cat, @key, @value)
            ON CONFLICT(scan_id, category, key) DO UPDATE SET value = excluded.value";
        var pScan = cmd.Parameters.Add("@scan", SqliteType.Integer);
        var pCat = cmd.Parameters.Add("@cat", SqliteType.Text);
        var pKey = cmd.Parameters.Add("@key", SqliteType.Text);
        var pValue = cmd.Parameters.Add("@value", SqliteType.Integer);
        foreach (var (key, value) in values)
        {
            pScan.Value = scanId;
            pCat.Value = category;
            pKey.Value = key;
            pValue.Value = value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>Insights of a scan as category -> key -> value.</summary>
    public Dictionary<string, Dictionary<string, long>> GetByScan(long scanId)
    {
        var result = new Dictionary<string, Dictionary<string, long>>(StringComparer.OrdinalIgnoreCase);
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT category, key, value FROM scan_insights WHERE scan_id = @scan";
        cmd.Parameters.AddWithValue("@scan", scanId);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var category = reader.GetString(0);
            if (!result.TryGetValue(category, out var map))
                result[category] = map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            map[reader.GetString(1)] = reader.GetInt64(2);
        }
        return result;
    }
}
