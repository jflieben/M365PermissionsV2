using Microsoft.Data.Sqlite;

namespace M365Permissions.Engine.Database;

/// <summary>
/// Persists scan log lines to the `logs` table so long scans can be debugged post-mortem,
/// surviving engine restarts (B15/O1). Levels: 0=Critical, 1=Error, 2=Warning, 3=Info,
/// 4=Verbose, 5=Debug. Only messages at or below the configured threshold are written.
/// </summary>
public sealed class LogRepository
{
    private readonly SqliteDb _db;

    public LogRepository(SqliteDb db) => _db = db;

    public void Insert(long? scanId, int level, string category, string message)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO logs (scan_id, level, message, category)
            VALUES (@scan, @level, @message, @category)";
        cmd.Parameters.AddWithValue("@scan", (object?)scanId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@level", level);
        cmd.Parameters.AddWithValue("@message", message);
        cmd.Parameters.AddWithValue("@category", category);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Read persisted logs for a scan, optionally filtered by max level and category.</summary>
    public List<LogEntry> GetByScan(long scanId, int? maxLevel = null, string? category = null, int limit = 1000)
    {
        var result = new List<LogEntry>();
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        var filters = "scan_id = @scan";
        if (maxLevel.HasValue) filters += " AND level <= @maxLevel";
        if (!string.IsNullOrEmpty(category)) filters += " AND category = @category";
        cmd.CommandText = $"SELECT id, scan_id, level, message, category, timestamp FROM logs WHERE {filters} ORDER BY id DESC LIMIT @limit";
        cmd.Parameters.AddWithValue("@scan", scanId);
        if (maxLevel.HasValue) cmd.Parameters.AddWithValue("@maxLevel", maxLevel.Value);
        if (!string.IsNullOrEmpty(category)) cmd.Parameters.AddWithValue("@category", category);
        cmd.Parameters.AddWithValue("@limit", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new LogEntry
            {
                Id = reader.GetInt64(0),
                ScanId = reader.IsDBNull(1) ? null : reader.GetInt64(1),
                Level = reader.GetInt32(2),
                Message = reader.GetString(3),
                Category = reader.GetString(4),
                Timestamp = reader.GetString(5)
            });
        }
        result.Reverse(); // oldest first
        return result;
    }
}

public sealed class LogEntry
{
    public long Id { get; set; }
    public long? ScanId { get; set; }
    public int Level { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}
