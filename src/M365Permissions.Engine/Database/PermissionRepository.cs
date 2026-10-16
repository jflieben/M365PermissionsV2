using M365Permissions.Engine.Models;
using Microsoft.Data.Sqlite;

namespace M365Permissions.Engine.Database;

/// <summary>
/// Permission storage: bulk insert, paged and streamed queries, risk updates.
/// </summary>
public sealed class PermissionRepository
{
    private readonly SqliteDb _db;

    public PermissionRepository(SqliteDb db) => _db = db;

    /// <summary>
    /// Insert a batch of permission entries in a single transaction.
    /// Optimized for high throughput during scans (1000+ entries/batch).
    /// </summary>
    public void BulkInsert(IReadOnlyList<PermissionEntry> entries)
    {
        if (entries.Count == 0) return;

        using var conn = _db.CreateConnection();
        using var tx = conn.BeginTransaction();

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
            INSERT INTO permissions (
                scan_id, category, target_path, target_type, target_id,
                principal_entra_id, principal_entra_upn, principal_sys_id, principal_sys_name,
                principal_type, principal_role, through, access_type, tenure, parent_id,
                start_date_time, end_date_time, created_date_time, modified_date_time,
                risk_level, risk_reason
            ) VALUES (
                @scan_id, @category, @target_path, @target_type, @target_id,
                @pid, @pupn, @psid, @psname,
                @ptype, @prole, @through, @access, @tenure, @parent,
                @start_dt, @end_dt, @created_dt, @modified_dt,
                @risk_level, @risk_reason
            )";

        var pScanId = cmd.Parameters.Add("@scan_id", SqliteType.Integer);
        var pCategory = cmd.Parameters.Add("@category", SqliteType.Text);
        var pTargetPath = cmd.Parameters.Add("@target_path", SqliteType.Text);
        var pTargetType = cmd.Parameters.Add("@target_type", SqliteType.Text);
        var pTargetId = cmd.Parameters.Add("@target_id", SqliteType.Text);
        var pPid = cmd.Parameters.Add("@pid", SqliteType.Text);
        var pPupn = cmd.Parameters.Add("@pupn", SqliteType.Text);
        var pPsid = cmd.Parameters.Add("@psid", SqliteType.Text);
        var pPsname = cmd.Parameters.Add("@psname", SqliteType.Text);
        var pPtype = cmd.Parameters.Add("@ptype", SqliteType.Text);
        var pProle = cmd.Parameters.Add("@prole", SqliteType.Text);
        var pThrough = cmd.Parameters.Add("@through", SqliteType.Text);
        var pAccess = cmd.Parameters.Add("@access", SqliteType.Text);
        var pTenure = cmd.Parameters.Add("@tenure", SqliteType.Text);
        var pParent = cmd.Parameters.Add("@parent", SqliteType.Text);
        var pStartDt = cmd.Parameters.Add("@start_dt", SqliteType.Text);
        var pEndDt = cmd.Parameters.Add("@end_dt", SqliteType.Text);
        var pCreatedDt = cmd.Parameters.Add("@created_dt", SqliteType.Text);
        var pModifiedDt = cmd.Parameters.Add("@modified_dt", SqliteType.Text);
        var pRiskLevel = cmd.Parameters.Add("@risk_level", SqliteType.Text);
        var pRiskReason = cmd.Parameters.Add("@risk_reason", SqliteType.Text);

        cmd.Prepare();

        foreach (var e in entries)
        {
            pScanId.Value = e.ScanId;
            pCategory.Value = e.Category;
            pTargetPath.Value = e.TargetPath;
            pTargetType.Value = e.TargetType;
            pTargetId.Value = e.TargetId;
            pPid.Value = e.PrincipalEntraId;
            pPupn.Value = e.PrincipalEntraUpn;
            pPsid.Value = e.PrincipalSysId;
            pPsname.Value = e.PrincipalSysName;
            pPtype.Value = e.PrincipalType;
            pProle.Value = e.PrincipalRole;
            pThrough.Value = e.Through;
            pAccess.Value = e.AccessType;
            pTenure.Value = e.Tenure;
            pParent.Value = e.ParentId;
            pStartDt.Value = e.StartDateTime;
            pEndDt.Value = e.EndDateTime;
            pCreatedDt.Value = e.CreatedDateTime;
            pModifiedDt.Value = e.ModifiedDateTime;
            pRiskLevel.Value = e.RiskLevel;
            pRiskReason.Value = e.RiskReason;
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    public const int MaxPageSize = 1000;

    /// <summary>
    /// Paginated query with optional filters.
    /// </summary>
    public PagedResult<PermissionEntry> Query(long scanId, string? category = null,
        string? searchText = null, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
    {
        (page, pageSize) = ClampPaging(page, pageSize);
        using var conn = _db.CreateConnection();

        using var countCmd = conn.CreateCommand();
        var where = BuildWhereClause(countCmd, scanId, category, searchText, columnFilters);
        countCmd.CommandText = $"SELECT COUNT(*) FROM permissions {where}";
        var totalCount = (long)countCmd.ExecuteScalar()!;

        var orderBy = BuildOrderBy(sortColumn, sortDirection);
        using var dataCmd = conn.CreateCommand();
        var where2 = BuildWhereClause(dataCmd, scanId, category, searchText, columnFilters);
        dataCmd.CommandText = $"SELECT * FROM permissions {where2} {orderBy} LIMIT @limit OFFSET @offset";
        dataCmd.Parameters.AddWithValue("@limit", pageSize);
        dataCmd.Parameters.AddWithValue("@offset", (long)(page - 1) * pageSize);

        var items = new List<PermissionEntry>();
        using var reader = dataCmd.ExecuteReader();
        while (reader.Read())
            items.Add(MapPermission(reader));

        return new PagedResult<PermissionEntry>
        {
            Items = items,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize
        };
    }

    /// <summary>Get all permissions for a scan+category (for export and comparison).</summary>
    public List<PermissionEntry> GetAll(long scanId, string? category = null)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        var where = "WHERE scan_id = @scan_id";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        if (!string.IsNullOrEmpty(category))
        {
            where += " AND category = @category";
            cmd.Parameters.AddWithValue("@category", category);
        }
        cmd.CommandText = $"SELECT * FROM permissions {where} ORDER BY target_path, principal_entra_upn, id";

        var items = new List<PermissionEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            items.Add(MapPermission(reader));
        return items;
    }

    /// <summary>
    /// Fetch one page of a scan's permissions ordered by id (keyset cursor), so exports and
    /// evaluations never hold a whole scan in memory. Optional risk and search filters.
    /// </summary>
    public List<PermissionEntry> GetPage(long scanId, string? category, long afterId, int limit,
        IReadOnlyCollection<string>? riskLevels = null, string? searchText = null)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        var where = "WHERE scan_id = @scan_id AND id > @afterId";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        cmd.Parameters.AddWithValue("@afterId", afterId);
        if (!string.IsNullOrEmpty(category))
        {
            where += " AND category = @category";
            cmd.Parameters.AddWithValue("@category", category);
        }
        if (riskLevels is { Count: > 0 })
        {
            var names = riskLevels.Select((r, i) => { cmd.Parameters.AddWithValue($"@rl{i}", r); return $"@rl{i}"; });
            where += $" AND risk_level IN ({string.Join(",", names)})";
        }
        if (!string.IsNullOrEmpty(searchText))
        {
            where += " AND (target_path LIKE @search ESCAPE '\\' OR principal_entra_upn LIKE @search ESCAPE '\\' OR principal_sys_name LIKE @search ESCAPE '\\' OR principal_role LIKE @search ESCAPE '\\')";
            cmd.Parameters.AddWithValue("@search", Contains(searchText));
        }
        cmd.CommandText = $"SELECT * FROM permissions {where} ORDER BY id LIMIT @limit";
        cmd.Parameters.AddWithValue("@limit", limit);

        var items = new List<PermissionEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            items.Add(MapPermission(reader));
        return items;
    }

    /// <summary>Stream every matching row of a scan, a page at a time.</summary>
    public IEnumerable<PermissionEntry> Stream(long scanId, string? category = null,
        IReadOnlyCollection<string>? riskLevels = null, string? searchText = null, int batchSize = 5000)
    {
        long afterId = 0;
        while (true)
        {
            var page = GetPage(scanId, category, afterId, batchSize, riskLevels, searchText);
            if (page.Count == 0) yield break;
            foreach (var e in page) yield return e;
            afterId = page[^1].Id;
            if (page.Count < batchSize) yield break;
        }
    }

    /// <summary>Write new risk scores in one transaction. Returns the number of rows whose score changed.</summary>
    public int UpdateRisk(IReadOnlyList<(long Id, string RiskLevel, string RiskReason)> scores)
    {
        if (scores.Count == 0) return 0;
        using var conn = _db.CreateConnection();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"UPDATE permissions SET risk_level = @level, risk_reason = @reason
            WHERE id = @id AND (risk_level != @level OR risk_reason != @reason)";
        var pId = cmd.Parameters.Add("@id", SqliteType.Integer);
        var pLevel = cmd.Parameters.Add("@level", SqliteType.Text);
        var pReason = cmd.Parameters.Add("@reason", SqliteType.Text);
        cmd.Prepare();
        int changed = 0;
        foreach (var (id, level, reason) in scores)
        {
            pId.Value = id;
            pLevel.Value = level;
            pReason.Value = reason;
            changed += cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return changed;
    }

    /// <summary>Get distinct categories for a scan.</summary>
    public List<string> GetCategories(long scanId)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT DISTINCT category FROM permissions WHERE scan_id = @scan_id ORDER BY category";
        cmd.Parameters.AddWithValue("@scan_id", scanId);

        var result = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            result.Add(reader.GetString(0));
        return result;
    }

    public long Count(long scanId, string? category = null)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM permissions WHERE scan_id = @scan_id" +
            (string.IsNullOrEmpty(category) ? "" : " AND category = @category");
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        if (!string.IsNullOrEmpty(category)) cmd.Parameters.AddWithValue("@category", category);
        return (long)cmd.ExecuteScalar()!;
    }

    private static readonly HashSet<string> AllowedSortColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "category", "target_path", "target_type", "principal_entra_upn", "principal_sys_name",
        "principal_type", "principal_role", "through", "access_type", "tenure", "risk_level", "id"
    };

    private static readonly HashSet<string> AllowedFilterColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "category", "target_type", "principal_type", "principal_role", "through", "access_type", "tenure", "risk_level"
    };

    // Severity order, so sorting on risk gives Critical..Info instead of alphabetical.
    internal const string RiskOrdinalSql =
        "CASE risk_level WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 WHEN 'Info' THEN 4 ELSE 5 END";

    /// <summary>ORDER BY clause; id is always the final tiebreaker so paging is stable.</summary>
    internal static string BuildOrderBy(string? sortColumn, string? sortDirection)
    {
        if (string.IsNullOrEmpty(sortColumn) || !AllowedSortColumns.Contains(sortColumn))
            return "ORDER BY target_path, principal_entra_upn, id";
        var dir = string.Equals(sortDirection, "desc", StringComparison.OrdinalIgnoreCase) ? "DESC" : "ASC";
        var col = sortColumn.Equals("risk_level", StringComparison.OrdinalIgnoreCase) ? RiskOrdinalSql : sortColumn.ToLowerInvariant();
        return col == "id" ? $"ORDER BY id {dir}" : $"ORDER BY {col} {dir}, id {dir}";
    }

    internal static (int page, int pageSize) ClampPaging(int page, int pageSize)
        => (Math.Max(1, page), Math.Clamp(pageSize < 1 ? 100 : pageSize, 1, MaxPageSize));

    /// <summary>Escape LIKE wildcards (with ESCAPE '\') so _ and % in a search are literal.</summary>
    internal static string EscapeLike(string value)
        => value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    private static string Contains(string value) => $"%{EscapeLike(value)}%";

    private static string BuildWhereClause(SqliteCommand cmd, long scanId, string? category, string? searchText,
        Dictionary<string, string>? columnFilters = null)
    {
        var clauses = new List<string> { "scan_id = @scan_id" };
        cmd.Parameters.AddWithValue("@scan_id", scanId);

        if (!string.IsNullOrEmpty(category))
        {
            clauses.Add("category = @category");
            cmd.Parameters.AddWithValue("@category", category);
        }
        if (!string.IsNullOrEmpty(searchText))
        {
            clauses.Add("(target_path LIKE @search ESCAPE '\\' OR principal_entra_upn LIKE @search ESCAPE '\\' OR principal_sys_name LIKE @search ESCAPE '\\' OR principal_role LIKE @search ESCAPE '\\')");
            cmd.Parameters.AddWithValue("@search", Contains(searchText));
        }

        clauses.AddRange(BuildColumnFilters(columnFilters, "cf", (name, value) => cmd.Parameters.AddWithValue(name, value)));
        return "WHERE " + string.Join(" AND ", clauses);
    }

    // Pipe-separated multi-select values per whitelisted column: "val1|val2" becomes col IN (...).
    private static IEnumerable<string> BuildColumnFilters(Dictionary<string, string>? columnFilters, string prefix,
        Action<string, string> addParam)
    {
        if (columnFilters == null) yield break;
        int filterIdx = 0;
        foreach (var (col, values) in columnFilters)
        {
            if (!AllowedFilterColumns.Contains(col) || string.IsNullOrEmpty(values)) continue;
            var valList = values.Split('|', StringSplitOptions.RemoveEmptyEntries);
            if (valList.Length == 0) continue;

            var paramNames = new List<string>();
            for (int i = 0; i < valList.Length; i++)
            {
                var pName = $"@{prefix}{filterIdx}_{i}";
                paramNames.Add(pName);
                addParam(pName, valList[i]);
            }
            yield return $"{col.ToLowerInvariant()} IN ({string.Join(",", paramNames)})";
            filterIdx++;
        }
    }

    private static PermissionEntry MapPermission(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        ScanId = reader.GetInt64(reader.GetOrdinal("scan_id")),
        Category = reader.GetString(reader.GetOrdinal("category")),
        TargetPath = reader.GetString(reader.GetOrdinal("target_path")),
        TargetType = reader.GetString(reader.GetOrdinal("target_type")),
        TargetId = reader.GetString(reader.GetOrdinal("target_id")),
        PrincipalEntraId = reader.GetString(reader.GetOrdinal("principal_entra_id")),
        PrincipalEntraUpn = reader.GetString(reader.GetOrdinal("principal_entra_upn")),
        PrincipalSysId = reader.GetString(reader.GetOrdinal("principal_sys_id")),
        PrincipalSysName = reader.GetString(reader.GetOrdinal("principal_sys_name")),
        PrincipalType = reader.GetString(reader.GetOrdinal("principal_type")),
        PrincipalRole = reader.GetString(reader.GetOrdinal("principal_role")),
        Through = reader.GetString(reader.GetOrdinal("through")),
        AccessType = reader.GetString(reader.GetOrdinal("access_type")),
        Tenure = reader.GetString(reader.GetOrdinal("tenure")),
        ParentId = reader.GetString(reader.GetOrdinal("parent_id")),
        StartDateTime = reader.GetString(reader.GetOrdinal("start_date_time")),
        EndDateTime = reader.GetString(reader.GetOrdinal("end_date_time")),
        CreatedDateTime = reader.GetString(reader.GetOrdinal("created_date_time")),
        ModifiedDateTime = reader.GetString(reader.GetOrdinal("modified_date_time")),
        RiskLevel = reader.GetString(reader.GetOrdinal("risk_level")),
        RiskReason = reader.GetString(reader.GetOrdinal("risk_reason"))
    };

    private static readonly System.Text.RegularExpressions.Regex UpnLike =
        new(@"^[^@\s%*]+@[^@\s]+\.[^@\s]+$", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Search permissions for a user across all categories in a scan: rows where the user is the
    /// principal, plus effective access through the Entra groups they are a member of (rows whose
    /// principal is such a group) and, for Microsoft 365 group owners, SharePoint grants to the
    /// group's owners claim ("&lt;groupId&gt;_o"). Other members of those groups are never returned.
    /// A UPN-like search term matches that UPN exactly when it exists in the scan.
    /// </summary>
    public UserPermissionsPage QueryUserPermissions(long scanId, string userSearch, int page = 1, int pageSize = 100,
        string? sortColumn = null, string? sortDirection = null,
        Dictionary<string, string>? columnFilters = null)
    {
        (page, pageSize) = ClampPaging(page, pageSize);
        userSearch = userSearch.Trim();
        using var conn = _db.CreateConnection();

        var exact = UpnLike.IsMatch(userSearch) && HasExactUpn(conn, scanId, userSearch);

        // Rows that identify the user themselves, by search term (alias placeholder {a}).
        var termMatch = exact
            ? "(lower({a}.principal_entra_upn) = lower(@term) OR {a}.principal_sys_id LIKE @claim ESCAPE '\\')"
            : "({a}.principal_entra_upn LIKE @search ESCAPE '\\' OR {a}.principal_sys_name LIKE @search ESCAPE '\\' OR {a}.principal_entra_id LIKE @search ESCAPE '\\')";
        string Term(string a) => termMatch.Replace("{a}", a);
        string Direct(string a) => "(" + Term(a) + " OR (" + a + ".principal_entra_id != '' AND " + a + ".principal_entra_id IN (SELECT id FROM me)))";

        var cte = $@"WITH me AS (
                SELECT DISTINCT m.principal_entra_id AS id FROM permissions m
                WHERE m.scan_id = @scan_id AND m.principal_entra_id != '' AND {Term("m")}
            ),
            grp AS (
                SELECT CASE WHEN g.principal_role = 'Owner' THEN g.target_id || '_o' ELSE g.target_id END AS gid,
                       MIN(CASE WHEN g.target_path LIKE 'Group/%' THEN substr(g.target_path, 7) ELSE g.target_path END) AS gname
                FROM permissions g
                WHERE g.scan_id = @scan_id AND g.category = 'Entra'
                  AND g.target_type IN ('SecurityGroup','M365Group','DistributionList')
                  AND g.target_id != '' AND g.principal_role IN ('Member','Owner')
                  AND {Direct("g")}
                GROUP BY gid
            )";

        var filterParams = new Dictionary<string, string>();
        var filterClauses = string.Concat(BuildColumnFilters(columnFilters, "ucf", (n, v) => filterParams[n] = v)
            .Select(c => " AND p." + c));
        var where = $"WHERE p.scan_id = @scan_id AND ({Direct("p")} OR (p.principal_entra_id != '' AND p.principal_entra_id IN (SELECT gid FROM grp))){filterClauses}";

        void Bind(SqliteCommand cmd)
        {
            cmd.Parameters.AddWithValue("@scan_id", scanId);
            cmd.Parameters.AddWithValue("@term", userSearch);
            cmd.Parameters.AddWithValue("@claim", "%|" + EscapeLike(userSearch));
            cmd.Parameters.AddWithValue("@search", Contains(userSearch));
            foreach (var (k, v) in filterParams) cmd.Parameters.AddWithValue(k, v);
        }

        using var countCmd = conn.CreateCommand();
        countCmd.CommandText = $"{cte} SELECT COUNT(*) FROM permissions p {where}";
        Bind(countCmd);
        var totalCount = (long)countCmd.ExecuteScalar()!;

        var orderBy = BuildOrderBy(sortColumn, sortDirection);
        using var dataCmd = conn.CreateCommand();
        dataCmd.CommandText = $@"{cte} SELECT p.*,
                CASE WHEN {Direct("p")} THEN '' ELSE (SELECT gname FROM grp WHERE grp.gid = p.principal_entra_id) END AS via
            FROM permissions p {where} {orderBy} LIMIT @limit OFFSET @offset";
        Bind(dataCmd);
        dataCmd.Parameters.AddWithValue("@limit", pageSize);
        dataCmd.Parameters.AddWithValue("@offset", (long)(page - 1) * pageSize);

        var result = new UserPermissionsPage { TotalCount = totalCount, Page = page, PageSize = pageSize, ExactMatch = exact };
        using var reader = dataCmd.ExecuteReader();
        var viaOrdinal = reader.GetOrdinal("via");
        while (reader.Read())
        {
            var entry = MapPermission(reader);
            result.Items.Add(entry);
            var via = reader.IsDBNull(viaOrdinal) ? "" : reader.GetString(viaOrdinal);
            if (via.Length > 0) result.Via[entry.Id] = via;
        }
        return result;
    }

    private static bool HasExactUpn(SqliteConnection conn, long scanId, string upn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM permissions WHERE scan_id = @scan_id AND lower(principal_entra_upn) = lower(@upn) LIMIT 1";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        cmd.Parameters.AddWithValue("@upn", upn);
        return cmd.ExecuteScalar() != null;
    }

    /// <summary>Get members of a specific group from Entra scan results.</summary>
    public List<PermissionEntry> GetGroupMembers(long scanId, string groupId)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT * FROM permissions WHERE scan_id = @scan_id
            AND category = 'Entra' AND target_id = @group_id AND principal_role = 'Member'
            ORDER BY principal_entra_upn, principal_sys_name, id";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        cmd.Parameters.AddWithValue("@group_id", groupId);

        var items = new List<PermissionEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            items.Add(MapPermission(reader));
        return items;
    }

    /// <summary>
    /// Members of a SharePoint group as emitted for one target: rows with Through = SharePointGroup
    /// and ParentId = the group name, on the same target (by id when known, else by path).
    /// </summary>
    public List<PermissionEntry> GetSharePointGroupMembers(long scanId, string groupName, string? targetPath, string? targetId)
    {
        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        var targetClause = !string.IsNullOrEmpty(targetId) ? "target_id = @tid" : "target_path = @tp";
        cmd.CommandText = $@"SELECT * FROM permissions WHERE scan_id = @scan_id
            AND through = 'SharePointGroup' AND parent_id = @group AND {targetClause}
            ORDER BY principal_entra_upn, principal_sys_name, id";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        cmd.Parameters.AddWithValue("@group", groupName);
        cmd.Parameters.AddWithValue("@tid", targetId ?? "");
        cmd.Parameters.AddWithValue("@tp", targetPath ?? "");

        var items = new List<PermissionEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            items.Add(MapPermission(reader));
        return items;
    }

    /// <summary>Get distinct values for a column in a scan (for filter dropdowns).</summary>
    public List<string> GetDistinctValues(long scanId, string column, string? category = null)
    {
        if (!AllowedFilterColumns.Contains(column))
            return new List<string>();
        column = column.ToLowerInvariant();

        using var conn = _db.CreateConnection();
        using var cmd = conn.CreateCommand();
        var where = "WHERE scan_id = @scan_id";
        cmd.Parameters.AddWithValue("@scan_id", scanId);
        if (!string.IsNullOrEmpty(category))
        {
            where += " AND category = @category";
            cmd.Parameters.AddWithValue("@category", category);
        }
        var order = column == "risk_level" ? RiskOrdinalSql : column;
        cmd.CommandText = $"SELECT {column} FROM permissions {where} GROUP BY {column} ORDER BY {order}";

        var result = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var val = reader.GetString(0);
            if (!string.IsNullOrEmpty(val)) result.Add(val);
        }
        return result;
    }
}
