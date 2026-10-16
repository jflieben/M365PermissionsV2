using ClosedXML.Excel;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Export;

/// <summary>Scan context written to the About sheet of an export.</summary>
public sealed class ExportMetadata
{
    public long ScanId { get; set; }
    public string TenantDomain { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string StartedAt { get; set; } = "";
    public string CompletedAt { get; set; } = "";
    public string Status { get; set; } = "";
    public string ScanTypes { get; set; } = "";
    public string Category { get; set; } = "";
    public string ModuleVersion { get; set; } = "";
    public List<ScanProgress> CategoryStatus { get; set; } = new();
    public List<string> PartialNotes { get; set; } = new();
    public Dictionary<string, int> RiskSummary { get; set; } = new();
}

/// <summary>
/// Exports permission entries to XLSX format using ClosedXML.
/// </summary>
public sealed class ExcelExporter
{
    private static readonly string[] Headers =
    {
        "Risk Level", "Risk Reason", "Category",
        "Target Path", "Target Type", "Target ID",
        "Principal (Entra ID)", "Principal (UPN)", "Principal (System ID)", "Principal Name",
        "Principal Type", "Role", "Through", "Access Type", "Tenure",
        "Parent ID", "Start Date", "End Date", "Created", "Modified"
    };

    /// <summary>Generate an XLSX workbook from permission entries, with an About sheet when metadata is given.</summary>
    public byte[] Export(IReadOnlyList<PermissionEntry> entries, string sheetName = "Permissions", ExportMetadata? metadata = null)
    {
        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add(SafeSheetName(sheetName));

        for (int col = 0; col < Headers.Length; col++)
            StyleHeader(worksheet.Cell(1, col + 1), Headers[col], XLColor.FromArgb(0, 172, 215));

        for (int row = 0; row < entries.Count; row++)
        {
            var e = entries[row];
            var r = row + 2;
            var values = new[]
            {
                e.RiskLevel, e.RiskReason, e.Category, e.TargetPath, e.TargetType, e.TargetId,
                e.PrincipalEntraId, e.PrincipalEntraUpn, e.PrincipalSysId, e.PrincipalSysName,
                e.PrincipalType, e.PrincipalRole, e.Through, e.AccessType, e.Tenure,
                e.ParentId, e.StartDateTime, e.EndDateTime, e.CreatedDateTime, e.ModifiedDateTime
            };
            for (int c = 0; c < values.Length; c++)
                worksheet.Cell(r, c + 1).Value = values[c];
            ApplyRiskColor(worksheet.Cell(r, 1), e.RiskLevel);
        }

        worksheet.Columns().AdjustToContents(1, Math.Min(entries.Count + 1, 100));
        worksheet.SheetView.FreezeRows(1);
        if (entries.Count > 0)
            worksheet.RangeUsed()?.SetAutoFilter();

        WriteAboutSheet(workbook, metadata, entries.Count);

        using var ms = new MemoryStream();
        workbook.SaveAs(ms);
        return ms.ToArray();
    }

    private static void WriteAboutSheet(XLWorkbook workbook, ExportMetadata? meta, int rowCount)
    {
        var ws = workbook.Worksheets.Add("About");
        int r = 1;
        ws.Cell(r, 1).Value = "M365Permissions export";
        ws.Cell(r, 1).Style.Font.Bold = true;
        ws.Cell(r, 1).Style.Font.FontSize = 14;
        r += 2;

        void Row(string label, string value)
        {
            ws.Cell(r, 1).Value = label;
            ws.Cell(r, 1).Style.Font.Bold = true;
            ws.Cell(r, 2).Value = value;
            r++;
        }

        if (meta != null)
        {
            Row("Tenant", string.IsNullOrEmpty(meta.TenantDomain) ? meta.TenantId : $"{meta.TenantDomain} ({meta.TenantId})");
            Row("Scan", $"#{meta.ScanId}");
            Row("Started (UTC)", meta.StartedAt);
            Row("Completed (UTC)", meta.CompletedAt);
            Row("Scan status", meta.Status);
            Row("Scan types", meta.ScanTypes);
            Row("Exported category", string.IsNullOrEmpty(meta.Category) ? "All" : meta.Category);
        }
        Row("Rows exported", rowCount.ToString("N0"));

        if (meta != null)
        {
            var findings = meta.RiskSummary.Where(kv => kv.Key is "Critical" or "High" or "Medium" or "Low").Sum(kv => kv.Value);
            Row("Rows with a policy finding (Low or higher)", findings.ToString("N0"));
            foreach (var level in new[] { "Critical", "High", "Medium", "Low", "Info" })
            {
                Row($"  {level}", meta.RiskSummary.GetValueOrDefault(level).ToString("N0"));
                ApplyRiskColor(ws.Cell(r - 1, 1), level);
            }

            if (meta.CategoryStatus.Count > 0)
            {
                r++;
                StyleHeader(ws.Cell(r, 1), "Category", XLColor.FromArgb(0, 172, 215));
                StyleHeader(ws.Cell(r, 2), "Status", XLColor.FromArgb(0, 172, 215));
                StyleHeader(ws.Cell(r, 3), "Permissions found", XLColor.FromArgb(0, 172, 215));
                StyleHeader(ws.Cell(r, 4), "Failed targets", XLColor.FromArgb(0, 172, 215));
                r++;
                foreach (var p in meta.CategoryStatus)
                {
                    ws.Cell(r, 1).Value = p.Category;
                    ws.Cell(r, 2).Value = p.Status;
                    ws.Cell(r, 3).Value = p.PermissionsFound;
                    ws.Cell(r, 4).Value = p.FailedTargets;
                    r++;
                }
            }

            if (meta.PartialNotes.Count > 0)
            {
                r++;
                ws.Cell(r, 1).Value = "Coverage notes";
                ws.Cell(r, 1).Style.Font.Bold = true;
                r++;
                foreach (var note in meta.PartialNotes)
                {
                    ws.Cell(r, 1).Value = note;
                    r++;
                }
            }
        }

        r++;
        var version = string.IsNullOrEmpty(meta?.ModuleVersion) ? Engine.ModuleVersion : meta!.ModuleVersion;
        ws.Cell(r, 1).Value = $"Generated by M365Permissions {version}";
        ws.Cell(r, 1).Style.Font.Italic = true;
        ws.Cell(r, 1).Style.Font.FontColor = XLColor.Gray;
        r++;
        ws.Cell(r, 1).Value = "Risk levels reflect the policies active when the scan ran or was last re-scored.";
        ws.Cell(r, 1).Style.Font.Italic = true;
        ws.Cell(r, 1).Style.Font.FontColor = XLColor.Gray;
        r++;
        ws.Cell(r, 1).Value = "Scheduled scans, change alerts and every file and folder with unique permissions: M365Permissions Cloud Edition";
        ws.Cell(r, 1).Style.Font.Italic = true;
        ws.Cell(r, 1).Style.Font.FontColor = XLColor.Gray;
        ws.Cell(r, 2).Value = "https://m365permissions.com/evaluate";
        ws.Cell(r, 2).SetHyperlink(new XLHyperlink("https://m365permissions.com/evaluate?utm_source=m365permissions-module&utm_medium=xlsx"));

        ws.Column(1).Width = 45;
        ws.Column(2).Width = 45;
        ws.Column(3).Width = 18;
        ws.Column(4).Width = 15;
    }

    /// <summary>Rows per sheet in a comparison export; larger diffs are cut off with a note on the Summary sheet.</summary>
    public const int ComparisonSheetRowLimit = 200_000;

    /// <summary>
    /// Export a comparison result with Summary / Added / Removed / Changed sheets.
    /// </summary>
    public byte[] ExportComparison(ComparisonResult result)
    {
        using var workbook = new XLWorkbook();

        WriteSummarySheet(workbook, result);
        WriteComparisonSheet(workbook, "Added", result.Added);
        WriteComparisonSheet(workbook, "Removed", result.Removed);
        WriteChangedSheet(workbook, result.Changed);

        using var ms = new MemoryStream();
        workbook.SaveAs(ms);
        return ms.ToArray();
    }

    private static void WriteComparisonSheet(XLWorkbook workbook, string name, IReadOnlyList<PermissionEntry> entries)
    {
        var ws = workbook.Worksheets.Add(name);
        var headers = new[] { "Risk Level", "Category", "Target Path", "Target Type", "Principal", "Principal Type", "Role", "Through", "Access Type", "Tenure" };
        var color = name == "Added" ? XLColor.FromArgb(76, 175, 80) : XLColor.FromArgb(244, 67, 54);
        for (int c = 0; c < headers.Length; c++)
            StyleHeader(ws.Cell(1, c + 1), headers[c], color);

        var count = Math.Min(entries.Count, ComparisonSheetRowLimit);
        for (int r = 0; r < count; r++)
        {
            var e = entries[r];
            var row = r + 2;
            ws.Cell(row, 1).Value = e.RiskLevel;
            ApplyRiskColor(ws.Cell(row, 1), e.RiskLevel);
            ws.Cell(row, 2).Value = e.Category;
            ws.Cell(row, 3).Value = e.TargetPath;
            ws.Cell(row, 4).Value = e.TargetType;
            ws.Cell(row, 5).Value = ComparisonEngine.PrincipalLabel(e);
            ws.Cell(row, 6).Value = e.PrincipalType;
            ws.Cell(row, 7).Value = e.PrincipalRole;
            ws.Cell(row, 8).Value = e.Through;
            ws.Cell(row, 9).Value = e.AccessType;
            ws.Cell(row, 10).Value = e.Tenure;
        }
        ws.Columns().AdjustToContents(1, Math.Min(count + 1, 100));
        ws.SheetView.FreezeRows(1);
        if (count > 0) ws.RangeUsed()?.SetAutoFilter();
    }

    private static void WriteChangedSheet(XLWorkbook workbook, IReadOnlyList<PermissionChange> changes)
    {
        var ws = workbook.Worksheets.Add("Changed");
        var headers = new[] { "Category", "Target Path", "Principal", "Role", "Field", "Old Value", "New Value" };
        for (int c = 0; c < headers.Length; c++)
            StyleHeader(ws.Cell(1, c + 1), headers[c], XLColor.FromArgb(255, 152, 0));

        int row = 2;
        foreach (var change in changes)
        {
            foreach (var field in change.ChangedFields)
            {
                if (row > ComparisonSheetRowLimit + 1) break;
                ws.Cell(row, 1).Value = change.New.Category;
                ws.Cell(row, 2).Value = change.New.TargetPath;
                ws.Cell(row, 3).Value = ComparisonEngine.PrincipalLabel(change.New);
                ws.Cell(row, 4).Value = change.New.PrincipalRole;
                ws.Cell(row, 5).Value = field;
                ws.Cell(row, 6).Value = GetFieldValue(change.Old, field);
                ws.Cell(row, 7).Value = GetFieldValue(change.New, field);
                row++;
            }
        }
        ws.Columns().AdjustToContents(1, Math.Min(row, 100));
        ws.SheetView.FreezeRows(1);
        if (row > 2) ws.RangeUsed()?.SetAutoFilter();
    }

    private static string GetFieldValue(PermissionEntry entry, string fieldName) => fieldName switch
    {
        "PrincipalRole" => entry.PrincipalRole,
        "Through" => entry.Through,
        "AccessType" => entry.AccessType,
        "Tenure" => entry.Tenure,
        "RiskLevel" => entry.RiskLevel,
        "RiskReason" => entry.RiskReason,
        "PrincipalType" => entry.PrincipalType,
        "PrincipalEntraUpn" => entry.PrincipalEntraUpn,
        "PrincipalSysName" => entry.PrincipalSysName,
        "TargetType" => entry.TargetType,
        "TargetPath" => entry.TargetPath,
        "StartDateTime" => entry.StartDateTime,
        "EndDateTime" => entry.EndDateTime,
        _ => fieldName
    };

    private static void WriteSummarySheet(XLWorkbook workbook, ComparisonResult result)
    {
        var ws = workbook.Worksheets.Add("Summary");
        ws.Cell(1, 1).Value = "M365Permissions comparison";
        ws.Cell(1, 1).Style.Font.Bold = true;
        ws.Cell(1, 1).Style.Font.FontSize = 14;
        ws.Cell(2, 1).Value = $"Scan #{result.OldScanId} (baseline) vs scan #{result.NewScanId}";

        ws.Cell(4, 1).Value = "Metric";
        ws.Cell(4, 2).Value = "Count";
        ws.Cell(4, 1).Style.Font.Bold = true;
        ws.Cell(4, 2).Style.Font.Bold = true;

        var rows = new (string Label, int Count, XLColor Color)[]
        {
            ("Permissions added", Math.Max(result.AddedCount, result.Added.Count), XLColor.FromArgb(76, 175, 80)),
            ("Permissions removed", Math.Max(result.RemovedCount, result.Removed.Count), XLColor.FromArgb(244, 67, 54)),
            ("Permissions changed", Math.Max(result.ChangedCount, result.Changed.Count), XLColor.FromArgb(255, 152, 0)),
            ("New or escalated Critical", result.NewCriticalCount, XLColor.FromArgb(183, 28, 28)),
            ("New or escalated High", result.NewHighCount, XLColor.FromArgb(244, 67, 54)),
        };
        int r = 5;
        foreach (var (label, count, color) in rows)
        {
            ws.Cell(r, 1).Value = label;
            ws.Cell(r, 2).Value = count;
            ws.Cell(r, 2).Style.Font.FontColor = color;
            r++;
        }

        r++;
        if (result.IncludedCategories.Count > 0)
        {
            ws.Cell(r, 1).Value = "Compared categories";
            ws.Cell(r, 2).Value = string.Join(", ", result.IncludedCategories);
            r++;
        }
        foreach (var note in result.ExcludedCategories)
        {
            ws.Cell(r, 1).Value = $"Not compared: {note.Category}";
            ws.Cell(r, 2).Value = note.Reason;
            r++;
        }
        foreach (var note in result.FlaggedCategories)
        {
            ws.Cell(r, 1).Value = $"Partial: {note.Category}";
            ws.Cell(r, 2).Value = note.Reason;
            r++;
        }
        if (result.Added.Count > ComparisonSheetRowLimit || result.Removed.Count > ComparisonSheetRowLimit ||
            result.Changed.Sum(c => c.ChangedFields.Count) > ComparisonSheetRowLimit)
        {
            ws.Cell(r, 1).Value = $"Sheets are limited to the first {ComparisonSheetRowLimit:N0} rows.";
            ws.Cell(r, 1).Style.Font.Italic = true;
        }

        ws.Column(1).Width = 40;
        ws.Column(2).Width = 80;
    }

    private static void StyleHeader(IXLCell cell, string text, XLColor color)
    {
        cell.Value = text;
        cell.Style.Font.Bold = true;
        cell.Style.Fill.BackgroundColor = color;
        cell.Style.Font.FontColor = XLColor.White;
    }

    private static string SafeSheetName(string name)
    {
        var cleaned = new string(name.Where(ch => ch is not (':' or '\\' or '/' or '?' or '*' or '[' or ']')).ToArray());
        if (string.IsNullOrWhiteSpace(cleaned) || cleaned.Equals("About", StringComparison.OrdinalIgnoreCase)) cleaned = "Permissions";
        return cleaned.Length > 31 ? cleaned[..31] : cleaned;
    }

    private static void ApplyRiskColor(IXLCell cell, string riskLevel)
    {
        switch (riskLevel)
        {
            case "Critical":
                cell.Style.Fill.BackgroundColor = XLColor.FromArgb(183, 28, 28);
                cell.Style.Font.FontColor = XLColor.White;
                break;
            case "High":
                cell.Style.Fill.BackgroundColor = XLColor.FromArgb(244, 67, 54);
                cell.Style.Font.FontColor = XLColor.White;
                break;
            case "Medium":
                cell.Style.Fill.BackgroundColor = XLColor.FromArgb(255, 152, 0);
                cell.Style.Font.FontColor = XLColor.White;
                break;
            case "Low":
                cell.Style.Fill.BackgroundColor = XLColor.FromArgb(76, 175, 80);
                cell.Style.Font.FontColor = XLColor.White;
                break;
            case "Info":
                cell.Style.Fill.BackgroundColor = XLColor.FromArgb(33, 150, 243);
                cell.Style.Font.FontColor = XLColor.White;
                break;
        }
    }
}
