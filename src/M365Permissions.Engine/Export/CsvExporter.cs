using System.Text;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Export;

/// <summary>
/// Exports permission entries to CSV (UTF-8 with BOM, every value quoted).
/// </summary>
public sealed class CsvExporter
{
    private const string Header =
        "Risk Level,Risk Reason,Category,Target Path,Target Type,Target ID," +
        "Principal Entra ID,Principal UPN,Principal System ID,Principal Name," +
        "Principal Type,Role,Through,Access Type,Tenure," +
        "Parent ID,Start Date,End Date,Created,Modified";

    private static readonly UTF8Encoding Utf8Bom = new(encoderShouldEmitUTF8Identifier: true);

    public byte[] Export(IReadOnlyList<PermissionEntry> entries)
    {
        using var ms = new MemoryStream();
        Write(ms, entries);
        return ms.ToArray();
    }

    /// <summary>Write the CSV to a stream (left open).</summary>
    public void Write(Stream output, IEnumerable<PermissionEntry> entries)
    {
        using var writer = new StreamWriter(output, Utf8Bom, bufferSize: 65536, leaveOpen: true);
        writer.WriteLine(Header);
        foreach (var e in entries) writer.WriteLine(FormatRow(e));
    }

    /// <summary>
    /// Build a CSV by pulling pages from <paramref name="fetchPage"/> (rows after a given id), so
    /// the full result set is never materialised at once.
    /// </summary>
    public byte[] ExportPaged(Func<long, List<PermissionEntry>> fetchPage)
    {
        using var ms = new MemoryStream();
        Write(ms, Paged(fetchPage));
        return ms.ToArray();
    }

    private static IEnumerable<PermissionEntry> Paged(Func<long, List<PermissionEntry>> fetchPage)
    {
        long afterId = 0;
        while (true)
        {
            var page = fetchPage(afterId);
            if (page.Count == 0) yield break;
            foreach (var e in page)
            {
                yield return e;
                if (e.Id > afterId) afterId = e.Id;
            }
        }
    }

    private static string FormatRow(PermissionEntry e) => string.Join(",",
        Escape(e.RiskLevel), Escape(e.RiskReason), Escape(e.Category),
        Escape(e.TargetPath), Escape(e.TargetType), Escape(e.TargetId),
        Escape(e.PrincipalEntraId), Escape(e.PrincipalEntraUpn),
        Escape(e.PrincipalSysId), Escape(e.PrincipalSysName),
        Escape(e.PrincipalType), Escape(e.PrincipalRole),
        Escape(e.Through), Escape(e.AccessType), Escape(e.Tenure),
        Escape(e.ParentId), Escape(e.StartDateTime),
        Escape(e.EndDateTime), Escape(e.CreatedDateTime),
        Escape(e.ModifiedDateTime));

    /// <summary>
    /// Quote a value. Values starting with = + - @ tab or CR get a leading apostrophe so a
    /// spreadsheet opens them as text instead of evaluating a formula (CSV injection).
    /// </summary>
    internal static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}
