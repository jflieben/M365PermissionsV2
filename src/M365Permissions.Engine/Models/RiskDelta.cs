using System.Text.Json.Serialization;

namespace M365Permissions.Engine.Models;

/// <summary>
/// Change in risk findings between a scan and the previous scan of the same tenant (O3).
/// Drives "N new Critical findings since last scan" style headlines. Only categories that
/// completed in both scans are compared; the others are listed in ExcludedCategories.
/// </summary>
public sealed class RiskDelta
{
    public long ScanId { get; set; }
    public long? PreviousScanId { get; set; }
    public int NewCritical { get; set; }
    public int NewHigh { get; set; }
    public int TotalAdded { get; set; }
    public int TotalRemoved { get; set; }
    public int TotalChanged { get; set; }
    public bool HasPrevious => PreviousScanId != null;
    public List<string> IncludedCategories { get; set; } = new();
    public List<CategoryCoverageNote> ExcludedCategories { get; set; } = new();
    public List<CategoryCoverageNote> FlaggedCategories { get; set; } = new();
}

/// <summary>Why a category was left out of, or flagged in, a comparison.</summary>
public sealed class CategoryCoverageNote
{
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;
}

/// <summary>Result of the PSGallery update check ($4).</summary>
public sealed class VersionInfo
{
    public string Current { get; set; } = string.Empty;
    public string? Latest { get; set; }
    public bool UpdateAvailable { get; set; }
}
