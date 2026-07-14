namespace M365Permissions.Engine.Models;

/// <summary>
/// Change in risk findings between a scan and the previous scan of the same tenant (O3).
/// Drives "N new Critical findings since last scan" style headlines.
/// </summary>
public sealed class RiskDelta
{
    public long ScanId { get; set; }
    public long? PreviousScanId { get; set; }
    public int NewCritical { get; set; }
    public int NewHigh { get; set; }
    public int TotalAdded { get; set; }
    public int TotalRemoved { get; set; }
    public bool HasPrevious => PreviousScanId != null;
}

/// <summary>Result of the PSGallery update check ($4).</summary>
public sealed class VersionInfo
{
    public string Current { get; set; } = string.Empty;
    public string? Latest { get; set; }
    public bool UpdateAvailable { get; set; }
}
