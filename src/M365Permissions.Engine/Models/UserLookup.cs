using System.Text.Json.Serialization;

namespace M365Permissions.Engine.Models;

/// <summary>
/// A page of a user's permissions. Via maps a row id to the group the user gets that row through
/// (absent for rows held directly).
/// </summary>
public sealed class UserPermissionsPage
{
    [JsonPropertyName("items")]
    public List<PermissionEntry> Items { get; set; } = new();

    [JsonPropertyName("totalCount")]
    public long TotalCount { get; set; }

    [JsonPropertyName("page")]
    public int Page { get; set; }

    [JsonPropertyName("pageSize")]
    public int PageSize { get; set; }

    [JsonPropertyName("via")]
    public Dictionary<long, string> Via { get; set; } = new();

    /// <summary>True when the search term looked like a UPN and matched it exactly.</summary>
    [JsonPropertyName("exactMatch")]
    public bool ExactMatch { get; set; }
}
