using System.Text.Json;

namespace M365Permissions.Engine.Scanning;

/// <summary>Classifies SharePoint REST principals (site users, role assignment members).</summary>
public static class SharePointPrincipal
{
    private const int SharePointGroupType = 8; // SP.Utilities.PrincipalType.SharePointGroup

    /// <summary>Principal type from a SharePoint claim login name and, when known, the REST PrincipalType code.</summary>
    public static string DetermineType(string? loginName, int? principalTypeCode = null)
    {
        // SharePoint groups carry their title as LoginName, so only the type code identifies them.
        if (principalTypeCode == SharePointGroupType) return "SharePoint Group";
        if (string.IsNullOrEmpty(loginName)) return "Unknown";

        // Guests also use the membership prefix (i:0#.f|membership|john_contoso.com#ext#@...), so check them first.
        if (loginName.Contains("#ext#", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("urn:spo:guest", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("urn%3aspo%3aguest", StringComparison.OrdinalIgnoreCase))
            return "External User";

        if (loginName.StartsWith("i:0#.f|membership|", StringComparison.OrdinalIgnoreCase)) return "Internal User";

        // Everyone (c:0(.s|true) and Everyone except external users (c:0-.f|rolemanager|spo-grid-all-users/<tenant>).
        if (loginName.StartsWith("c:0(.s|true", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("|rolemanager|spo-grid-all-users", StringComparison.OrdinalIgnoreCase))
            return "Everyone";

        // Entra security groups (c:0t.c|tenant|<id>) and Microsoft 365 group members/owners (c:0o.c|federateddirectoryclaimprovider|<id>[_o]).
        if (loginName.StartsWith("c:0t.c|tenant|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        if (loginName.Contains("|federateddirectoryclaimprovider|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        if (loginName.Contains("|membership|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        return "Unknown";
    }

    /// <summary>Reads the numeric PrincipalType of a SharePoint REST user or member object.</summary>
    public static int? ReadTypeCode(JsonElement principal)
        => principal.TryGetProperty("PrincipalType", out var pt) && pt.ValueKind == JsonValueKind.Number && pt.TryGetInt32(out var code)
            ? code
            : null;
}
