using System.Text.Json;

namespace M365Permissions.Engine.Scanning;

/// <summary>Identity of a SharePoint REST principal, normalised for permission rows.</summary>
public sealed record SharePointPrincipalInfo(
    string Name, string LoginName, string Type, string EntraId, string Upn, int? TypeCode)
{
    public bool IsSystem => LoginName.Contains("SHAREPOINT\\system", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Classifies SharePoint REST principals (site users, role assignment members) and roles.</summary>
public static class SharePointPrincipal
{
    private const int SharePointGroupType = 8; // SP.Utilities.PrincipalType.SharePointGroup
    private const string MembershipPrefix = "i:0#.f|membership|";
    private const string TenantGroupPrefix = "c:0t.c|tenant|";
    private const string M365GroupMarker = "|federateddirectoryclaimprovider|";

    /// <summary>Principal type from a SharePoint claim login name and, when known, the REST PrincipalType code.</summary>
    public static string DetermineType(string? loginName, int? principalTypeCode = null)
    {
        // SharePoint groups carry their title as LoginName, so only the type code identifies them.
        if (principalTypeCode == SharePointGroupType) return "SharePoint Group";
        if (string.IsNullOrEmpty(loginName)) return "Unknown";

        if (loginName.Contains("urn:spo:anon", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("urn%3aspo%3aanon", StringComparison.OrdinalIgnoreCase))
            return "Anonymous";

        // Guests also use the membership prefix (i:0#.f|membership|john_contoso.com#ext#@...), so check them first.
        if (loginName.Contains("#ext#", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("urn:spo:guest", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("urn%3aspo%3aguest", StringComparison.OrdinalIgnoreCase))
            return "External User";

        if (loginName.StartsWith(MembershipPrefix, StringComparison.OrdinalIgnoreCase)) return "Internal User";

        // Everyone (c:0(.s|true) and Everyone except external users (c:0-.f|rolemanager|spo-grid-all-users/<tenant>).
        if (loginName.StartsWith("c:0(.s|true", StringComparison.OrdinalIgnoreCase) ||
            loginName.Contains("|rolemanager|spo-grid-all-users", StringComparison.OrdinalIgnoreCase))
            return "Everyone";

        if (loginName.StartsWith(TenantGroupPrefix, StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        if (loginName.Contains(M365GroupMarker, StringComparison.OrdinalIgnoreCase)) return "M365Group";

        // Add-in and app-only principals (i:0i.t|ms.sp.ext|<appId>@<tenant>, i:0i.t|00000003-...|app@sharepoint).
        if (loginName.StartsWith("i:0i.t|", StringComparison.OrdinalIgnoreCase)) return "Application";

        if (loginName.Contains("|membership|", StringComparison.OrdinalIgnoreCase)) return "SecurityGroup";
        return "Unknown";
    }

    /// <summary>
    /// Entra object id from a group claim: c:0t.c|tenant|&lt;id&gt; and c:0o.c|federateddirectoryclaimprovider|&lt;id&gt;.
    /// Microsoft 365 group owner claims end in _o and keep that suffix, so they never match the group's members.
    /// </summary>
    public static string ExtractEntraId(string? loginName)
    {
        if (string.IsNullOrEmpty(loginName)) return "";
        string? tail = null;
        if (loginName.StartsWith(TenantGroupPrefix, StringComparison.OrdinalIgnoreCase))
            tail = loginName[TenantGroupPrefix.Length..];
        else
        {
            var idx = loginName.IndexOf(M365GroupMarker, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) tail = loginName[(idx + M365GroupMarker.Length)..];
        }
        if (tail == null) return "";
        var isOwners = tail.EndsWith("_o", StringComparison.OrdinalIgnoreCase);
        var id = isOwners ? tail[..^2] : tail;
        return Guid.TryParse(id, out var guid) ? guid.ToString() + (isOwners ? "_o" : "") : "";
    }

    /// <summary>UPN from a membership claim (i:0#.f|membership|user@contoso.com).</summary>
    public static string ExtractUpn(string? loginName)
    {
        if (string.IsNullOrEmpty(loginName) || !loginName.StartsWith(MembershipPrefix, StringComparison.OrdinalIgnoreCase))
            return "";
        var upn = loginName[MembershipPrefix.Length..];
        return upn.Contains('@') && !upn.StartsWith("urn:", StringComparison.OrdinalIgnoreCase) ? upn : "";
    }

    /// <summary>True when the claim belongs to the given UPN (exact match, not a substring).</summary>
    public static bool IsAccount(string? loginName, string? upn)
        => !string.IsNullOrEmpty(upn) && ExtractUpn(loginName).Equals(upn, StringComparison.OrdinalIgnoreCase);

    /// <summary>Normalised identity of a REST user, group or role assignment member.</summary>
    public static SharePointPrincipalInfo Describe(JsonElement principal)
    {
        var login = ReadString(principal, "LoginName");
        var title = ReadString(principal, "Title");
        var code = ReadTypeCode(principal);
        var upn = ReadString(principal, "UserPrincipalName");
        if (string.IsNullOrEmpty(upn)) upn = ExtractUpn(login);
        return new SharePointPrincipalInfo(
            string.IsNullOrEmpty(title) ? login : title,
            login,
            DetermineType(login, code),
            ExtractEntraId(login),
            upn,
            code);
    }

    /// <summary>Reads the numeric PrincipalType of a SharePoint REST user or member object.</summary>
    public static int? ReadTypeCode(JsonElement principal)
        => principal.TryGetProperty("PrincipalType", out var pt) && pt.ValueKind == JsonValueKind.Number && pt.TryGetInt32(out var code)
            ? code
            : null;

    private const long LimitedAccessId = 1073741825;
    private const long ViewOnlyId = 1073741924;

    /// <summary>
    /// Locale-independent role name for a role definition binding, or null for Limited Access
    /// (and other hidden roles), which only mark access to something further down.
    /// Built-in roles map by RoleTypeKind (localised names such as "Volledig beheer" become "Full Control").
    /// </summary>
    public static string? CanonicalRole(JsonElement binding)
    {
        var hidden = binding.TryGetProperty("Hidden", out var h) && h.ValueKind == JsonValueKind.True;
        var id = binding.TryGetProperty("Id", out var idProp) && idProp.ValueKind == JsonValueKind.Number ? idProp.GetInt64() : 0;
        int? kind = binding.TryGetProperty("RoleTypeKind", out var k) && k.ValueKind == JsonValueKind.Number ? k.GetInt32() : null;

        if (hidden || kind == 1 || id == LimitedAccessId) return null;
        if (id == ViewOnlyId) return "View Only";
        return kind switch
        {
            2 => "Read",
            3 => "Contribute",
            4 => "Design",
            5 => "Full Control",
            6 => "Edit",
            _ => ReadString(binding, "Name")
        };
    }

    /// <summary>True when the binding is Limited Access (access to an item, folder or list below this level).</summary>
    public static bool IsLimitedAccess(JsonElement binding)
    {
        var id = binding.TryGetProperty("Id", out var idProp) && idProp.ValueKind == JsonValueKind.Number ? idProp.GetInt64() : 0;
        var kind = binding.TryGetProperty("RoleTypeKind", out var k) && k.ValueKind == JsonValueKind.Number ? k.GetInt32() : -1;
        return kind == 1 || id == LimitedAccessId;
    }

    internal static string ReadString(JsonElement element, string name)
        => element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
