namespace M365Permissions.Engine.Auth;

/// <summary>Built-in Entra role template IDs and the roles each scan category needs.</summary>
public static class DirectoryRoles
{
    public const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    public const string GlobalReader = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
    public const string SharePointAdministrator = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c";
    public const string ExchangeAdministrator = "29232cdf-9323-42fd-ade2-1d097af3e4de";
    public const string FabricAdministrator = "a9ea8996-122f-4c74-9520-8edcd192826c";
    public const string PowerPlatformAdministrator = "11648597-926c-4cf3-9c36-bcebb0ba8dcc";
    public const string Dynamics365Administrator = "44367163-eba1-44c3-98af-f5787879f96a";
    public const string ComplianceAdministrator = "17315797-102d-40b4-93e0-432062caca18";
    public const string SecurityAdministrator = "194ae4cb-b126-40b2-bd5b-6091b380977d";
    public const string PrivilegedRoleAdministrator = "e8611ab8-c189-46e8-94e1-60213ab1f814";
    public const string TeamsAdministrator = "69091246-20e8-4a56-aa4d-066075b2a7a8";

    /// <summary>The implicit "User" role every member carries; not worth showing.</summary>
    public const string DefaultUserRole = "b79fbf4d-3ef9-4689-8143-76b194e85509";

    private static readonly Dictionary<string, string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        [GlobalAdministrator] = "Global Administrator",
        [GlobalReader] = "Global Reader",
        [SharePointAdministrator] = "SharePoint Administrator",
        [ExchangeAdministrator] = "Exchange Administrator",
        [FabricAdministrator] = "Fabric Administrator",
        [PowerPlatformAdministrator] = "Power Platform Administrator",
        [Dynamics365Administrator] = "Dynamics 365 Administrator",
        [ComplianceAdministrator] = "Compliance Administrator",
        [SecurityAdministrator] = "Security Administrator",
        [PrivilegedRoleAdministrator] = "Privileged Role Administrator",
        [TeamsAdministrator] = "Teams Administrator"
    };

    /// <summary>Roles (any one of) that give a category complete results. Categories not listed need no directory role.</summary>
    private static readonly Dictionary<string, string[]> RequiredByCategory = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sharepoint"] = new[] { GlobalAdministrator, SharePointAdministrator },
        ["onedrive"] = new[] { GlobalAdministrator, SharePointAdministrator },
        ["exchange"] = new[] { GlobalAdministrator, ExchangeAdministrator },
        ["powerbi"] = new[] { GlobalAdministrator, FabricAdministrator },
        ["powerautomate"] = new[] { GlobalAdministrator, PowerPlatformAdministrator, Dynamics365Administrator },
        ["purview"] = new[] { GlobalAdministrator, ComplianceAdministrator, ExchangeAdministrator }
    };

    public static IReadOnlyList<string> RequiredForCategory(string category)
        => RequiredByCategory.TryGetValue(category, out var r) ? r : Array.Empty<string>();

    public static string NameOf(string roleTemplateId)
        => Names.TryGetValue(roleTemplateId, out var n) ? n : roleTemplateId;

    public static bool IsKnown(string roleTemplateId) => Names.ContainsKey(roleTemplateId);

    /// <summary>"A or B" / "A, B or C" for messages.</summary>
    public static string DescribeAny(IReadOnlyList<string> roleTemplateIds)
    {
        var names = roleTemplateIds.Select(NameOf).ToList();
        return names.Count <= 1 ? string.Join("", names) : string.Join(", ", names.Take(names.Count - 1)) + " or " + names[^1];
    }
}
