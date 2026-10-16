namespace M365Permissions.Engine.Scanning;

/// <summary>Keys of the per-scan coverage counters (scan_insights). The GUI reads these names.</summary>
public static class InsightKeys
{
    public const string PartialReasons = "partialReasons";

    // SharePoint / OneDrive
    public const string SitesScanned = "sitesScanned";
    public const string SubsitesWithUniquePermissions = "subsitesWithUniquePermissions";
    public const string ListsWithUniquePermissions = "listsWithUniquePermissions";
    public const string SharingLinks = "sharingLinks";
    public const string AnonymousLinks = "anonymousLinks";
    public const string OrganizationLinks = "organizationLinks";
    public const string SpecificPeopleLinks = "specificPeopleLinks";
    public const string UnresolvedLinkItems = "unresolvedLinkItems";
    public const string ItemLevelPrincipals = "itemLevelPrincipals";
    public const string LockedSites = "lockedSites";
    public const string ArchivedSites = "archivedSites";

    /// <summary>Readable sentence for a counter (exports), or null for counters that need no explanation.</summary>
    public static string? Describe(string key, long value) => key switch
    {
        PartialReasons => "results are incomplete; see the scan log for the reason",
        SitesScanned => $"{value:N0} site collections scanned",
        SubsitesWithUniquePermissions => $"{value:N0} subsites with unique permissions",
        ListsWithUniquePermissions => $"{value:N0} lists or libraries with unique permissions",
        SharingLinks => $"{value:N0} sharing links",
        AnonymousLinks => $"{value:N0} anonymous sharing links",
        OrganizationLinks => $"{value:N0} organization-wide sharing links",
        SpecificPeopleLinks => $"{value:N0} specific-people sharing links",
        UnresolvedLinkItems => $"{value:N0} shared items whose path was not looked up (listed by item id)",
        ItemLevelPrincipals => $"{value:N0} users or groups with access to individual files, folders or items (counted, not listed)",
        LockedSites => $"{value:N0} locked sites not readable",
        ArchivedSites => $"{value:N0} archived sites not readable",
        _ => null
    };
}
