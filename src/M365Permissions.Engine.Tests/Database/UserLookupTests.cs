using M365Permissions.Engine.Database;
using M365Permissions.Engine.Models;
using Xunit;

namespace M365Permissions.Engine.Tests.Database;

/// <summary>
/// Guards the User Lookup query: a user's results must include their own memberships and the
/// effective access of the groups they belong to, but must NOT leak the rosters of those groups
/// (other members). Previously the transitive clause matched on target_path and returned every
/// member of every group the user was in.
/// </summary>
public sealed class UserLookupTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteDb _db;
    private readonly PermissionRepository _permRepo;
    private readonly long _scanId;

    public UserLookupTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"m365lookup_{Guid.NewGuid():N}.db");
        _db = new SqliteDb(_dbPath);
        _db.Initialize();
        var scanRepo = new ScanRepository(_db);
        _permRepo = new PermissionRepository(_db);
        _scanId = scanRepo.Create(new ScanInfo
        {
            TenantDomain = "lieben.nu",
            Status = ScanStatus.Completed,
            ScanTypes = "Entra,SharePoint",
            StartedAt = DateTime.UtcNow.ToString("O"),
            ModuleVersion = "0.1.0"
        });

        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            // Hans is a member of Group A
            new() { ScanId = _scanId, Category = "Entra", TargetType = "SecurityGroup", TargetPath = "Group/GroupA",
                    TargetId = "groupA", PrincipalEntraUpn = "hans@lieben.nu", PrincipalEntraId = "hansId",
                    PrincipalSysName = "Hans", PrincipalRole = "Member" },
            // Bob is ALSO a member of Group A — must NOT show up in Hans's lookup
            new() { ScanId = _scanId, Category = "Entra", TargetType = "SecurityGroup", TargetPath = "Group/GroupA",
                    TargetId = "groupA", PrincipalEntraUpn = "bob@lieben.nu", PrincipalEntraId = "bobId",
                    PrincipalSysName = "Bob", PrincipalRole = "Member" },
            // Group A is granted access to a SharePoint site — this IS Hans's effective access
            new() { ScanId = _scanId, Category = "SharePoint", TargetType = "Site", TargetPath = "https://contoso.sharepoint.com/sites/HR",
                    TargetId = "siteHR", PrincipalEntraId = "groupA", PrincipalSysName = "Group A", PrincipalType = "SecurityGroup",
                    PrincipalRole = "Contributor" },
            // An unrelated direct grant to Hans
            new() { ScanId = _scanId, Category = "SharePoint", TargetType = "Site", TargetPath = "https://contoso.sharepoint.com/sites/Direct",
                    TargetId = "siteDirect", PrincipalEntraUpn = "hans@lieben.nu", PrincipalEntraId = "hansId", PrincipalRole = "Read" }
        });
    }

    [Fact]
    public void UserLookup_IncludesOwnMembershipAndGroupEffectiveAccess_ButNotOtherMembers()
    {
        var result = _permRepo.QueryUserPermissions(_scanId, "hans@lieben.nu", page: 1, pageSize: 100);

        // Hans's own group membership
        Assert.Contains(result.Items, e => e.TargetPath == "Group/GroupA" && e.PrincipalEntraId == "hansId");
        // Effective access via Group A (group is the principal)
        Assert.Contains(result.Items, e => e.TargetPath.EndsWith("/HR") && e.PrincipalEntraId == "groupA");
        // Direct grant
        Assert.Contains(result.Items, e => e.TargetPath.EndsWith("/Direct"));

        // The roster leak: Bob (another member of Group A) must NOT appear.
        Assert.DoesNotContain(result.Items, e => e.PrincipalEntraId == "bobId");
        Assert.DoesNotContain(result.Items, e => e.PrincipalEntraUpn == "bob@lieben.nu");
    }

    [Fact]
    public void UserLookup_ReportsViaGroup_AndMatchesM365GroupOwnerClaim()
    {
        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            // Hans owns M365 group B; SharePoint grants the group's owners claim "<id>_o".
            new() { ScanId = _scanId, Category = "Entra", TargetType = "M365Group", TargetPath = "Group/GroupB",
                    TargetId = "groupB", PrincipalEntraUpn = "hans@lieben.nu", PrincipalEntraId = "hansId", PrincipalRole = "Owner" },
            new() { ScanId = _scanId, Category = "SharePoint", TargetType = "Site", TargetPath = "https://contoso.sharepoint.com/sites/B",
                    PrincipalEntraId = "groupB_o", PrincipalSysName = "GroupB Owners", PrincipalType = "M365Group", PrincipalRole = "Full Control" },
            // Members of group B (Hans isn't one) get this; it must not show for Hans.
            new() { ScanId = _scanId, Category = "SharePoint", TargetType = "Site", TargetPath = "https://contoso.sharepoint.com/sites/BMembers",
                    PrincipalEntraId = "groupB", PrincipalSysName = "GroupB Members", PrincipalType = "M365Group", PrincipalRole = "Edit" },
        });

        var result = _permRepo.QueryUserPermissions(_scanId, "hans@lieben.nu", page: 1, pageSize: 100);

        Assert.True(result.ExactMatch);
        var ownerRow = Assert.Single(result.Items, e => e.TargetPath.EndsWith("/sites/B"));
        Assert.Equal("GroupB", result.Via[ownerRow.Id]);
        var hrRow = Assert.Single(result.Items, e => e.TargetPath.EndsWith("/HR"));
        Assert.Equal("GroupA", result.Via[hrRow.Id]);
        Assert.DoesNotContain(result.Items, e => e.TargetPath.EndsWith("/BMembers"));
        Assert.False(result.Via.ContainsKey(result.Items.Single(e => e.TargetPath.EndsWith("/Direct")).Id));
    }

    [Fact]
    public void UserLookup_UpnSearch_IsExact_NotSubstring()
    {
        _permRepo.BulkInsert(new List<PermissionEntry>
        {
            new() { ScanId = _scanId, Category = "SharePoint", TargetType = "Site", TargetPath = "https://contoso.sharepoint.com/sites/Johans",
                    PrincipalEntraUpn = "johans@lieben.nu", PrincipalEntraId = "johansId", PrincipalRole = "Read" }
        });

        var result = _permRepo.QueryUserPermissions(_scanId, "hans@lieben.nu", page: 1, pageSize: 100);
        Assert.DoesNotContain(result.Items, e => e.PrincipalEntraUpn == "johans@lieben.nu");
    }

    public void Dispose()
    {
        _db.Dispose();
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
