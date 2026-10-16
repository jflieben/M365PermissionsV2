using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

/// <summary>
/// Contract tests between the scanners' vocabulary and the built-in policies: each fixture mirrors
/// what a scanner emits, and the test pins the severity the row must get. Guards against policies
/// that silently never fire (or fire too high) after a vocabulary change.
/// </summary>
public sealed class DefaultPolicyContractTests
{
    private static readonly IReadOnlyList<Policy> Policies = DefaultPolicies.GetAll();

    private static string Severity(PermissionEntry entry)
    {
        PolicyEngine.Classify(entry, Policies);
        return entry.RiskLevel;
    }

    private static bool Fires(string key, PermissionEntry entry)
    {
        var policy = Policies.Single(p => p.DefaultKey == key);
        return PolicyEngine.Evaluate(entry, Policies).Any(v => v.PolicyName == policy.Name);
    }

    private static PermissionEntry Role(string role, string tenure, string through = "DirectoryRoleAssignment", string scope = "") => new()
    {
        Category = "Entra",
        TargetPath = $"DirectoryRole/{role}{scope}",
        TargetType = "DirectoryRole",
        PrincipalType = "User",
        PrincipalRole = role,
        Through = through,
        Tenure = tenure
    };

    [Fact]
    public void AllDefaults_AreValid_HaveUniqueKeys_AndRemediation()
    {
        Assert.Equal(Policies.Count, Policies.Select(p => p.DefaultKey).Distinct().Count());
        foreach (var p in Policies)
        {
            Assert.Empty(PolicyEngine.Validate(p));
            Assert.False(string.IsNullOrWhiteSpace(p.Remediation), $"{p.DefaultKey} has no remediation");
            Assert.True(p.IsDefault);
        }
    }

    [Fact]
    public void LegacyNames_PointAtExistingKeys()
    {
        var keys = Policies.Select(p => p.DefaultKey).ToHashSet();
        foreach (var key in DefaultPolicies.LegacyNames.Values)
            Assert.Contains(key, keys);
    }

    // ── Entra roles ─────────────────────────────────────────

    [Theory]
    [InlineData("Global Administrator", "Permanent", "Critical")]
    [InlineData("Hybrid Identity Administrator", "Permanent", "Critical")]
    [InlineData("Domain Name Administrator", "Permanent", "Critical")]
    [InlineData("External Identity Provider Administrator", "Permanent", "Critical")]
    [InlineData("Billing Administrator", "Permanent", "High")]
    [InlineData("Guest Inviter", "Permanent", "Medium")]
    [InlineData("Global Administrator", "Eligible-Permanent", "High")]
    [InlineData("Security Administrator", "Eligible (until 2026-12-31T00:00:00Z)", "High")]
    [InlineData("Global Administrator", "Active (until 2026-12-31T00:00:00Z)", "High")]
    [InlineData("Global Administrator", "Activated (PIM, until 2026-12-31T00:00:00Z)", "Medium")]
    [InlineData("Global Administrator", "Activated (PIM)", "Medium")]
    [InlineData("Billing Administrator", "Eligible-Permanent", "Medium")]
    public void DirectoryRoles_ScoreByRoleAndTenure(string role, string tenure, string expected)
        => Assert.Equal(expected, Severity(Role(role, tenure)));

    [Fact]
    public void RoleViaRoleAssignableGroup_ScoresLikeDirectHolder()
        => Assert.Equal("Critical", Severity(Role("Global Administrator", "Permanent", through: "GroupMember")));

    [Fact]
    public void AdministrativeUnitScopedRole_IsOneLevelLower()
    {
        Assert.Equal("High", Severity(Role("User Administrator", "Permanent", scope: " (scope: /administrativeUnits/x, AU Sales)")));
        Assert.Equal("Medium", Severity(Role("User Administrator", "Eligible-Permanent", scope: " (scope: /administrativeUnits/x, AU Sales)")));
    }

    // ── Entra apps and consent ──────────────────────────────

    [Theory]
    [InlineData("RoleManagement.ReadWrite.Directory", "Critical")]
    [InlineData("AppRoleAssignment.ReadWrite.All", "Critical")]
    [InlineData("Mail.Read", "High")]
    [InlineData("Files.Read.All", "High")]
    [InlineData("full_access_as_app", "High")]
    [InlineData("Policy.ReadWrite.ConditionalAccess", "High")]
    [InlineData("Mail.ReadBasic", "Info")]
    [InlineData("User.Read.All", "Info")]
    public void ApplicationPermissions_Score(string permission, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "Entra", TargetPath = "Application/Some App", PrincipalType = "Application",
            PrincipalRole = permission, Through = "ApplicationPermission", Tenure = "Granted"
        }));

    [Fact]
    public void OAuth2Grants_AdminConsentHigh_UserConsentMedium()
    {
        PermissionEntry Grant(string through, string type) => new()
        {
            Category = "Entra", TargetPath = "OAuth2PermissionGrant/Some App → Microsoft Graph", TargetType = "DelegatedConsent",
            PrincipalType = type, PrincipalRole = "Mail.ReadWrite", Through = through
        };
        Assert.Equal("High", Severity(Grant("OAuth2Grant (AllPrincipals)", "Application")));
        Assert.Equal("Medium", Severity(Grant("OAuth2Grant (Principal)", "User")));
    }

    [Fact]
    public void AppOwner_IsMedium()
        => Assert.Equal("Medium", Severity(new PermissionEntry
        {
            Category = "Entra", TargetPath = "Application/Some App", TargetType = "Application",
            PrincipalType = "User", PrincipalRole = "Owner", Through = "ApplicationOwner"
        }));

    // ── Groups, Teams, guests ───────────────────────────────

    [Theory]
    [InlineData("SecurityGroup")]
    [InlineData("M365Group")]
    [InlineData("DistributionList")]
    public void GroupOwner_NeverBelowMember(string targetType)
    {
        PermissionEntry Row(string role) => new()
        {
            Category = "Entra", TargetPath = "Group/Sales", TargetType = targetType, PrincipalType = "User", PrincipalRole = role
        };
        Assert.Equal("Medium", Severity(Row("Owner")));
        Assert.Equal("Low", Severity(Row("Member")));
    }

    [Fact]
    public void TeamOwner_IsMedium_GuestMember_IsMedium_GuestOwner_IsHigh()
    {
        PermissionEntry Row(string role, string type) => new()
        {
            Category = "Teams", TargetPath = "Teams/Sales", TargetType = "Team", PrincipalType = type, PrincipalRole = role, Through = "TeamMembership"
        };
        Assert.Equal("Medium", Severity(Row("Owner", "User")));
        Assert.Equal("Low", Severity(Row("Member", "User")));
        Assert.Equal("Medium", Severity(Row("Member", "Guest")));
        Assert.Equal("High", Severity(Row("Owner", "Guest")));
    }

    [Theory]
    [InlineData("Guest", "Edit", "High")]
    [InlineData("External User", "Full Control", "High")]
    [InlineData("External User", "Read", "Medium")]
    [InlineData("External Group", "Member", "Medium")]
    public void GuestsAndExternals(string type, string role, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "SharePoint", TargetPath = "https://contoso.sharepoint.com/sites/x", TargetType = "Site",
            PrincipalType = type, PrincipalRole = role, Through = "Direct"
        }));

    // ── SharePoint / OneDrive ───────────────────────────────

    private static PermissionEntry Sp(string type, string role, string through = "Direct", string name = "", string category = "SharePoint", string targetType = "Site") => new()
    {
        Category = category, TargetPath = "https://contoso.sharepoint.com/sites/x", TargetType = targetType,
        PrincipalType = type, PrincipalRole = role, Through = through, PrincipalSysName = name
    };

    [Theory]
    [InlineData("Anonymous", "Edit", "SharingLink", "Critical")]
    [InlineData("Anonymous", "View or Edit", "SharingLink", "Critical")]
    [InlineData("Anonymous", "Read", "SharingLink", "High")]
    [InlineData("Everyone", "Edit", "SharingLink", "Medium")]
    [InlineData("Everyone", "Read", "SharingLink", "Medium")]
    [InlineData("Everyone", "Full Control", "Direct", "Critical")]
    [InlineData("Everyone", "Edit", "Direct", "High")]
    [InlineData("Everyone", "Read", "Direct", "Medium")]
    [InlineData("Internal User", "Site Collection Administrator", "Direct", "Medium")]
    [InlineData("Internal User", "Full Control", "SharePointGroup", "Medium")]
    [InlineData("Internal User", "Edit", "Direct", "Low")]
    [InlineData("Internal User", "Read", "Direct", "Info")]
    public void SharePoint_Score(string type, string role, string through, string expected)
        => Assert.Equal(expected, Severity(Sp(type, role, through)));

    [Fact]
    public void OneDrive_AnonymousFileLink_IsHigh()
        => Assert.Equal("High", Severity(Sp("Anonymous", "Read", "SharingLink", "Anyone link", "OneDrive", "File")));

    [Fact]
    public void LegacyBroadPrincipalName_StillMedium_ButUnanchoredLookalikeDoesNot()
    {
        Assert.Equal("Medium", Severity(Sp("SecurityGroup", "Read", name: "Everyone except external users")));
        Assert.Equal("Info", Severity(Sp("SecurityGroup", "Read", name: "Everyone in Sales team")));
    }

    // ── Exchange ────────────────────────────────────────────

    private static PermissionEntry Exo(string targetType, string role, string type = "User", string access = "Allow", string through = "MailboxPermission") => new()
    {
        Category = "Exchange", TargetPath = "john@contoso.com", TargetType = targetType,
        PrincipalType = type, PrincipalRole = role, Through = through, AccessType = access
    };

    [Fact]
    public void Exchange_Scores()
    {
        Assert.Equal("High", Severity(Exo("Mailbox", "FullAccess")));
        Assert.Equal("High", Severity(Exo("Mailbox", "SendAs", through: "RecipientPermission")));
        Assert.Equal("Medium", Severity(Exo("SharedMailbox", "FullAccess")));
        Assert.Equal("Low", Severity(Exo("Mailbox", "SendOnBehalf", through: "GrantSendOnBehalfTo")));
        Assert.Equal("Low", Severity(Exo("Mailbox", "FullAccess", type: "Orphaned SID")));
    }

    [Fact]
    public void DenyRows_AreNeverRisky()
    {
        var deny = Exo("Mailbox", "FullAccess", access: "Deny");
        Assert.Equal("Info", Severity(deny));
        Assert.Equal(PolicyEngine.DenyReason, deny.RiskReason);
        Assert.Empty(PolicyEngine.Evaluate(deny, Policies));
    }

    // ── Azure ───────────────────────────────────────────────

    private static PermissionEntry Az(string targetType, string role, string tenure, string type = "User") => new()
    {
        Category = "Azure", TargetPath = "/subscriptions/x", TargetType = targetType,
        PrincipalType = type, PrincipalRole = role, Through = "AzureRBAC", Tenure = tenure
    };

    [Theory]
    [InlineData("ManagementGroup", "Owner", "Permanent", "Critical")]
    [InlineData("Subscription", "Contributor", "Permanent", "Critical")]
    [InlineData("Subscription", "Owner", "Active (until 2026-12-31)", "High")]
    [InlineData("Subscription", "Owner", "Eligible-Permanent", "Medium")]
    [InlineData("Subscription", "Owner", "Activated (PIM)", "Medium")]
    [InlineData("ResourceGroup", "Contributor", "Permanent", "High")]
    [InlineData("ResourceGroup", "Owner", "Eligible (until 2026-12-31)", "Low")]
    [InlineData("Resource", "Role Based Access Control Administrator", "Permanent", "High")]
    [InlineData("Resource", "User Access Administrator", "Permanent", "High")]
    [InlineData("Resource", "Contributor", "Permanent", "Medium")]
    [InlineData("Subscription", "Reader", "Permanent", "Info")]
    public void Azure_Scores(string targetType, string role, string tenure, string expected)
        => Assert.Equal(expected, Severity(Az(targetType, role, tenure)));

    [Fact]
    public void Azure_DeletedPrincipal_IsCleanupLow()
        => Assert.Equal("Low", Severity(Az("Subscription", "Owner", "Permanent", type: "Deleted principal")));

    // ── DevOps, Purview, Power BI, Power Platform ───────────

    [Theory]
    [InlineData("Organization", "Project Collection Administrators", "Critical")]
    [InlineData("Organization", "Project Collection Build Administrators", "High")]
    [InlineData("Project", "Project Administrators", "High")]
    [InlineData("Project", "Contributors", "Low")]
    [InlineData("Project", "Readers", "Info")]
    public void DevOps_Scores(string targetType, string role, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "AzureDevOps", TargetPath = "AzureDevOps/contoso", TargetType = targetType,
            PrincipalType = "User", PrincipalRole = role, Through = "Group: " + role
        }));

    [Theory]
    [InlineData("Organization Management", "Critical")]
    [InlineData("OrganizationManagement", "Critical")]
    [InlineData("eDiscovery Manager", "Critical")]
    [InlineData("Compliance Administrator", "Critical")]
    [InlineData("Records Management", "High")]
    [InlineData("InsiderRiskManagement", "High")]
    public void Purview_Scores_WithAndWithoutSpaces(string roleGroup, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "Purview", TargetPath = $"Purview/{roleGroup}", TargetType = "RoleGroup",
            PrincipalType = "User", PrincipalRole = roleGroup, Through = "RoleGroupMember"
        }));

    [Theory]
    [InlineData("Workspace", "Admin", "Medium")]
    [InlineData("Workspace", "Member", "Low")]
    [InlineData("Workspace", "Contributor", "Low")]
    [InlineData("Workspace", "Viewer", "Info")]
    [InlineData("PersonalWorkspace", "Admin", "Info")]
    [InlineData("OrphanedWorkspace", "Viewer", "Medium")]
    public void PowerBI_Scores(string targetType, string role, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "PowerBI", TargetPath = "PowerBI/Sales", TargetType = targetType,
            PrincipalType = "User", PrincipalRole = role, Through = "WorkspaceAccess"
        }));

    [Theory]
    [InlineData("Everyone", "CanView", "Medium")]
    [InlineData("Everyone", "CanEdit", "High")]
    [InlineData("User", "Owner", "Medium")]
    [InlineData("User", "Creator", "Medium")]
    [InlineData("User", "CanView", "Info")]
    public void PowerPlatform_Scores(string type, string role, string expected)
        => Assert.Equal(expected, Severity(new PermissionEntry
        {
            Category = "PowerAutomate", TargetPath = "PowerPlatform/Default/Flow", TargetType = "Flow",
            PrincipalType = type, PrincipalSysName = type == "Everyone" ? "Everyone in the organization" : "John",
            PrincipalRole = role, Through = "Direct"
        }));

    [Fact]
    public void Fires_ReturnsRemediation()
    {
        var entry = Role("Global Administrator", "Permanent");
        Assert.True(Fires("entra-permanent-critical-role", entry));
        Assert.All(PolicyEngine.Evaluate(entry, Policies), v => Assert.False(string.IsNullOrEmpty(v.Remediation)));
    }
}
