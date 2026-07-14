using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

/// <summary>
/// Contract tests that guard against B3-class regressions: default policies whose
/// conditions no longer match what the scanners actually emit (so the policy silently
/// never fires). Each fixture entry mirrors the fields a real scanner produces; the
/// test asserts the intended policy is among the evaluated violations.
/// </summary>
public sealed class DefaultPolicyContractTests
{
    private static readonly IReadOnlyList<Policy> Policies = DefaultPolicies.GetAll();

    private static bool Fires(string policyName, PermissionEntry entry)
        => PolicyEngine.Evaluate(entry, Policies).Any(v => v.PolicyName == policyName);

    [Fact]
    public void PermanentActiveAdminRole_FiresForDirectoryRoleAssignment()
    {
        // Mirrors EntraScanner.MapDirectoryRoleMember for a Global Administrator.
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "DirectoryRole/Global Administrator",
            TargetType = "DirectoryRole",
            PrincipalRole = "Global Administrator",
            Through = "DirectoryRoleAssignment",
            Tenure = "Permanent"
        };
        Assert.True(Fires("Permanent active admin role", entry));
    }

    [Theory]
    [InlineData("Eligible-Permanent")]
    [InlineData("Eligible (until 2026-12-31T00:00:00Z)")]
    public void PimEligibleCriticalAdminRole_FiresForBothTenureShapes(string tenure)
    {
        // Mirrors EntraScanner PIM eligibility emit.
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "DirectoryRole/Security Administrator",
            TargetType = "DirectoryRole",
            PrincipalRole = "Security Administrator",
            Through = "PIM-Eligible",
            Tenure = tenure
        };
        Assert.True(Fires("PIM-eligible critical admin role", entry));
    }

    [Fact]
    public void PermanentNonCriticalDirectoryRole_FiresForNonAdminRole()
    {
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "DirectoryRole/Guest Inviter",
            TargetType = "DirectoryRole",
            PrincipalRole = "Guest Inviter",
            Through = "DirectoryRoleAssignment",
            Tenure = "Permanent"
        };
        Assert.True(Fires("Permanent non-critical directory role", entry));
    }

    [Fact]
    public void PermanentNonCriticalDirectoryRole_DoesNotFireForCriticalRole()
    {
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "DirectoryRole/Global Administrator",
            TargetType = "DirectoryRole",
            PrincipalRole = "Global Administrator",
            Through = "DirectoryRoleAssignment",
            Tenure = "Permanent"
        };
        Assert.False(Fires("Permanent non-critical directory role", entry));
    }

    [Fact]
    public void AdminConsentedOAuth2Grant_FiresForAllPrincipalsHighRiskScope()
    {
        // Mirrors EntraScanner OAuth2PermissionGrant emit (Through has a "→ resource" suffix).
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "OAuth2PermissionGrant/Some App",
            TargetType = "DelegatedConsent",
            PrincipalType = "AllPrincipals",
            PrincipalRole = "Mail.ReadWrite",
            Through = "OAuth2Grant → Microsoft Graph",
            Tenure = "Permanent"
        };
        Assert.True(Fires("Admin-consented OAuth2 grant", entry));
    }

    [Fact]
    public void AnonymousSharingLink_FiresForOneDriveAnonymousLink()
    {
        // Mirrors OneDriveScanner sharing-link mapping (scope=anonymous).
        var entry = new PermissionEntry
        {
            Category = "OneDrive",
            TargetPath = "https://contoso-my.sharepoint.com/personal/user/Documents/secret.docx",
            PrincipalSysName = "Sharing Link (anonymous)",
            PrincipalType = "Anonymous",
            PrincipalRole = "view",
            Through = "Direct"
        };
        Assert.True(Fires("Anonymous sharing link", entry));
    }

    [Fact]
    public void OrganizationWideSharingLink_FiresForOneDriveOrganizationLink()
    {
        var entry = new PermissionEntry
        {
            Category = "OneDrive",
            TargetPath = "https://contoso-my.sharepoint.com/personal/user/Documents/plan.docx",
            PrincipalSysName = "Sharing Link (organization)",
            PrincipalType = "AllInternalUsers",
            PrincipalRole = "edit",
            Through = "Direct"
        };
        Assert.True(Fires("Organization-wide sharing link", entry));
    }

    [Fact]
    public void AzureManagementGroupOwner_FiresAsCritical()
    {
        // Mirrors AzureScanner management-group role assignment emit (A5).
        var entry = new PermissionEntry
        {
            Category = "Azure",
            TargetPath = "Azure/ManagementGroup/Tenant Root Group",
            TargetType = "ManagementGroup",
            PrincipalRole = "Owner",
            Through = "AzureRBAC"
        };
        Assert.True(Fires("Azure management-group Owner/Contributor", entry));
    }

    [Fact]
    public void HighRiskApplicationPermission_FiresForConsentedAppRole()
    {
        // Mirrors EntraScanner application-permission emit (Through=ApplicationPermission).
        var entry = new PermissionEntry
        {
            Category = "Entra",
            TargetPath = "Application/Some App",
            PrincipalType = "Application",
            PrincipalRole = "Directory.ReadWrite.All",
            Through = "ApplicationPermission",
            Tenure = "Permanent"
        };
        Assert.True(Fires("High-risk application permission", entry));
    }
}
