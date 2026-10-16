using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class EntraMappingTests
{
    [Theory]
    [InlineData("Assigned", null, "Permanent")]
    [InlineData("Assigned", "", "Permanent")]
    [InlineData(null, null, "Permanent")]
    [InlineData("Assigned", "2026-12-31T00:00:00Z", "Active (until 2026-12-31T00:00:00Z)")]
    [InlineData("Activated", "2026-10-14T18:00:00Z", "Activated (PIM, until 2026-10-14T18:00:00Z)")]
    [InlineData("activated", null, "Activated (PIM)")]
    public void ActiveTenure_OnlyAssignedWithoutEndIsPermanent(string? assignmentType, string? end, string expected)
    {
        Assert.Equal(expected, RoleTenure.Active(assignmentType, end));
    }

    [Fact]
    public void ActivatedRole_DoesNotFirePermanentAdminPolicy()
    {
        // The admin who activated Global Administrator to run the scan must not be flagged as permanent.
        Assert.NotEqual("Permanent", RoleTenure.Active("Activated", "2026-10-14T18:00:00Z"));
    }

    [Theory]
    [InlineData(null, "Eligible-Permanent")]
    [InlineData("2026-12-31T00:00:00Z", "Eligible (until 2026-12-31T00:00:00Z)")]
    public void EligibleTenure_KeepsEligiblePrefix(string? end, string expected)
    {
        var tenure = RoleTenure.Eligible(end);
        Assert.Equal(expected, tenure);
        Assert.StartsWith("Eligible", tenure);
    }

    [Theory]
    [InlineData(new[] { "Unified" }, false, true, "M365Group")]
    [InlineData(new[] { "Unified", "DynamicMembership" }, false, true, "M365Group")]
    [InlineData(new string[0], true, false, "SecurityGroup")]
    [InlineData(new string[0], true, true, "SecurityGroup")]          // mail-enabled security group
    [InlineData(new[] { "DynamicMembership" }, true, false, "SecurityGroup")]
    [InlineData(new string[0], false, true, "DistributionList")]
    public void ClassifyGroup_UsesGroupTypesAndFlags(string[] groupTypes, bool securityEnabled, bool mailEnabled, string expected)
    {
        Assert.Equal(expected, EntraScanner.ClassifyGroup(groupTypes, securityEnabled, mailEnabled));
    }

    [Theory]
    [InlineData("#microsoft.graph.user", "Guest", "", "Guest")]
    [InlineData("#microsoft.graph.user", "", "john_contoso.com#EXT#@fabrikam.onmicrosoft.com", "Guest")]
    [InlineData("#microsoft.graph.user", "Member", "jane@fabrikam.com", "User")]
    [InlineData("#microsoft.graph.group", "", "", "Group")]
    [InlineData("#microsoft.graph.servicePrincipal", "", "", "ServicePrincipal")]
    [InlineData("", "", "", "Unknown")]
    public void MapMemberType_DetectsGuests(string odataType, string userType, string upn, string expected)
    {
        Assert.Equal(expected, EntraScanner.MapMemberType(odataType, userType, upn));
    }

    [Fact]
    public void RoleTargetPath_TenantWideIsBareRole()
    {
        Assert.Equal("DirectoryRole/Global Administrator", EntraScanner.RoleTargetPath("Global Administrator", "/"));
        Assert.Equal("DirectoryRole/Global Administrator", EntraScanner.RoleTargetPath("Global Administrator", null));
    }

    [Fact]
    public void RoleTargetPath_ScopedAssignmentCarriesScopeAndName()
    {
        var names = new Dictionary<string, string> { ["/administrativeUnits/au1"] = "AU Sales" };
        Assert.Equal("DirectoryRole/User Administrator (scope: /administrativeUnits/au1, AU Sales)",
            EntraScanner.RoleTargetPath("User Administrator", "/administrativeUnits/au1", names));
        Assert.Equal("DirectoryRole/Application Administrator (scope: /app1)",
            EntraScanner.RoleTargetPath("Application Administrator", "/app1", names));
    }
}
