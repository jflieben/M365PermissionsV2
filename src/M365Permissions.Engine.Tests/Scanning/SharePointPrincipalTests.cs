using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class SharePointPrincipalTests
{
    [Theory]
    [InlineData("i:0#.f|membership|john_contoso.com#ext#@fabrikam.onmicrosoft.com", "External User")]
    [InlineData("i:0#.f|membership|urn:spo:guest#john@contoso.com", "External User")]
    [InlineData("i:0#.f|membership|jane@fabrikam.com", "Internal User")]
    [InlineData("c:0(.s|true", "Everyone")]
    [InlineData("c:0-.f|rolemanager|spo-grid-all-users/1a2b3c4d-0000-0000-0000-000000000000", "Everyone")]
    [InlineData("c:0t.c|tenant|1a2b3c4d-0000-0000-0000-000000000000", "SecurityGroup")]
    [InlineData("c:0o.c|federateddirectoryclaimprovider|1a2b3c4d-0000-0000-0000-000000000000_o", "SecurityGroup")]
    [InlineData("SHAREPOINT\\system", "Unknown")]
    [InlineData("", "Unknown")]
    public void DetermineType_ClassifiesLoginNames(string loginName, string expected)
    {
        Assert.Equal(expected, SharePointPrincipal.DetermineType(loginName));
    }

    [Fact]
    public void DetermineType_UsesPrincipalTypeCodeForSharePointGroups()
    {
        // SharePoint groups carry their title as LoginName.
        Assert.Equal("SharePoint Group", SharePointPrincipal.DetermineType("Project Site Members", 8));
    }

    [Fact]
    public void GuestOnSite_FiresGuestPolicy()
    {
        var entry = new PermissionEntry
        {
            Category = "SharePoint",
            TargetType = "Site",
            PrincipalType = SharePointPrincipal.DetermineType("i:0#.f|membership|john_contoso.com#ext#@fabrikam.onmicrosoft.com"),
            PrincipalRole = "Edit",
            Through = "Direct"
        };

        Assert.Contains(PolicyEngine.Evaluate(entry, DefaultPolicies.GetAll()), v => v.PolicyName == "Guest/external user access");
    }
}
