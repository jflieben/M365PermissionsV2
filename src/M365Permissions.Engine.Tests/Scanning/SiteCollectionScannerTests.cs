using System.Text.Json;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class SiteCollectionScannerTests
{
    [Theory]
    [InlineData("c:0t.c|tenant|1A2B3C4D-0000-0000-0000-000000000000", "1a2b3c4d-0000-0000-0000-000000000000")]
    [InlineData("c:0o.c|federateddirectoryclaimprovider|1a2b3c4d-0000-0000-0000-000000000000", "1a2b3c4d-0000-0000-0000-000000000000")]
    [InlineData("c:0o.c|federateddirectoryclaimprovider|1a2b3c4d-0000-0000-0000-000000000000_o", "1a2b3c4d-0000-0000-0000-000000000000_o")]
    [InlineData("i:0#.f|membership|jane@contoso.com", "")]
    [InlineData("c:0t.c|tenant|not-a-guid", "")]
    public void ExtractEntraId_ReadsGroupClaims(string loginName, string expected)
    {
        Assert.Equal(expected, SharePointPrincipal.ExtractEntraId(loginName));
    }

    [Fact]
    public void IsAccount_MatchesExactUpnOnly()
    {
        Assert.True(SharePointPrincipal.IsAccount("i:0#.f|membership|Jos@contoso.com", "jos@contoso.com"));
        Assert.False(SharePointPrincipal.IsAccount("i:0#.f|membership|bjos@contoso.com", "jos@contoso.com"));
        Assert.False(SharePointPrincipal.IsAccount("i:0#.f|membership|jos@contoso.com", ""));
    }

    [Theory]
    [InlineData("""{"Id":1073741829,"Name":"Volledig beheer","RoleTypeKind":5,"Hidden":false}""", "Full Control")]
    [InlineData("""{"Id":1073741827,"Name":"Bijdragen","RoleTypeKind":3,"Hidden":false}""", "Contribute")]
    [InlineData("""{"Id":1073741924,"Name":"View Only","RoleTypeKind":0,"Hidden":false}""", "View Only")]
    [InlineData("""{"Id":1073741930,"Name":"Custom Approver","RoleTypeKind":0,"Hidden":false}""", "Custom Approver")]
    [InlineData("""{"Id":1073741825,"Name":"Limited Access","RoleTypeKind":1,"Hidden":true}""", null)]
    [InlineData("""{"Id":1073741926,"Name":"Web-Only Limited Access","RoleTypeKind":0,"Hidden":true}""", null)]
    public void CanonicalRole_IsLocaleIndependentAndKeepsViewOnly(string json, string? expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(expected, SharePointPrincipal.CanonicalRole(doc.RootElement));
    }

    [Theory]
    [InlineData("SharingLinks.0d7c1d6e-9f5b-4a39-9b0b-4a1a2b3c4d5e.AnonymousEdit.11111111-2222-3333-4444-555555555555", "Anonymous", "Edit")]
    [InlineData("SharingLinks.0d7c1d6e-9f5b-4a39-9b0b-4a1a2b3c4d5e.OrganizationView.11111111-2222-3333-4444-555555555555", "Organization", "Read")]
    [InlineData("SharingLinks.0d7c1d6e-9f5b-4a39-9b0b-4a1a2b3c4d5e.Flexible.11111111-2222-3333-4444-555555555555", "SpecificPeople", "View or Edit")]
    public void ParseSharingLinkGroup_ReadsScopeAndRole(string title, string scope, string role)
    {
        var link = SiteCollectionScanner.ParseSharingLinkGroup(title);
        Assert.NotNull(link);
        Assert.Equal("0d7c1d6e-9f5b-4a39-9b0b-4a1a2b3c4d5e", link!.Value.ItemId);
        Assert.Equal(scope, link.Value.Scope);
        Assert.Equal(role, link.Value.Role);
    }

    [Theory]
    [InlineData("Contoso Members")]
    [InlineData("SharingLinks.not-a-guid.Flexible.x")]
    public void ParseSharingLinkGroup_IgnoresOtherGroups(string title)
    {
        Assert.Null(SiteCollectionScanner.ParseSharingLinkGroup(title));
    }

    [Theory]
    [InlineData("https://contoso.sharepoint.com/sites/appcatalog", "", true)]
    [InlineData("https://contoso.sharepoint.com/sites/appcatalog-project", "", false)]
    [InlineData("https://contoso.sharepoint.com/sites/old", "REDIRECTSITE#0", true)]
    [InlineData("https://contoso-my.sharepoint.com/personal/jane_contoso_com", "SPSPERS#10", true)]
    [InlineData("https://contoso.sharepoint.com/sites/Project-Private", "TEAMCHANNEL#1", false)]
    public void IsSystemSite_MatchesWholePathsAndTemplates(string url, string template, bool expected)
    {
        Assert.Equal(expected, SharePointScanner.IsSystemSite(new SiteTarget { Url = url, Template = template }));
    }

    [Fact]
    public void GraphSitePermission_EmitsEveryApplication()
    {
        using var doc = JsonDocument.Parse("""
            {"id":"x","roles":["write"],"grantedToIdentitiesV2":[
              {"application":{"id":"a1","displayName":"App One"}},
              {"application":{"id":"a2","displayName":"App Two"}}]}
            """);
        var rows = SiteCollectionScanner.MapGraphSitePermission(doc.RootElement, "https://contoso.sharepoint.com/sites/x", "sid").ToList();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("write", r.PrincipalRole));
    }

    [Fact]
    public void OneDrive_PersonalSiteDetection()
    {
        Assert.True(OneDriveScanner.IsPersonalSite(new SiteTarget { Url = "https://contoso-my.sharepoint.com/personal/jane_contoso_com" }));
        Assert.False(OneDriveScanner.IsPersonalSite(new SiteTarget { Url = "https://contoso-my.sharepoint.com", Template = "SPSMSITEHOST#0" }));
    }
}
