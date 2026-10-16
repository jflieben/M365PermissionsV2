using System.Text.Json;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class DevOpsPurviewScannerMappingTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    // ── Azure DevOps ────────────────────────────────────────────

    private static readonly AzureDevOpsScanner.DevOpsGroup ProjectAdmins = new()
    {
        DisplayName = "Project Administrators",
        PrincipalName = "[Web]\\Project Administrators"
    };

    [Fact]
    public void DevOps_EntraGroup_MapsToSecurityGroupWithOriginId()
    {
        var subject = AzureDevOpsScanner.ParseSubject(Json(
            """{"subjectKind":"group","origin":"aad","originId":"66666666-6666-6666-6666-666666666666","displayName":"DevOps Admins","descriptor":"aadgp.abc"}"""), "aadgp.abc");

        var entry = AzureDevOpsScanner.MapMember(subject, ProjectAdmins, "AzureDevOps/org/Web", "Project", "p1");

        Assert.Equal("SecurityGroup", entry.PrincipalType);
        Assert.Equal("66666666-6666-6666-6666-666666666666", entry.PrincipalEntraId);
        Assert.Equal("DevOps Admins", entry.PrincipalSysName);
        Assert.Equal("aadgp.abc", entry.PrincipalSysId);
        Assert.Equal("Project Administrators", entry.PrincipalRole);
    }

    [Fact]
    public void DevOps_EntraUser_UsesPrincipalNameAsUpn()
    {
        var subject = AzureDevOpsScanner.ParseSubject(Json(
            """{"subjectKind":"user","origin":"aad","originId":"77777777-7777-7777-7777-777777777777","principalName":"jane@contoso.com","mailAddress":"jane.doe@contoso.com","metaType":"member"}"""), "aad.x");

        var entry = AzureDevOpsScanner.MapMember(subject, ProjectAdmins, "p", "Project", "p1");

        Assert.Equal("User", entry.PrincipalType);
        Assert.Equal("jane@contoso.com", entry.PrincipalEntraUpn);
        Assert.Equal("77777777-7777-7777-7777-777777777777", entry.PrincipalEntraId);
        Assert.Equal("aad.x", entry.PrincipalSysId);
    }

    [Fact]
    public void DevOps_MsaUser_HasNoEntraId()
    {
        var subject = AzureDevOpsScanner.ParseSubject(Json(
            """{"subjectKind":"user","origin":"msa","originId":"00037FFE00000000","mailAddress":"x@outlook.com"}"""), "msa.x");

        Assert.Equal("", AzureDevOpsScanner.MapMember(subject, ProjectAdmins, "p", "Project", "p1").PrincipalEntraId);
    }

    [Theory]
    [InlineData("user", null, "User")]
    [InlineData("user", "guest", "Guest")]
    [InlineData("group", null, "SecurityGroup")]
    [InlineData("servicePrincipal", null, "Application")]
    [InlineData("", null, "Unknown")]
    public void DevOps_MapPrincipalType(string kind, string? metaType, string expected)
    {
        Assert.Equal(expected, AzureDevOpsScanner.MapPrincipalType(kind, metaType));
    }

    [Fact]
    public void DevOps_TryParseJson_RejectsHtmlAndInvalidBodies()
    {
        Assert.Null(AzureDevOpsScanner.TryParseJson("  <html>sign in</html>"));
        Assert.Null(AzureDevOpsScanner.TryParseJson(""));
        Assert.Null(AzureDevOpsScanner.TryParseJson("{not json"));
        using var doc = AzureDevOpsScanner.TryParseJson("""{"value":[]}""");
        Assert.NotNull(doc);
    }

    [Fact]
    public void DevOps_ExtractRoleName()
    {
        Assert.Equal("Contributors", AzureDevOpsScanner.ExtractRoleName("[Web]\\Contributors"));
        Assert.Equal("Readers", AzureDevOpsScanner.ExtractRoleName("Readers"));
    }

    // ── Purview ─────────────────────────────────────────────────

    [Theory]
    [InlineData("UserMailbox", "User")]
    [InlineData("MailUser", "User")]
    [InlineData("User", "User")]
    [InlineData("GuestMailUser", "Guest")]
    [InlineData("MailUniversalSecurityGroup", "SecurityGroup")]
    [InlineData("UniversalSecurityGroup", "SecurityGroup")]
    [InlineData("MailUniversalDistributionGroup", "SecurityGroup")]
    [InlineData("RoleGroup", "SecurityGroup")]
    [InlineData("Group", "SecurityGroup")]
    [InlineData("GroupMailbox", "M365Group")]
    [InlineData("ServicePrincipal", "Application")]
    [InlineData("SomethingNew", "Unknown")]
    public void Purview_MapRecipientType(string recipientType, string expected)
    {
        Assert.Equal(expected, PurviewScanner.MapRecipientType(recipientType));
    }

    [Fact]
    public void Purview_Member_UsesDisplayNameAsRoleAndExternalIdAsEntraId()
    {
        var group = new PurviewScanner.ComplianceRoleGroup { Name = "OrganizationManagement", DisplayName = "Organization Management", Guid = "g1", IsBuiltIn = true };
        var member = Json("""{"DisplayName":"Jane","WindowsLiveID":"jane@contoso.com","RecipientType":"MailUser","RecipientTypeDetails":"GuestMailUser","ExternalDirectoryObjectId":"88888888-8888-8888-8888-888888888888"}""");

        var entry = PurviewScanner.MapComplianceRoleMember(member, group)!;

        Assert.Equal("Organization Management", entry.PrincipalRole);
        Assert.Equal("Purview/Organization Management", entry.TargetPath);
        Assert.Equal("88888888-8888-8888-8888-888888888888", entry.PrincipalEntraId);
        Assert.Equal("Guest", entry.PrincipalType);
        Assert.Equal("ComplianceBuiltInRole", entry.TargetType);
    }

    [Fact]
    public void Purview_Member_FallsBackToNameWithoutDisplayName()
    {
        var group = new PurviewScanner.ComplianceRoleGroup { Name = "eDiscoveryManager" };
        var member = Json("""{"DisplayName":"Jane","RecipientType":"UserMailbox"}""");

        Assert.Equal("eDiscoveryManager", PurviewScanner.MapComplianceRoleMember(member, group)!.PrincipalRole);
    }
}
