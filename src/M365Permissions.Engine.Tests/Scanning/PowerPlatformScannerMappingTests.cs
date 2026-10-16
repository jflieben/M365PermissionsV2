using System.Text.Json;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class PowerPlatformScannerMappingTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    // ── Power BI ────────────────────────────────────────────────

    [Fact]
    public void PowerBI_User_UsesGraphIdAsEntraIdAndIdentifierAsUpn()
    {
        var user = Json("""{"identifier":"jane@contoso.com","graphId":"11111111-1111-1111-1111-111111111111","principalType":"User","groupUserAccessRight":"Admin","displayName":"Jane"}""");

        var entry = PowerBIScanner.MapWorkspaceUser(user, "Sales", "ws1", "Workspace")!;

        Assert.Equal("11111111-1111-1111-1111-111111111111", entry.PrincipalEntraId);
        Assert.Equal("jane@contoso.com", entry.PrincipalEntraUpn);
        Assert.Equal("User", entry.PrincipalType);
        Assert.Equal("Admin", entry.PrincipalRole);
    }

    [Fact]
    public void PowerBI_UserWithoutGraphId_DoesNotPutUpnInEntraId()
    {
        var user = Json("""{"identifier":"jane@contoso.com","principalType":"User","groupUserAccessRight":"Viewer"}""");

        var entry = PowerBIScanner.MapWorkspaceUser(user, "Sales", "ws1", "Workspace")!;

        Assert.Equal("", entry.PrincipalEntraId);
        Assert.Equal("jane@contoso.com", entry.PrincipalEntraUpn);
    }

    [Fact]
    public void PowerBI_Group_UsesIdentifierAsEntraId()
    {
        var group = Json("""{"identifier":"22222222-2222-2222-2222-222222222222","principalType":"Group","groupUserAccessRight":"Member","displayName":"Finance"}""");

        var entry = PowerBIScanner.MapWorkspaceUser(group, "Sales", "ws1", "Workspace")!;

        Assert.Equal("22222222-2222-2222-2222-222222222222", entry.PrincipalEntraId);
        Assert.Equal("", entry.PrincipalEntraUpn);
        Assert.Equal("SecurityGroup", entry.PrincipalType);
    }

    [Theory]
    [InlineData("User", null, "User")]
    [InlineData("User", "Guest", "Guest")]
    [InlineData("Group", null, "SecurityGroup")]
    [InlineData("App", null, "Application")]
    [InlineData("None", null, "Unknown")]
    [InlineData(null, null, "Unknown")]
    public void PowerBI_MapPrincipalType(string? pbiType, string? userType, string expected)
    {
        Assert.Equal(expected, PowerBIScanner.MapPrincipalType(pbiType, userType));
    }

    [Theory]
    [InlineData("""{"state":"Active"}""", true)]
    [InlineData("""{"state":"Orphaned"}""", true)]
    [InlineData("""{"state":"Deleted"}""", false)]
    [InlineData("""{"state":"Removing"}""", false)]
    [InlineData("""{}""", true)]
    public void PowerBI_IsActive(string ws, bool expected)
    {
        Assert.Equal(expected, PowerBIScanner.IsActive(Json(ws)));
    }

    [Fact]
    public void PowerBI_WorkspaceTargetType_PersonalOrphanedAndRegular()
    {
        var admin = Json("""{"groupUserAccessRight":"Admin"}""");
        var viewer = Json("""{"groupUserAccessRight":"Viewer"}""");

        Assert.Equal("PersonalWorkspace", PowerBIScanner.WorkspaceTargetType("PersonalGroup", new[] { viewer }));
        Assert.Equal("Workspace", PowerBIScanner.WorkspaceTargetType("Workspace", new[] { viewer, admin }));
        Assert.Equal(PowerBIScanner.OrphanedWorkspace, PowerBIScanner.WorkspaceTargetType("Workspace", new[] { viewer }));
        Assert.Equal(PowerBIScanner.OrphanedWorkspace, PowerBIScanner.WorkspaceTargetType("Workspace", Array.Empty<JsonElement>()));
    }

    // ── Power Platform ──────────────────────────────────────────

    [Fact]
    public void PowerPlatform_TenantPrincipal_MapsToEveryone()
    {
        var perm = Json("""{"properties":{"roleName":"CanView","principal":{"type":"Tenant","tenantId":"33333333-3333-3333-3333-333333333333"}}}""");

        var entry = PowerAutomateScanner.MapPermission(perm, "PowerApps/Env/App", "PowerApp", "app1", "AppPermission")!;

        Assert.Equal("33333333-3333-3333-3333-333333333333", entry.PrincipalEntraId);
        Assert.Equal(PowerAutomateScanner.EveryoneInOrganization, entry.PrincipalSysName);
        Assert.Equal("Everyone", entry.PrincipalType);
        Assert.Equal("CanView", entry.PrincipalRole);
    }

    [Fact]
    public void PowerPlatform_UserPrincipal_Maps()
    {
        var perm = Json("""{"properties":{"roleName":"Owner","principal":{"type":"User","id":"44444444-4444-4444-4444-444444444444","email":"jane@contoso.com","displayName":"Jane"}}}""");

        var entry = PowerAutomateScanner.MapPermission(perm, "p", "Flow", "f1", "FlowPermission")!;

        Assert.Equal("44444444-4444-4444-4444-444444444444", entry.PrincipalEntraId);
        Assert.Equal("jane@contoso.com", entry.PrincipalEntraUpn);
        Assert.Equal("User", entry.PrincipalType);
        Assert.Equal("Owner", entry.PrincipalRole);
    }

    [Fact]
    public void PowerPlatform_PermissionWithoutPrincipal_IsSkipped()
    {
        Assert.Null(PowerAutomateScanner.MapPermission(Json("""{"properties":{"roleName":"Owner"}}"""), "p", "Flow", "f1", "FlowPermission"));
        Assert.Null(PowerAutomateScanner.MapPermission(Json("""{"properties":{"roleName":"Owner","principal":{"type":"User"}}}"""), "p", "Flow", "f1", "FlowPermission"));
    }

    [Fact]
    public void PowerPlatform_FlowCreator_UsesObjectIdNotUpn()
    {
        var creator = Json("""{"tenantId":"t","objectId":"55555555-5555-5555-5555-555555555555","userId":"55555555-5555-5555-5555-555555555555","userType":"ActiveDirectory"}""");

        var entry = PowerAutomateScanner.MapFlowCreator(creator, "p", "f1")!;

        Assert.Equal("55555555-5555-5555-5555-555555555555", entry.PrincipalEntraId);
        Assert.Equal("", entry.PrincipalEntraUpn);
        Assert.Equal("Creator", entry.PrincipalRole);
        Assert.Equal("FlowCreator", entry.Through);
    }

    [Theory]
    [InlineData("User", "User")]
    [InlineData("Group", "SecurityGroup")]
    [InlineData("ServicePrincipal", "Application")]
    [InlineData("Tenant", "Everyone")]
    [InlineData("Something", "Unknown")]
    public void PowerPlatform_MapPrincipalType(string type, string expected)
    {
        Assert.Equal(expected, PowerAutomateScanner.MapPrincipalType(type));
    }

    [Theory]
    [InlineData("""{"properties":{"isCustomApi":true}}""", true)]
    [InlineData("""{"properties":{"isCustomApi":false}}""", false)]
    [InlineData("""{"properties":{}}""", true)]
    public void PowerPlatform_IsCustomConnector(string api, bool expected)
    {
        Assert.Equal(expected, PowerAutomateScanner.IsCustomConnector(Json(api)));
    }
}
