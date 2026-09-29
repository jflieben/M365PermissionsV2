using M365Permissions.Engine.Auth;
using M365Permissions.Engine.Scanning;
using M365Permissions.Engine.Tests.Auth;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class AccountCheckTests
{
    private static TokenClaims Token(string scopes, params string[] wids)
        => TokenClaims.TryParse(TokenClaimsTests.Jwt(new { scp = scopes, wids }))!;

    private static TokenClaims TokenWithoutWids(string scopes)
        => TokenClaims.TryParse(TokenClaimsTests.Jwt(new { scp = scopes }))!;

    private const string FullGraph = "User.Read Sites.Read.All Sites.FullControl.All";

    [Fact]
    public void AccountWithoutAdminRoles_GetsRoleErrorsForSharePointAndExchange()
    {
        // The pattern behind "0 permissions found": consent is fine, the account holds no admin role.
        var claims = new Dictionary<string, TokenClaims?>
        {
            ["graph"] = Token(FullGraph + " User.Read.All", DirectoryRoles.DefaultUserRole),
            ["sharepoint"] = Token("AllSites.FullControl", DirectoryRoles.DefaultUserRole),
            ["exchange"] = Token("Exchange.Manage", DirectoryRoles.DefaultUserRole)
        };

        var notes = AccountCheck.Evaluate(new[] { "SharePoint", "Exchange" }, claims);

        var sp = Assert.Single(notes, n => n.Category == "SharePoint");
        Assert.Equal(1, sp.Level);
        Assert.Contains("Global Administrator or SharePoint Administrator", sp.Message);
        Assert.Contains("PIM", sp.Message);
        Assert.Single(notes, n => n.Category == "Exchange" && n.Level == 1);
        Assert.Contains(notes, n => n.Category == "" && n.Message.Contains("no active admin roles"));
    }

    [Fact]
    public void SharePointAdministrator_GetsNoRoleWarningForSharePoint()
    {
        var claims = new Dictionary<string, TokenClaims?>
        {
            ["graph"] = Token(FullGraph, DirectoryRoles.SharePointAdministrator),
            ["sharepoint"] = Token("AllSites.FullControl", DirectoryRoles.SharePointAdministrator)
        };

        var notes = AccountCheck.Evaluate(new[] { "SharePoint" }, claims);

        Assert.DoesNotContain(notes, n => n.Level <= 2);
        Assert.Contains(notes, n => n.Message.Contains("SharePoint Administrator") && n.Level == 3);
    }

    [Fact]
    public void TokensWithoutWids_DoNotProduceRoleWarnings()
    {
        var claims = new Dictionary<string, TokenClaims?>
        {
            ["graph"] = TokenWithoutWids(FullGraph),
            ["sharepoint"] = TokenWithoutWids("AllSites.FullControl")
        };

        Assert.Empty(AccountCheck.Evaluate(new[] { "SharePoint" }, claims));
    }

    [Fact]
    public void MissingScopes_AreListedPerCategory()
    {
        var claims = new Dictionary<string, TokenClaims?>
        {
            ["graph"] = Token("User.Read Sites.Read.All", DirectoryRoles.GlobalAdministrator),
            ["sharepoint"] = Token("AllSites.Read", DirectoryRoles.GlobalAdministrator),
            ["exchange"] = Token("EWS.AccessAsUser.All", DirectoryRoles.GlobalAdministrator)
        };

        var notes = AccountCheck.Evaluate(new[] { "SharePoint", "Exchange" }, claims);

        var sp = Assert.Single(notes, n => n.Category == "SharePoint");
        Assert.Equal(2, sp.Level);
        Assert.Contains("AllSites.FullControl", sp.Message);
        Assert.Contains("Sites.FullControl.All", sp.Message);
        Assert.Contains("Exchange.Manage", Assert.Single(notes, n => n.Category == "Exchange").Message);
    }

    [Fact]
    public void MissingScope_NamesTheTokenAndWhatItHas()
    {
        var claims = new Dictionary<string, TokenClaims?>
        {
            ["sharepoint"] = Token("User.Read.All", DirectoryRoles.GlobalAdministrator)
        };

        var note = Assert.Single(AccountCheck.Evaluate(new[] { "OneDrive" }, claims), n => n.Category == "OneDrive");

        Assert.Contains("The SharePoint token lacks AllSites.FullControl (it has: User.Read.All)", note.Message);
    }

    [Fact]
    public void UnavailableServices_AreReportedPerCategory()
    {
        var unavailable = new[]
        {
            new ResourcePrincipalNotFoundException("azuredevops", "AADSTS650052", "Azure DevOps isn't set up in this tenant: a Graph lookup found no service principal with app ID 499b84ac-1321-427f-aa17-267ca6975798."),
            new ResourcePrincipalNotFoundException("powerbi", "AADSTS65001", "Cannot acquire a token for 'powerbi'.")
        };

        var notes = AccountCheck.Evaluate(new[] { "AzureDevOps", "PowerBI" }, new Dictionary<string, TokenClaims?>(), unavailable);

        var devops = Assert.Single(notes, n => n.Category == "AzureDevOps");
        Assert.Equal(3, devops.Level);
        Assert.Contains("a Graph lookup found no service principal", devops.Message);
        var pbi = Assert.Single(notes, n => n.Category == "PowerBI");
        Assert.Equal(2, pbi.Level);
        Assert.Contains("Cannot acquire a token", pbi.Message);
    }

    [Fact]
    public void CategoriesWithoutRequirements_AndMissingTokens_AreSkipped()
    {
        var claims = new Dictionary<string, TokenClaims?> { ["graph"] = null };

        Assert.Empty(AccountCheck.Evaluate(new[] { "Azure", "SharePoint" }, claims));
    }
}
