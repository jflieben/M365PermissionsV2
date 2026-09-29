using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using M365Permissions.Engine.Auth;
using Xunit;

namespace M365Permissions.Engine.Tests.Auth;

/// <summary>
/// Scan start must end up with the scopes each service needs, as Entra behaves on a clean tenant
/// without Azure DevOps: a token request never fails for a scope that isn't granted, Exchange tokens
/// carry linked Graph grants, explicitly requested Exchange scopes are redirected to Graph
/// (AADSTS650053), and a .default consent fails with AADSTS650052 while the app registration lists
/// Azure DevOps.
/// Uses a fake Entra token endpoint and a simulated browser that answers the loopback redirect
/// (binds localhost:1985 like the real sign-in).
/// </summary>
public sealed class ScopeTopUpTests
{
    private const string DevOpsMissing =
        "AADSTS650052: The app is trying to access a service '499b84ac-1321-427f-aa17-267ca6975798'(Azure DevOps) that your organization lacks a service principal for.";

    private const string ExchangeScopeOnGraph =
        "AADSTS650053: The application 'M365Permissions PowerShell Module' asked for scope 'Exchange.Manage' that doesn't exist on the resource '00000003-0000-0000-c000-000000000000'.";

    private static string ApiOf(string scope)
        => scope.Contains("outlook.office365.com") || scope.Contains("ps.compliance.protection.outlook.com") || scope.Contains("00000002-0000-0ff1-ce00-000000000000") ? "exchange"
         : scope.Contains("management.azure.com") ? "azure"
         : scope.Contains(".sharepoint.com") ? "sharepoint"
         : scope.Contains("graph.microsoft.com") ? "graph"
         : scope.Contains("499b84ac-1321-427f-aa17-267ca6975798") ? "azuredevops"
         : "other";

    /// <summary>Fake token endpoint. Granted scopes per API; null means nothing granted at all.</summary>
    private sealed class FakeEntra : HttpMessageHandler
    {
        public readonly Dictionary<string, string?> Granted = new()
        {
            ["exchange"] = "Group.Read.All User.Read User.Read.All",   // linked from Graph
            ["azure"] = null,
            ["sharepoint"] = "User.Read.All",                         // partial grant
            ["graph"] = "User.Read Sites.Read.All",
            ["azuredevops"] = null
        };
        public readonly Dictionary<string, string> GrantedOnConsent = new()
        {
            ["exchange"] = "Exchange.Manage Group.Read.All User.Read User.Read.All",
            ["azure"] = "user_impersonation",
            ["sharepoint"] = "AllSites.FullControl User.Read.All",
            ["azuredevops"] = "user_impersonation"
        };
        public string? LastRefreshScope;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/sites/root", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"webUrl\":\"https://contoso.sharepoint.com\"}", Encoding.UTF8, "application/json")
                };
            if (!request.RequestUri.AbsolutePath.EndsWith("/oauth2/v2.0/token", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.NotFound);

            var form = (await request.Content!.ReadAsStringAsync(ct)).Split('&')
                .Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => WebUtility.UrlDecode(p[1]));
            var api = ApiOf(form["scope"]);

            if (form["grant_type"] == "authorization_code" && form["code"] == $"consented-{api}")
                Granted[api] = GrantedOnConsent[api];
            if (form["grant_type"] == "refresh_token")
                LastRefreshScope = form["scope"];

            if (Granted.GetValueOrDefault(api) is not { } scopes)
            {
                // Nothing granted for this API: the refresh fails, naming the missing Azure DevOps.
                var error = JsonSerializer.Serialize(new { error = "invalid_client", error_description = DevOpsMissing });
                return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(error, Encoding.UTF8, "application/json") };
            }

            var token = TokenClaimsTests.Jwt(new { scp = scopes });
            var json = JsonSerializer.Serialize(new { access_token = token, expires_in = 3600, refresh_token = "rt-next" });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }

    private readonly List<string> _prompts = new();

    /// <summary>
    /// A browser that "signs in" by calling the loopback redirect. A .default request fails like it
    /// does without Azure DevOps; otherwise only a forced consent screen grants anything.
    /// </summary>
    /// <param name="registrationListsDevOps">Whether the app registration's API permissions include the missing Azure DevOps.</param>
    /// <param name="devOpsExists">Whether the tenant has the Azure DevOps service principal (the sign-in knows for sure).</param>
    private BrowserPrompt Browser(string? declineWith = null, bool registrationListsDevOps = true, bool devOpsExists = false) => new(url =>
    {
        _prompts.Add(url);
        var state = Regex.Match(url, "state=([^&]+)").Groups[1].Value;
        var scope = Uri.UnescapeDataString(Regex.Match(url, "scope=([^&]+)").Groups[1].Value);
        var isDefault = scope.Contains("/.default");
        var query =
            declineWith != null ? $"error={declineWith}&error_description=AADSTS65004%3a+User+declined"
            // A .default consent covers every configured API, so a missing one fails it.
            : isDefault && registrationListsDevOps && !devOpsExists ? $"error=invalid_client&error_description={Uri.EscapeDataString(DevOpsMissing)}"
            : ApiOf(scope) == "azuredevops" && !devOpsExists ? $"error=invalid_client&error_description={Uri.EscapeDataString(DevOpsMissing)}"
            // Explicitly requested Exchange scopes are redirected to Microsoft Graph.
            : !isDefault && ApiOf(scope) == "exchange" ? $"error=invalid_client&error_description={Uri.EscapeDataString(ExchangeScopeOnGraph)}"
            : url.Contains("prompt=consent") ? $"code=consented-{ApiOf(scope)}"
            : "code=no-consent-screen";
        _ = Task.Run(async () =>
        {
            await Task.Delay(50);
            using var browser = new HttpClient();
            await browser.GetAsync($"http://localhost:1985/?{query}&state={state}");
        });
    });

    private static DelegatedAuth NewAuth(FakeEntra entra, BrowserPrompt browser)
    {
        var cache = new TokenCache();
        cache.SetRefreshToken("rt");
        return new DelegatedAuth(cache, browser, entra);
    }

    [Fact]
    public async Task LinkedExchangeToken_GetsExchangeManage_ThroughTheConfiguredPermissions()
    {
        var entra = new FakeEntra();
        var auth = NewAuth(entra, Browser(registrationListsDevOps: false));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "exchange" });

        Assert.Empty(unavailable);
        Assert.True(auth.GetCachedTokenClaims("exchange")!.HasScope("Exchange.Manage"));
        var prompt = Uri.UnescapeDataString(Assert.Single(_prompts));
        Assert.Contains("prompt=consent", prompt);
        Assert.Contains("https://outlook.office365.com/.default", prompt);
    }

    [Fact]
    public async Task ExchangeConsent_WhenARegisteredApiIsMissing_ExplainsTheAppRegistration()
    {
        var auth = NewAuth(new FakeEntra(), Browser(registrationListsDevOps: true));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "exchange" });

        var ex = Assert.Single(unavailable);
        Assert.Equal("OtherServiceMissing", ex.AadErrorCode);
        Assert.False(ex.NotProvisioned);
        Assert.Contains("app registration", ex.Message);
        Assert.Contains("Azure DevOps", ex.Message);
        Assert.Contains("New-MgServicePrincipal -AppId 499b84ac-1321-427f-aa17-267ca6975798", ex.Message);
    }

    [Fact]
    public async Task ServiceReportedMissingByTheTokenEndpoint_ButPresent_IsConsented()
    {
        // The silent request says "no service principal" (as right after one was created); the
        // sign-in knows better and shows the consent screen.
        var auth = NewAuth(new FakeEntra(), Browser(devOpsExists: true));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "azuredevops" });

        Assert.Empty(unavailable);
        Assert.Single(_prompts);
        Assert.True(auth.GetCachedTokenClaims("azuredevops")!.HasScope("user_impersonation"));
    }

    [Fact]
    public async Task ServiceReallyMissing_IsConcludedByTheSignIn()
    {
        var auth = NewAuth(new FakeEntra(), Browser(devOpsExists: false));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "azuredevops" });

        var ex = Assert.Single(unavailable);
        Assert.True(ex.NotProvisioned);
        Assert.Contains("sign-in returned AADSTS650052", ex.Message);
        Assert.Single(_prompts);
    }

    [Fact]
    public async Task SharePointBothHosts_ShareOneConsentScreen()
    {
        var auth = NewAuth(new FakeEntra(), Browser());

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "sharepoint", "onedrive" });

        Assert.Empty(unavailable);
        Assert.Single(_prompts);
        Assert.True(auth.GetCachedTokenClaims("sharepoint")!.HasScope("AllSites.FullControl"));
        Assert.True(auth.GetCachedTokenClaims("sharepointadmin")!.HasScope("AllSites.FullControl"));
    }

    [Fact]
    public void GraphConsent_OnlyAsksForGraphScopes()
    {
        // SharePoint and Exchange scopes appear in Graph tokens (Entra mixes linked grants in), but
        // asking Graph for them fails with AADSTS650053.
        foreach (var category in new[] { "sharepoint", "onedrive", "exchange", "teams", "entra" })
        {
            Assert.DoesNotContain("AllSites.FullControl", DelegatedAuth.GetRequiredGraphScopesForCategory(category));
            Assert.DoesNotContain("Exchange.Manage", DelegatedAuth.GetRequiredGraphScopesForCategory(category));
        }
    }

    [Fact]
    public async Task PurviewAfterAFailedExchangeConsent_DoesNotPromptAgain()
    {
        var auth = NewAuth(new FakeEntra(), Browser(registrationListsDevOps: true));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "exchange", "purview" });

        Assert.Single(_prompts);
        Assert.Equal(new[] { "exchange", "compliance" }, unavailable.Select(u => u.Resource));
        Assert.All(unavailable, u => Assert.Equal("OtherServiceMissing", u.AadErrorCode));
    }

    [Fact]
    public async Task ReconsentButton_ReportsTheFailure_InsteadOfSkippingIt()
    {
        var auth = NewAuth(new FakeEntra(), Browser(registrationListsDevOps: true));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => auth.ReconsentResourcesForCategoriesAsync(new[] { "exchange" }));

        Assert.Contains("Exchange Online", ex.Message);
        Assert.Contains("Azure DevOps", ex.Message);
    }

    [Fact]
    public async Task ServiceFailingOnAnotherMissingService_IsConsented_NotSkipped()
    {
        // Azure has no grant; its silent request fails with AADSTS650052 about Azure DevOps.
        var entra = new FakeEntra();
        var auth = NewAuth(entra, Browser());

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "azure" });

        Assert.Empty(unavailable);
        Assert.True(auth.GetCachedTokenClaims("azure")!.HasScope("user_impersonation"));
        Assert.Contains("management.azure.com/user_impersonation", Uri.UnescapeDataString(Assert.Single(_prompts)));
    }

    [Fact]
    public async Task ConsentThatStillGrantsNothing_IsReportedWithTheMissingScope()
    {
        var entra = new FakeEntra();
        entra.GrantedOnConsent["exchange"] = entra.Granted["exchange"]!;
        var auth = NewAuth(entra, Browser(registrationListsDevOps: false));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "exchange" });

        var ex = Assert.Single(unavailable);
        Assert.Equal("ScopeNotGranted", ex.AadErrorCode);
        Assert.Contains("Exchange.Manage", ex.Message);
    }

    [Fact]
    public async Task DeclinedConsent_IsReported_NotSwallowed()
    {
        var auth = NewAuth(new FakeEntra(), Browser(declineWith: "access_denied"));

        var unavailable = await auth.EnsureResourceConsentForCategoriesAsync(new[] { "exchange" });

        var ex = Assert.Single(unavailable);
        Assert.Contains("did not complete", ex.Message);
        Assert.Contains("access_denied", ex.Message);
        Assert.False(ex.NotProvisioned);
    }

    [Theory]
    [InlineData("azuredevops", "AADSTS650052")]   // it is the missing service itself
    [InlineData("exchange", "OtherServiceMissing")]
    [InlineData("azure", "OtherServiceMissing")]
    public void AADSTS650052_OnlyMeansNotSetUpForTheServiceItNames(string resource, string expected)
    {
        Assert.Equal(expected, DelegatedAuth.ClassifySkipCode(resource, "AADSTS650052", DevOpsMissing));
    }
}
