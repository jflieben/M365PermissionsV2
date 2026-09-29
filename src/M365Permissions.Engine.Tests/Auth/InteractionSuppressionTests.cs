using M365Permissions.Engine.Auth;
using Xunit;

namespace M365Permissions.Engine.Tests.Auth;

/// <summary>A running scan must never open a sign-in window; consent belongs to the scan start.</summary>
public sealed class InteractionSuppressionTests
{
    private readonly List<string> _opened = new();

    // No Power Platform refresh token, so a powerapps token can only come from an interactive sign-in.
    private DelegatedAuth NewAuth() => new(new TokenCache(), new BrowserPrompt(url => _opened.Add(url)));

    [Fact]
    public async Task SuppressedFlow_FailsInsteadOfPrompting_AndCarriesIntoStartedTasks()
    {
        var auth = NewAuth();
        Task<string> scanTask;
        using (auth.SuppressInteraction())
            scanTask = Task.Run(() => auth.GetAccessTokenAsync("powerapps"));

        var ex = await Assert.ThrowsAsync<ResourcePrincipalNotFoundException>(() => scanTask);

        Assert.Equal("InteractionRequired", ex.AadErrorCode);
        Assert.False(ex.NotProvisioned);
        Assert.Empty(_opened);
    }

    [Fact]
    public async Task UnusableResource_IsRemembered_UntilTokensAreDropped()
    {
        var auth = NewAuth();
        using (auth.SuppressInteraction())
            await Assert.ThrowsAsync<ResourcePrincipalNotFoundException>(() => auth.GetAccessTokenAsync("powerapps"));

        // Outside the scan, the remembered failure is returned without attempting a sign-in.
        var again = await Assert.ThrowsAsync<ResourcePrincipalNotFoundException>(() => auth.GetAccessTokenAsync("powerapps"));
        Assert.Equal("InteractionRequired", again.AadErrorCode);
        Assert.Empty(_opened);
    }

    [Theory]
    [InlineData("AADSTS650052", true)]
    [InlineData("AADSTS500011", true)]
    [InlineData("AADSTS65001", false)]
    [InlineData("invalid_scope", false)]
    public void NotProvisioned_OnlyForMissingServicePrincipal(string code, bool expected)
    {
        Assert.Equal(expected, new ResourcePrincipalNotFoundException("azuredevops", code, "x").NotProvisioned);
    }
}
