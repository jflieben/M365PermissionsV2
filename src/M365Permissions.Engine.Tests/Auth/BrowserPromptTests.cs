using M365Permissions.Engine.Auth;
using Xunit;

namespace M365Permissions.Engine.Tests.Auth;

public sealed class BrowserPromptTests
{
    private readonly List<string> _opened = new();

    private BrowserPrompt Create(int claimTimeoutMs = 2000)
        => new(url => { lock (_opened) _opened.Add(url); }, TimeSpan.FromMilliseconds(claimTimeoutMs));

    [Fact]
    public async Task WithoutGuiOperation_OpensSystemBrowser()
    {
        var prompt = Create();

        await prompt.ShowAsync("https://login/1", CancellationToken.None);

        Assert.Equal(new[] { "https://login/1" }, _opened);
        Assert.Null(prompt.Claim());
    }

    [Fact]
    public async Task GuiOperation_HandsUrlToGui_AndSkipsSystemBrowser()
    {
        var prompt = Create();
        using var op = prompt.BeginGuiOperation();

        var show = prompt.ShowAsync("https://login/2", CancellationToken.None);
        PendingPrompt? claimed = null;
        for (var i = 0; i < 50 && claimed == null; i++)
        {
            claimed = prompt.Claim();
            if (claimed == null) await Task.Delay(10);
        }
        await show;

        Assert.Equal("https://login/2", claimed?.Url);
        Assert.Empty(_opened);

        prompt.Complete();
        Assert.Null(prompt.Claim());
    }

    [Fact]
    public async Task GuiOperation_FallsBackToSystemBrowser_WhenNobodyClaims()
    {
        var prompt = Create(claimTimeoutMs: 200);
        using var op = prompt.BeginGuiOperation();

        await prompt.ShowAsync("https://login/3", CancellationToken.None);

        Assert.Equal(new[] { "https://login/3" }, _opened);
        Assert.Null(prompt.Claim());
    }

    [Fact]
    public async Task EachPrompt_GetsANewSequence()
    {
        var prompt = Create();
        using var op = prompt.BeginGuiOperation();

        var first = prompt.ShowAsync("https://login/a", CancellationToken.None);
        var a = prompt.Claim();
        await first;
        var second = prompt.ShowAsync("https://login/b", CancellationToken.None);
        var b = prompt.Claim();
        await second;

        Assert.NotNull(a);
        Assert.NotNull(b);
        Assert.NotEqual(a!.Sequence, b!.Sequence);
        Assert.Equal("https://login/b", b.Url);
    }

    [Fact]
    public void Cancel_CancelsRunningOperations_AndDisposeEndsGuiMode()
    {
        var prompt = Create();
        var op = prompt.BeginGuiOperation();
        Assert.True(prompt.GuiDriven);

        prompt.CancelGuiOperations();
        Assert.True(op.Token.IsCancellationRequested);

        op.Dispose();
        op.Dispose();
        Assert.False(prompt.GuiDriven);
    }

    [Theory]
    [InlineData("https://contoso.sharepoint.com/", "contoso")]
    [InlineData("https://contoso.sharepoint.com", "contoso")]
    [InlineData("https://fabrikam-my.sharepoint.com/personal/x", "fabrikam-my")]
    [InlineData("not a url", null)]
    [InlineData(null, null)]
    public void SharePointTenantFromUrl_TakesTheFirstHostLabel(string? url, string? expected)
    {
        Assert.Equal(expected, DelegatedAuth.SharePointTenantFromUrl(url));
    }
}
