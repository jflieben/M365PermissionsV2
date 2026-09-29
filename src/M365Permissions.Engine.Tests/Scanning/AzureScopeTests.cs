using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class AzureScopeTests
{
    private const string Sub = "/subscriptions/00000000-0000-0000-0000-000000000001";

    [Theory]
    [InlineData(Sub, true)]
    [InlineData(Sub + "/resourceGroups/rg1", true)]
    [InlineData(Sub + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1", true)]
    [InlineData("/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000001/resourceGroups/rg1", true)]
    [InlineData("/subscriptions/00000000-0000-0000-0000-0000000000012", false)] // other subscription sharing a prefix
    [InlineData("/providers/Microsoft.Management/managementGroups/root", false)]
    [InlineData("/", false)]
    public void IsAtOrBelow_KeepsSubscriptionAndChildScopesOnly(string scope, bool expected)
    {
        Assert.Equal(expected, AzureScanner.IsAtOrBelow(scope, Sub));
    }
}
