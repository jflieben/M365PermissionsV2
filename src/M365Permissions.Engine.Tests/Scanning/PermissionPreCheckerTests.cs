using System.Net;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class PermissionPreCheckerTests
{
    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, true)]
    [InlineData(HttpStatusCode.Forbidden, true)]
    [InlineData(HttpStatusCode.OK, false)]
    public void GetExchangePermissionIssue_ReturnsIssueForUnauthorizedStatuses(HttpStatusCode statusCode, bool shouldReturnIssue)
    {
        var issue = PermissionPreChecker.GetExchangePermissionIssue(statusCode);

        if (shouldReturnIssue)
        {
            Assert.False(string.IsNullOrWhiteSpace(issue));
        }
        else
        {
            Assert.Null(issue);
        }
    }

    [Fact]
    public void GetExchangePermissionIssue_UnauthorizedMessageMentionsExchangeAdminOrConsent()
    {
        var issue = PermissionPreChecker.GetExchangePermissionIssue(HttpStatusCode.Unauthorized);

        Assert.NotNull(issue);
        Assert.Contains("Exchange Administrator", issue, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exchange.ManageAsApp", issue, StringComparison.OrdinalIgnoreCase);
    }
}