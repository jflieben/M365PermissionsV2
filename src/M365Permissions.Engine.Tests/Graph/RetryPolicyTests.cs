using System.Net;
using System.Net.Http.Headers;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Graph;

public sealed class RetryPolicyTests
{
    [Fact]
    public void RetryAfter_HonoursSecondsAndDates()
    {
        var now = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(TimeSpan.FromSeconds(7), RetryPolicy.RetryAfter(new RetryConditionHeaderValue(TimeSpan.FromSeconds(7)), now));
        Assert.Equal(TimeSpan.FromSeconds(30), RetryPolicy.RetryAfter(new RetryConditionHeaderValue(now.AddSeconds(30)), now));
        Assert.Equal(TimeSpan.Zero, RetryPolicy.RetryAfter(new RetryConditionHeaderValue(now.AddSeconds(-30)), now));
        Assert.Null(RetryPolicy.RetryAfter(null, now));
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(1, 10)]
    [InlineData(3, 40)]
    [InlineData(4, 60)]
    [InlineData(10, 60)]
    public void ThrottleBackoff_IsCappedAtAMinute(int attempt, double baseSeconds)
    {
        var delay = RetryPolicy.ThrottleBackoff(attempt).TotalSeconds;
        Assert.InRange(delay, baseSeconds, baseSeconds + 1);
    }

    [Fact]
    public void IsTimeout_DistinguishesHttpClientTimeoutFromCancellation()
    {
        using var cts = new CancellationTokenSource();
        Assert.True(RetryPolicy.IsTimeout(new TaskCanceledException(), cts.Token));
        cts.Cancel();
        Assert.False(RetryPolicy.IsTimeout(new TaskCanceledException(), cts.Token));
        Assert.False(RetryPolicy.IsTimeout(new InvalidOperationException(), CancellationToken.None));
    }

    [Fact]
    public void ExchangeRetry_CoversThrottlingTimeoutsAndTransientCodes()
    {
        var ct = CancellationToken.None;
        Assert.True(ExchangeRestClient.IsRetryable(new HttpRequestException("x", null, (HttpStatusCode)429), ct));
        Assert.True(ExchangeRestClient.IsRetryable(new HttpRequestException("x", null, HttpStatusCode.ServiceUnavailable), ct));
        Assert.True(ExchangeRestClient.IsRetryable(new HttpRequestException("EXO 400 [Get-Mailbox]: ServerBusyException", null, HttpStatusCode.BadRequest), ct));
        Assert.True(ExchangeRestClient.IsRetryable(new TaskCanceledException(), ct));
        Assert.False(ExchangeRestClient.IsRetryable(new HttpRequestException("x", null, HttpStatusCode.Forbidden), ct));
        Assert.False(ExchangeRestClient.IsRetryable(new HttpRequestException("x", null, HttpStatusCode.BadRequest), ct));
    }

    [Theory]
    [InlineData("{\"value\":[]}", true)]
    [InlineData("{\"value\":[{\"subscriptionId\":\"1\"}]}", false)]
    [InlineData("not json", false)]
    public void AzurePreCheck_DetectsNoVisibleSubscriptions(string body, bool expected)
    {
        Assert.Equal(expected, PermissionPreChecker.IsEmptyValueList(body));
    }
}
