using M365Permissions.Engine.Graph;
using Xunit;

namespace M365Permissions.Engine.Tests.Graph;

/// <summary>
/// Guards B5: the adaptive throttle must actually reduce effective concurrency on 429s, not
/// merely lower a counter while the semaphore keeps handing out permits.
/// </summary>
public sealed class AdaptiveThrottleManagerTests
{
    [Fact]
    public void ReportThrottle_HalvesTheConcurrencyLimit()
    {
        var mgr = new AdaptiveThrottleManager(8, 16);
        mgr.ReportThrottle();
        Assert.Equal(4, mgr.CurrentConcurrency);
        mgr.ReportThrottle();
        Assert.Equal(2, mgr.CurrentConcurrency);
    }

    [Fact]
    public void ReportThrottle_NeverGoesBelowOne()
    {
        var mgr = new AdaptiveThrottleManager(2, 8);
        for (int i = 0; i < 10; i++) mgr.ReportThrottle();
        Assert.Equal(1, mgr.CurrentConcurrency);
    }

    [Fact]
    public async Task EffectiveConcurrency_DropsAfterThrottle()
    {
        var mgr = new AdaptiveThrottleManager(4, 8);
        mgr.ReportThrottle(); // limit → 2

        await mgr.WaitAsync(CancellationToken.None); // in-flight 1
        await mgr.WaitAsync(CancellationToken.None); // in-flight 2 (at limit)

        var third = mgr.WaitAsync(CancellationToken.None);
        var winner = await Task.WhenAny(third, Task.Delay(250));

        Assert.NotSame(third, winner);   // third is still blocked → effectively limited to 2
        Assert.False(third.IsCompleted);
    }

    [Fact]
    public async Task Release_FreesASlotForAWaiter()
    {
        var mgr = new AdaptiveThrottleManager(1, 4);
        await mgr.WaitAsync(CancellationToken.None); // in-flight 1 (at limit)

        var second = mgr.WaitAsync(CancellationToken.None);
        Assert.False(second.IsCompleted);

        mgr.Release(); // frees the slot
        var winner = await Task.WhenAny(second, Task.Delay(1000));
        Assert.Same(second, winner);
        Assert.True(second.IsCompletedSuccessfully);
    }
}
