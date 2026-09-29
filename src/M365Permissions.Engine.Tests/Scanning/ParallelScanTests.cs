using System.Collections.Concurrent;
using System.Threading.Channels;
using M365Permissions.Engine.Models;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

/// <summary>Guards P1's parallel-scan helper: all entries delivered, bounded concurrency, errors propagate.</summary>
public sealed class ParallelScanTests
{
    [Fact]
    public async Task RunAsync_DeliversEveryEntryFromEveryTarget()
    {
        var targets = Enumerable.Range(0, 50).ToList();

        var seen = new List<string>();
        await foreach (var e in ParallelScan.RunAsync(targets, 8, async (t, writer, ct) =>
        {
            await writer.WriteAsync(new PermissionEntry { TargetId = $"{t}-a" }, ct);
            await writer.WriteAsync(new PermissionEntry { TargetId = $"{t}-b" }, ct);
        }))
        {
            seen.Add(e.TargetId);
        }

        Assert.Equal(100, seen.Count);
        foreach (var t in targets)
        {
            Assert.Contains($"{t}-a", seen);
            Assert.Contains($"{t}-b", seen);
        }
    }

    [Fact]
    public async Task RunAsync_RespectsMaxDegreeOfParallelism()
    {
        var targets = Enumerable.Range(0, 40).ToList();
        int current = 0, peak = 0;
        var gate = new object();

        await foreach (var _ in ParallelScan.RunAsync(targets, 4, async (t, writer, ct) =>
        {
            lock (gate) { current++; peak = Math.Max(peak, current); }
            await Task.Delay(10, ct);
            lock (gate) { current--; }
            await writer.WriteAsync(new PermissionEntry { TargetId = t.ToString() }, ct);
        }))
        {
        }

        Assert.True(peak <= 4, $"peak concurrency {peak} exceeded limit 4");
    }

    [Fact]
    public async Task RunAsync_ConsumerStoppingEarly_CancelsProducers()
    {
        // More entries than the channel holds, so producers block until the consumer's exit cancels them.
        var targets = Enumerable.Range(0, 8).ToList();
        var cancelled = 0;

        await foreach (var _ in ParallelScan.RunAsync(targets, 4, async (t, writer, ct) =>
        {
            try
            {
                for (var i = 0; i < 1000; i++)
                    await writer.WriteAsync(new PermissionEntry { TargetId = $"{t}-{i}" }, ct);
            }
            catch (OperationCanceledException)
            {
                Interlocked.Increment(ref cancelled);
                throw;
            }
        }))
        {
            break;
        }

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (Volatile.Read(ref cancelled) == 0 && DateTime.UtcNow < deadline)
            await Task.Delay(20);

        Assert.True(Volatile.Read(ref cancelled) > 0, "blocked producers were not cancelled after the consumer stopped");
    }

    [Fact]
    public async Task RunAsync_PropagatesProducerException()
    {
        var targets = Enumerable.Range(0, 20).ToList();

        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await foreach (var _ in ParallelScan.RunAsync(targets, 4, async (t, writer, ct) =>
            {
                if (t == 7) throw new InvalidOperationException("boom");
                await writer.WriteAsync(new PermissionEntry { TargetId = t.ToString() }, ct);
            }))
            {
            }
        });
    }
}
