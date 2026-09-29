using System.Runtime.CompilerServices;
using System.Threading.Channels;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Runs per-target scan work in parallel and streams the resulting permission entries through a
/// bounded channel so a scanner can still expose a single <see cref="IAsyncEnumerable{T}"/> (P1).
/// The consumer (the orchestrator) reads sequentially, so only the per-target producers run
/// concurrently — bounded by <paramref name="maxDegreeOfParallelism"/> and, for Graph calls, by
/// the shared AdaptiveThrottleManager underneath.
/// </summary>
public static class ParallelScan
{
    public static async IAsyncEnumerable<PermissionEntry> RunAsync<T>(
        IReadOnlyList<T> targets,
        int maxDegreeOfParallelism,
        Func<T, ChannelWriter<PermissionEntry>, CancellationToken, Task> processTarget,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var dop = Math.Max(1, maxDegreeOfParallelism);
        var channel = Channel.CreateBounded<PermissionEntry>(new BoundedChannelOptions(2000)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });

        // Cancelled when the consumer stops early, so producers don't stay blocked on a full channel.
        using var producerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var producer = Task.Run(async () =>
        {
            try
            {
                await Parallel.ForEachAsync(targets,
                    new ParallelOptions { MaxDegreeOfParallelism = dop, CancellationToken = producerCts.Token },
                    async (target, tok) => await processTarget(target, channel.Writer, tok).ConfigureAwait(false))
                    .ConfigureAwait(false);
                channel.Writer.Complete();
            }
            catch (Exception ex)
            {
                // Surface the failure to the consumer: ReadAllAsync will throw after draining.
                channel.Writer.Complete(ex);
            }
        }, producerCts.Token);

        try
        {
            await foreach (var entry in channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
                yield return entry;
        }
        finally
        {
            producerCts.Cancel();
        }

        await producer.ConfigureAwait(false);
    }
}
