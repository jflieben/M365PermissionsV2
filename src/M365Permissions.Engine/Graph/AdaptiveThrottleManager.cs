namespace M365Permissions.Engine.Graph;

/// <summary>
/// Manages adaptive concurrency for API calls.
/// Decreases parallelism on 429 throttle responses, slowly increases when no throttling occurs.
/// Exposes metrics for GUI display.
/// </summary>
public sealed class AdaptiveThrottleManager
{
    // Effective concurrency is enforced by comparing an in-flight counter against the current
    // limit rather than by juggling semaphore permits. The old design lowered the limit on 429
    // but always returned a permit in the caller's finally, so the effective concurrency never
    // actually dropped and only ratcheted up (B5). Here shrinking the limit genuinely reduces
    // how many callers can hold a slot at once.
    private readonly SemaphoreSlim _slotAvailable = new(0, int.MaxValue);
    private int _inFlight;
    private int _currentMaxConcurrency;
    private readonly int _absoluteMin = 1;
    private readonly int _absoluteMax;
    private readonly object _lock = new();

    private int _throttleCount;
    private long _totalRequests;
    private DateTimeOffset _lastThrottleTime = DateTimeOffset.MinValue;
    private DateTimeOffset _lastIncreaseTime = DateTimeOffset.UtcNow;
    private DateTimeOffset _firstRequestTime = DateTimeOffset.MinValue;
    private int _requestsSinceLastThrottle;
    private const int RequestsBeforeIncrease = 20;

    public int CurrentConcurrency => Volatile.Read(ref _currentMaxConcurrency);
    public int ThrottleCount => _throttleCount;
    public long TotalRequests => Interlocked.Read(ref _totalRequests);
    public DateTimeOffset? LastThrottleTime => _throttleCount > 0 ? _lastThrottleTime : null;

    public AdaptiveThrottleManager(int initialConcurrency, int maxConcurrency)
    {
        _absoluteMax = maxConcurrency;
        _currentMaxConcurrency = initialConcurrency;
    }

    /// <summary>Acquire a concurrency slot, waiting while in-flight requests are at the limit.</summary>
    public async Task WaitAsync(CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            lock (_lock)
            {
                if (_inFlight < _currentMaxConcurrency)
                {
                    _inFlight++;
                    return;
                }
            }
            // No slot within the current limit — wait to be signalled by a Release or an increase.
            await _slotAvailable.WaitAsync(ct).ConfigureAwait(false);
        }
    }

    /// <summary>Release a previously acquired slot and wake one waiter.</summary>
    public void Release()
    {
        lock (_lock)
        {
            if (_inFlight > 0) _inFlight--;
        }
        _slotAvailable.Release();
    }

    /// <summary>Record that a request was made. Call before executing each API call.</summary>
    public void RecordRequest()
    {
        Interlocked.Increment(ref _totalRequests);
        if (_firstRequestTime == DateTimeOffset.MinValue)
            _firstRequestTime = DateTimeOffset.UtcNow;
    }

    /// <summary>Report a successful request. May increase concurrency if no recent throttling.</summary>
    public void ReportSuccess()
    {
        lock (_lock)
        {
            _requestsSinceLastThrottle++;

            // Only increase if we've had enough successful requests and enough time has passed
            if (_requestsSinceLastThrottle >= RequestsBeforeIncrease
                && _currentMaxConcurrency < _absoluteMax
                && (DateTimeOffset.UtcNow - _lastIncreaseTime).TotalSeconds >= 30)
            {
                _currentMaxConcurrency = Math.Min(_currentMaxConcurrency + 1, _absoluteMax);
                _lastIncreaseTime = DateTimeOffset.UtcNow;
                _requestsSinceLastThrottle = 0;
                // Wake a waiter so the newly opened slot can be used immediately.
                _slotAvailable.Release();
            }
        }
    }

    /// <summary>Report a 429 throttle response. Immediately decreases concurrency.</summary>
    public void ReportThrottle()
    {
        lock (_lock)
        {
            _throttleCount++;
            _lastThrottleTime = DateTimeOffset.UtcNow;
            _requestsSinceLastThrottle = 0;

            // Halve concurrency (minimum 1). The in-flight gate enforces this immediately: no
            // new slot is granted until in-flight requests drain below the reduced limit.
            _currentMaxConcurrency = Math.Max(_absoluteMin, _currentMaxConcurrency / 2);
        }
    }

    /// <summary>Get current metrics for GUI display.</summary>
    public ThrottleMetrics GetMetrics()
    {
        var total = Interlocked.Read(ref _totalRequests);
        var elapsed = _firstRequestTime != DateTimeOffset.MinValue
            ? (DateTimeOffset.UtcNow - _firstRequestTime).TotalSeconds
            : 0;
        var rps = elapsed > 0 ? total / elapsed : 0;

        return new()
        {
            CurrentConcurrency = _currentMaxConcurrency,
            MaxConcurrency = _absoluteMax,
            TotalRequests = total,
            ThrottledRequests = _throttleCount,
            RequestsPerSecond = Math.Round(rps, 1),
            LastThrottleTime = _throttleCount > 0 ? _lastThrottleTime.ToString("O") : null
        };
    }
}

public sealed class ThrottleMetrics
{
    public int CurrentConcurrency { get; set; }
    public int MaxConcurrency { get; set; }
    public long TotalRequests { get; set; }
    public int ThrottledRequests { get; set; }
    public double RequestsPerSecond { get; set; }
    public string? LastThrottleTime { get; set; }
}
