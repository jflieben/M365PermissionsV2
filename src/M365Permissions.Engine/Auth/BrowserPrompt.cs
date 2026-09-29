using System.Diagnostics;

namespace M365Permissions.Engine.Auth;

/// <summary>A sign-in URL waiting for the GUI. Sequence changes with every new prompt.</summary>
public sealed record PendingPrompt(string Url, long Sequence);

/// <summary>
/// Decides where interactive sign-in URLs open. By default in the system browser. While a GUI request
/// that may need sign-in is running, the URL is handed to the GUI instead (GET /api/auth/prompt), which
/// opens it in a popup it can close again. A browser tab the OS opened can't be closed by script.
/// </summary>
public sealed class BrowserPrompt
{
    private readonly object _lock = new();
    private readonly Action<string> _openSystemBrowser;
    private readonly TimeSpan _claimTimeout;
    private readonly List<CancellationTokenSource> _operations = new();
    private string? _url;
    private long _sequence;
    private bool _claimed;

    public BrowserPrompt(Action<string>? openSystemBrowser = null, TimeSpan? claimTimeout = null)
    {
        _openSystemBrowser = openSystemBrowser ?? OpenSystemBrowser;
        _claimTimeout = claimTimeout ?? TimeSpan.FromSeconds(5);
    }

    /// <summary>True while at least one GUI operation is running.</summary>
    public bool GuiDriven { get { lock (_lock) return _operations.Count > 0; } }

    /// <summary>
    /// Route prompts to the GUI until the returned operation is disposed. Its token is cancelled by
    /// <see cref="CancelGuiOperations"/> (the GUI's Cancel button).
    /// </summary>
    public GuiOperation BeginGuiOperation()
    {
        var cts = new CancellationTokenSource();
        lock (_lock) _operations.Add(cts);
        return new GuiOperation(this, cts);
    }

    public void CancelGuiOperations()
    {
        List<CancellationTokenSource> active;
        lock (_lock) active = _operations.ToList();
        foreach (var cts in active)
        {
            try { cts.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    /// <summary>
    /// Show a sign-in URL. With a GUI operation running, wait for the GUI to pick it up and fall back to
    /// the system browser if it doesn't (GUI tab closed, old GUI build).
    /// </summary>
    public async Task ShowAsync(string url, CancellationToken ct)
    {
        bool gui;
        lock (_lock)
        {
            gui = _operations.Count > 0;
            if (gui)
            {
                _url = url;
                _sequence++;
                _claimed = false;
            }
        }

        if (!gui)
        {
            _openSystemBrowser(url);
            return;
        }

        var deadline = DateTime.UtcNow + _claimTimeout;
        while (DateTime.UtcNow < deadline)
        {
            lock (_lock)
                if (_claimed || _url != url) return;
            await Task.Delay(100, ct).ConfigureAwait(false);
        }

        lock (_lock)
            if (_url == url) _url = null;
        _openSystemBrowser(url);
    }

    /// <summary>The URL the GUI should open now, or null. Marks it as picked up.</summary>
    public PendingPrompt? Claim()
    {
        lock (_lock)
        {
            if (_url == null) return null;
            _claimed = true;
            return new PendingPrompt(_url, _sequence);
        }
    }

    /// <summary>The sign-in finished (or failed); nothing is waiting any more.</summary>
    public void Complete()
    {
        lock (_lock) _url = null;
    }

    private void End(CancellationTokenSource cts)
    {
        lock (_lock)
        {
            _operations.Remove(cts);
            if (_operations.Count == 0) _url = null;
        }
        cts.Dispose();
    }

    public static void OpenSystemBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // Fallback for Linux/macOS
            if (OperatingSystem.IsLinux())
                Process.Start("xdg-open", url);
            else if (OperatingSystem.IsMacOS())
                Process.Start("open", url);
        }
    }

    public sealed class GuiOperation : IDisposable
    {
        private readonly BrowserPrompt _owner;
        private readonly CancellationTokenSource _cts;
        private int _disposed;

        internal GuiOperation(BrowserPrompt owner, CancellationTokenSource cts)
        {
            _owner = owner;
            _cts = cts;
            Token = cts.Token;
        }

        public CancellationToken Token { get; }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _owner.End(_cts);
        }
    }
}
