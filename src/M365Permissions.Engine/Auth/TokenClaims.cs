using System.Text;
using System.Text.Json;

namespace M365Permissions.Engine.Auth;

/// <summary>
/// Claims read from an access token payload. Used for diagnostics only: the signature is not validated.
/// </summary>
public sealed class TokenClaims
{
    private static readonly IReadOnlySet<string> Empty = new HashSet<string>();

    /// <summary>Active directory role template IDs (wids). Null when the token has no wids claim.</summary>
    public IReadOnlySet<string>? RoleTemplateIds { get; private init; }

    /// <summary>Delegated scopes (scp).</summary>
    public IReadOnlySet<string> Scopes { get; private init; } = Empty;

    public string? TenantId { get; private init; }
    public string? Audience { get; private init; }

    public bool HasScope(string scope) => Scopes.Contains(scope);

    public bool HasAnyRole(IEnumerable<string> roleTemplateIds)
        => RoleTemplateIds != null && roleTemplateIds.Any(RoleTemplateIds.Contains);

    /// <summary>Parse a JWT access token. Returns null for anything that is not a readable JWT.</summary>
    public static TokenClaims? TryParse(string? jwt)
    {
        if (string.IsNullOrEmpty(jwt)) return null;
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;

        try
        {
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
            var root = doc.RootElement;

            HashSet<string>? wids = null;
            if (root.TryGetProperty("wids", out var w) && w.ValueKind == JsonValueKind.Array)
            {
                wids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var id in w.EnumerateArray())
                    if (id.ValueKind == JsonValueKind.String && id.GetString() is { Length: > 0 } s)
                        wids.Add(s);
            }

            var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("scp", out var scp) && scp.ValueKind == JsonValueKind.String)
                foreach (var s in (scp.GetString() ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    scopes.Add(s);

            return new TokenClaims
            {
                RoleTemplateIds = wids,
                Scopes = scopes,
                TenantId = root.TryGetProperty("tid", out var tid) ? tid.GetString() : null,
                Audience = root.TryGetProperty("aud", out var aud) && aud.ValueKind == JsonValueKind.String ? aud.GetString() : null
            };
        }
        catch
        {
            return null;
        }
    }
}
