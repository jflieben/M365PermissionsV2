using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Security.Cryptography;

namespace M365Permissions.Engine.Auth;

/// <summary>
/// OAuth2 Authorization Code flow with PKCE for delegated authentication.
/// Opens system browser → user signs in → local loopback HTTP listener captures code → exchanges for tokens.
/// </summary>
public sealed class DelegatedAuth
{
    // App registration used by M365Permissions
    private const string ClientId = "0ee7aa45-310d-4b82-9cb5-11cc01ad38e4";
    // Microsoft's well-known PowerApps/Flow client ID (pre-consented for PP APIs)
    private const string PowerPlatformClientId = "689e5960-2e49-4505-98d8-369236220fc6";
    private const string Authority = "https://login.microsoftonline.com/common";

    // Minimal sign-in scope: identifies the user and obtains a refresh token. Anything more
    // is requested incrementally per scan category so tenants only see prompts for what they use.
    private const string MinimalGraphScope = "https://graph.microsoft.com/User.Read offline_access openid profile";

    /// <summary>
    /// Map scan category → the Microsoft Graph delegated permissions it needs.
    /// Resources outside Graph (Exchange, PowerBI, PowerApps, Azure, DevOps, Compliance) keep their
    /// own .default scope because those are single-resource SPNs and incremental consent on Graph
    /// alone wouldn't help. Graph however is the one resource where .default fails for tenants that
    /// have never tenant-consented our app, so we use explicit v2 scopes.
    /// </summary>
    private static readonly Dictionary<string, string[]> GraphScopesByCategory = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sharepoint"] = new[] { "Sites.Read.All" },
        ["onedrive"]   = new[] { "User.Read.All", "Sites.Read.All", "Files.Read.All" },
        ["entra"]      = new[] { "Directory.Read.All", "Application.Read.All", "Group.Read.All", "GroupMember.Read.All", "RoleManagement.Read.Directory" },
        ["teams"]      = new[] { "Team.ReadBasic.All", "TeamMember.Read.All", "Channel.ReadBasic.All", "ChannelMember.Read.All" },
        ["exchange"]   = new[] { "User.Read.All" },
        ["powerbi"]    = new[] { "User.Read.All" },
        ["powerautomate"] = new[] { "User.Read.All" },
        ["azure"]      = new[] { "Directory.Read.All" },
        ["azuredevops"] = Array.Empty<string>(),
        ["purview"]    = new[] { "User.Read.All" }
    };

    /// <summary>
    /// Map scan category -> non-Graph resource keys that require their own token consent flow.
    /// These resources don't participate in Graph incremental consent and must be acquired separately.
    /// </summary>
    private static readonly Dictionary<string, string[]> ResourceKeysByCategory = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sharepoint"] = new[] { "sharepoint", "sharepointadmin" },
        ["onedrive"] = new[] { "sharepoint" },
        ["exchange"] = new[] { "exchange" },
        ["powerbi"] = new[] { "powerbi" },
        ["powerautomate"] = new[] { "powerapps" },
        ["azure"] = new[] { "azure" },
        ["azuredevops"] = new[] { "azuredevops" },
        ["purview"] = new[] { "compliance" }
    };

    /// <summary>Return the list of Graph delegated scopes a given scan category needs.</summary>
    public static IReadOnlyList<string> GetRequiredGraphScopesForCategory(string category)
        => GraphScopesByCategory.TryGetValue(category, out var s) ? s : Array.Empty<string>();

    /// <summary>Return non-Graph resource keys a scan category needs consent for.</summary>
    public static IReadOnlyList<string> GetRequiredResourceKeysForCategory(string category)
        => ResourceKeysByCategory.TryGetValue(category, out var r) ? r : Array.Empty<string>();

    private readonly TokenCache _tokenCache;
    private string? _tenantId;
    private string? _tenantDomain;
    private string? _sharePointTenant;
    private string? _userPrincipalName;

    public bool IsConnected => _tokenCache.HasValidToken("graph") || _tokenCache.GetRefreshToken() != null;
    public string? TenantId => _tenantId;
    public string? TenantDomain => _tenantDomain;
    public string? UserPrincipalName => _userPrincipalName;
    public DateTimeOffset? RefreshTokenExpiry => _tokenCache.RefreshTokenExpiry;

    public DelegatedAuth(TokenCache tokenCache)
    {
        _tokenCache = tokenCache;
    }

    /// <summary>
    /// Perform interactive delegated sign-in.
    /// Opens system browser, waits for OAuth callback on loopback port.
    /// </summary>
    public async Task AuthenticateAsync(CancellationToken ct = default)
    {
        // Generate PKCE challenge
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state = GenerateState();

        // Loopback listener on the fixed redirect port (1985 — the only URI on the Entra app).
        var redirectUri = "http://localhost:1985/";
        var listener = StartLoopbackListener(redirectUri);

        try
        {
            // Build authorization URL — initial sign-in only asks for User.Read; per-scan consents come later.
            var authUrl = $"{Authority}/oauth2/v2.0/authorize" +
                $"?client_id={Uri.EscapeDataString(ClientId)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_mode=query" +
                $"&scope={Uri.EscapeDataString(MinimalGraphScope)}" +
                $"&state={Uri.EscapeDataString(state)}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256";

            OpenBrowser(authUrl);

            var code = await WaitForOAuthCallbackAsync(listener, state,
                "<html><body><h2>Authentication successful!</h2><p>You can close this window.</p></body></html>",
                "Authentication failed", ct);

            // Exchange code for tokens
            await ExchangeCodeForTokens(code, redirectUri, codeVerifier, ct);

            // Discover tenant info
            await DiscoverTenantInfoAsync(ct);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    public void SignOut()
    {
        _tokenCache.Clear();
        _tenantId = null;
        _tenantDomain = null;
        _userPrincipalName = null;
    }

    /// <summary>
    /// Trigger an interactive admin consent flow for the M365Permissions app registration.
    /// Opens browser with prompt=consent to let an admin re-grant all configured API permissions.
    /// After consent, tokens are refreshed so new permissions take effect immediately.
    /// </summary>
    public async Task ReconsentAsync(CancellationToken ct = default)
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state = GenerateState();

        var redirectUri = "http://localhost:1985/";
        var listener = StartLoopbackListener(redirectUri);

        try
        {
            var authUrl = $"{Authority}/oauth2/v2.0/authorize" +
                $"?client_id={Uri.EscapeDataString(ClientId)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_mode=query" +
                $"&scope={Uri.EscapeDataString(MinimalGraphScope)}" +
                $"&prompt=consent" +
                $"&state={Uri.EscapeDataString(state)}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256";

            OpenBrowser(authUrl);

            var code = await WaitForOAuthCallbackAsync(listener, state,
                "<html><body><h2>Consent granted!</h2><p>Permissions have been updated. You can close this window.</p></body></html>",
                "Consent failed", ct);

            // Exchange code for fresh tokens with the newly consented permissions
            await ExchangeCodeForTokens(code, redirectUri, codeVerifier, ct);

            // Refresh tenant info in case this is a different consent context
            await DiscoverTenantInfoAsync(ct);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    /// <summary>
    /// Ensure the persisted refresh token has consent for all Graph delegated scopes the given
    /// scan categories require. If anything is missing, opens an incremental consent flow in the
    /// browser that asks for the union of (already consented + new) scopes. Returns immediately
    /// if everything is already consented. AAD only prompts for the new scopes.
    /// </summary>
    public async Task EnsureGraphConsentForCategoriesAsync(IEnumerable<string> categories, CancellationToken ct = default)
    {
        var needed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cat in categories)
            foreach (var s in GetRequiredGraphScopesForCategory(cat))
                needed.Add(s);

        if (needed.Count == 0) return;

        var consented = _tokenCache.GetConsentedGraphScopes();
        var missing = needed.Where(s => !consented.Contains(s)).ToList();
        if (missing.Count == 0) return;

        // Build a scope string with the union: previously-consented + missing + always-needed.
        var union = new HashSet<string>(consented, StringComparer.OrdinalIgnoreCase);
        union.Add("User.Read");
        foreach (var s in missing) union.Add(s);

        var fullyQualified = union.Select(s => s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? s
            : $"https://graph.microsoft.com/{s}");
        var scope = string.Join(' ', fullyQualified) + " offline_access openid profile";

        // Run interactive PKCE \u2014 AAD will only show prompts for scopes not yet consented.
        await AcquireTokenInteractiveAsync(ClientId, "graph", scope, ct, isPP: false);

        // Mark all of those as consented going forward.
        _tokenCache.AddConsentedGraphScopes(union);
    }

    /// <summary>
    /// Ensure all selected scan categories can acquire tokens for their non-Graph resources.
    /// If a refresh-token grant fails due missing consent, trigger an interactive consent prompt
    /// for that specific resource so the user can grant it before scan/pre-check runs.
    /// </summary>
    public async Task EnsureResourceConsentForCategoriesAsync(IEnumerable<string> categories, CancellationToken ct = default)
    {
        var resources = GetOrderedResourceKeysForCategories(categories);
        foreach (var resource in resources)
            await EnsureResourceTokenAsync(resource, ct);
    }

    /// <summary>
    /// Force an interactive consent flow per resource required by the selected categories.
    /// This is used by the explicit "Re-consent" action where the user expects resource-specific
    /// consent screens (for example Exchange-only).
    /// </summary>
    public async Task ReconsentResourcesForCategoriesAsync(IEnumerable<string> categories, CancellationToken ct = default)
    {
        var resources = GetOrderedResourceKeysForCategories(categories);
        var failures = new List<string>();

        foreach (var resource in resources)
        {
            try
            {
                await ReconsentResourceAsync(resource, ct);
            }
            catch (Exception ex)
            {
                failures.Add($"{resource}: {ex.Message}");
            }
        }

        if (failures.Count > 0)
        {
            throw new InvalidOperationException(
                "One or more selected resource consents failed: " + string.Join(" | ", failures));
        }
    }

    private static List<string> GetOrderedResourceKeysForCategories(IEnumerable<string> categories)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();

        foreach (var category in categories)
        {
            foreach (var resource in GetRequiredResourceKeysForCategory(category))
            {
                if (seen.Add(resource))
                    ordered.Add(resource);
            }
        }

        return ordered;
    }

    /// <summary>
    /// Try to restore a previous session using a persisted refresh token.
    /// Returns true if session was restored, false if interactive login is needed.
    /// </summary>
    public async Task<bool> TryRestoreSessionAsync(CancellationToken ct = default)
    {
        var refreshToken = _tokenCache.GetRefreshToken();
        if (string.IsNullOrEmpty(refreshToken))
            return false;

        try
        {
            await RefreshTokensAsync(refreshToken, ct);
            await DiscoverTenantInfoAsync(ct);
            return true;
        }
        catch
        {
            // Refresh token expired or revoked — need interactive login
            return false;
        }
    }

    /// <summary>Get a valid access token for the given resource. Auto-refreshes if expired.</summary>
    public async Task<string> GetAccessTokenAsync(string resource = "graph", CancellationToken ct = default)
    {
        var token = _tokenCache.Get(resource);
        if (token != null) return token;

        await EnsureResourceTokenAsync(resource, ct);
        return _tokenCache.Get(resource)
            ?? throw new InvalidOperationException($"Token acquisition for '{resource}' failed.");
    }

    private async Task EnsureResourceTokenAsync(string resource, CancellationToken ct)
    {
        if (_tokenCache.Get(resource) != null)
            return;

        // Power Platform resources use the well-known PP client ID (different from our app)
        if (IsPowerPlatformResource(resource))
        {
            await AcquirePowerPlatformTokenAsync(resource, ct);
            return;
        }

        var refreshToken = _tokenCache.GetRefreshToken();
        if (string.IsNullOrEmpty(refreshToken))
            throw new InvalidOperationException("Not authenticated. Call ConnectAsync first.");

        var scope = GetScopeForResource(resource);

        try
        {
            await AcquireTokenForResourceAsync(refreshToken, ClientId, resource, scope, ct);
            return;
        }
        catch (ResourcePrincipalNotFoundException ex) when (ShouldTryInteractiveConsentByCode(ex.AadErrorCode))
        {
            // Consent-like tenant errors should trigger an interactive prompt, not a silent skip.
        }
        catch (InvalidOperationException ex) when (ShouldTryInteractiveConsentByMessage(ex.Message))
        {
            // Token endpoint returned consent-related errors in payload. Fall through to interactive.
        }

        await AcquireTokenInteractiveAsync(ClientId, resource, scope, ct, isPP: false);
    }

    private async Task ReconsentResourceAsync(string resource, CancellationToken ct)
    {
        var scope = GetScopeForResource(resource);
        var isPowerPlatform = IsPowerPlatformResource(resource);
        var clientId = isPowerPlatform ? PowerPlatformClientId : ClientId;

        // Force a consent screen for this resource so users can explicitly grant/re-grant access.
        await AcquireTokenInteractiveAsync(clientId, resource, scope, ct, isPP: isPowerPlatform, forceConsentPrompt: true);
    }

    private static bool ShouldTryInteractiveConsentByCode(string? aadErrorCodeOrOauth)
    {
        if (string.IsNullOrWhiteSpace(aadErrorCodeOrOauth))
            return false;

        return aadErrorCodeOrOauth.Equals("AADSTS65001", StringComparison.OrdinalIgnoreCase)
            || aadErrorCodeOrOauth.Equals("AADSTS70011", StringComparison.OrdinalIgnoreCase)
            || aadErrorCodeOrOauth.Equals("invalid_scope", StringComparison.OrdinalIgnoreCase)
            || aadErrorCodeOrOauth.Equals("unauthorized_client", StringComparison.OrdinalIgnoreCase)
            || aadErrorCodeOrOauth.Equals("invalid_client", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldTryInteractiveConsentByMessage(string message)
    {
        return message.Contains("AADSTS65001", StringComparison.OrdinalIgnoreCase)
            || message.Contains("AADSTS70011", StringComparison.OrdinalIgnoreCase)
            || message.Contains("\"error\":\"invalid_scope\"", StringComparison.OrdinalIgnoreCase)
            || message.Contains("\"error\":\"unauthorized_client\"", StringComparison.OrdinalIgnoreCase)
            || message.Contains("\"error\":\"invalid_client\"", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPowerPlatformResource(string resource)
        => resource is "powerapps" or "flow";

    /// <summary>
    /// Acquire a Power Platform token using Microsoft's well-known PowerApps client ID.
    /// Uses a separate refresh token since it's a different client application.
    /// On first use, triggers an interactive browser login.
    /// </summary>
    private async Task<string> AcquirePowerPlatformTokenAsync(string resource, CancellationToken ct)
    {
        var scope = GetScopeForResource(resource);
        var ppRefreshToken = _tokenCache.GetPPRefreshToken();

        if (!string.IsNullOrEmpty(ppRefreshToken))
        {
            try
            {
                await AcquireTokenForResourceAsync(ppRefreshToken, PowerPlatformClientId, resource, scope, ct, isPP: true);
                var token = _tokenCache.Get(resource);
                if (token != null) return token;
            }
            catch (ResourcePrincipalNotFoundException)
            {
                // SPN missing — surface immediately so caller can skip this scan
                throw;
            }
            catch
            {
                // Refresh token expired or invalid — fall through to interactive
            }
        }

        // Interactive PKCE login with the PP client ID
        await AcquireTokenInteractiveAsync(PowerPlatformClientId, resource, scope, ct, isPP: true);
        return _tokenCache.Get(resource)
            ?? throw new InvalidOperationException($"Power Platform token acquisition for '{resource}' failed.");
    }

    /// <summary>Map resource key to the OAuth2 scope string needed for that API.</summary>
    private string GetScopeForResource(string resource) => resource switch
    {
        // Graph uses explicit consented v2 scopes (never .default) so missing tenant-consent on extra perms
        // doesn't break login or token refresh in tenants that have never granted them.
        "graph" => BuildGraphScopeString(),
        "sharepoint" => $"https://{GetSharePointHost()}/.default offline_access",
        "exchange" => "https://outlook.office365.com/.default offline_access",
        "compliance" => "https://ps.compliance.protection.outlook.com/.default offline_access",
        "powerbi" => "https://analysis.windows.net/powerbi/api/.default offline_access",
        // BAP + PowerApps APIs use service.powerapps.com audience
        "powerapps" => "https://service.powerapps.com/.default offline_access",
        // Flow API uses service.flow.microsoft.com audience
        "flow" => "https://service.flow.microsoft.com/.default offline_access",
        "azure" => "https://management.azure.com/.default offline_access",
        "azuredevops" => "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation offline_access",
        "sharepointadmin" => $"https://{GetSharePointAdminHost()}/.default offline_access",
        _ => throw new ArgumentException($"Unknown resource: {resource}")
    };

    /// <summary>
    /// Build the Graph scope string from the set of scopes the user has already consented to.
    /// Always includes User.Read + offline_access + openid + profile so refresh keeps working.
    /// </summary>
    private string BuildGraphScopeString()
    {
        var scopes = _tokenCache.GetConsentedGraphScopes();
        scopes.Add("User.Read");
        var fully = scopes.Select(s => s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? s
            : $"https://graph.microsoft.com/{s}");
        return string.Join(' ', fully) + " offline_access openid profile";
    }

    /// <summary>Derive the tenant's SharePoint hostname (e.g. contoso.sharepoint.com).</summary>
    private string GetSharePointHost()
    {
        if (!string.IsNullOrEmpty(_sharePointTenant))
            return $"{_sharePointTenant}.sharepoint.com";
        throw new InvalidOperationException("SharePoint tenant not available. Ensure you're connected first.");
    }

    /// <summary>Derive the tenant's SharePoint admin hostname (e.g. contoso-admin.sharepoint.com).</summary>
    private string GetSharePointAdminHost()
    {
        if (!string.IsNullOrEmpty(_sharePointTenant))
            return $"{_sharePointTenant}-admin.sharepoint.com";
        throw new InvalidOperationException("SharePoint tenant not available. Ensure you're connected first.");
    }

    /// <summary>Get the SharePoint admin site URL (e.g. https://contoso-admin.sharepoint.com).</summary>
    public string GetSharePointAdminUrl() => $"https://{GetSharePointAdminHost()}";

    /// <summary>Acquire an access token for a specific resource using a refresh token.</summary>
    private async Task AcquireTokenForResourceAsync(string refreshToken, string clientId, string cacheKey, string scope, CancellationToken ct, bool isPP = false)
    {
        using var http = new HttpClient();
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["scope"] = scope
        });

        var response = await http.PostAsync($"{Authority}/oauth2/v2.0/token", body, ct);
        var json = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            // If the PRIMARY refresh token is expired/revoked, the whole session is dead. Clear it
            // so IsConnected (and the GUI badge) reflect reality instead of staying "connected"
            // because a stale .rt file still exists on disk.
            if (!isPP && cacheKey == "graph" && IsInvalidGrant(json))
            {
                SignOut();
                throw new InvalidOperationException(
                    "Your saved sign-in has expired or was revoked. Please connect again.");
            }
            ThrowIfResourcePrincipalMissing(cacheKey, json);
            throw new InvalidOperationException($"Token acquisition for '{cacheKey}' failed: {json}");
        }

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        _tokenCache.Set(cacheKey,
            root.GetProperty("access_token").GetString()!,
            TimeSpan.FromSeconds(root.GetProperty("expires_in").GetInt32() - 300));

        if (root.TryGetProperty("refresh_token", out var rt))
        {
            long? rtExpiry = root.TryGetProperty("refresh_token_expires_in", out var rtExp) ? rtExp.GetInt64() : null;
            if (isPP)
                _tokenCache.SetPPRefreshToken(rt.GetString()!, rtExpiry);
            else
                _tokenCache.SetRefreshToken(rt.GetString()!, rtExpiry);
        }
    }

    /// <summary>
    /// Detect a token-endpoint error that means the refresh token itself is no longer usable
    /// (expired, revoked, password change, MFA/session invalidation) — as opposed to a per-resource
    /// consent/provisioning problem. Used to clear a dead primary session.
    /// </summary>
    private static bool IsInvalidGrant(string errorJson)
    {
        // AADSTS700082: RT expired due to inactivity. AADSTS70008: expired/revoked.
        // AADSTS50173: session revoked (password change). AADSTS50078/50076: MFA required again.
        // AADSTS700084: RT was issued to a different session. oauth error: "invalid_grant".
        string[] codes = { "invalid_grant", "AADSTS700082", "AADSTS70008", "AADSTS50173", "AADSTS50078", "AADSTS700084" };
        foreach (var c in codes)
            if (errorJson.Contains(c, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    /// <summary>
    /// If the AAD error response indicates the resource cannot be acquired in the user's tenant
    /// (e.g. PowerBI / Azure DevOps / ASM SPN missing, resource never consented, user can't grant
    /// consent), throw a typed <see cref="ResourcePrincipalNotFoundException"/> so callers can skip
    /// that resource gracefully. Otherwise return without throwing.
    /// </summary>
    private static void ThrowIfResourcePrincipalMissing(string resource, string errorJson)
    {
        // AAD error codes that mean "this resource is not usable in this tenant for this user
        // and no amount of retrying will fix it programmatically":
        //  - AADSTS500011: The resource principal named X was not found in the tenant
        //  - AADSTS650052: The app needs access to a service the org has not subscribed to
        //  - AADSTS650057: Invalid resource
        //  - AADSTS65001:  No consent for the requested permissions
        //  - AADSTS70011:  Invalid scope (often: scope not consented for this app/tenant)
        //  - AADSTS700016: App not found in tenant (shouldn't happen for resource tokens, but safe)
        // OAuth2 error names that wrap any of the above on the token endpoint:
        //  - "invalid_client", "invalid_scope", "invalid_request", "unauthorized_client"
        var skippableAadCodes = new[]
        {
            "AADSTS500011", "AADSTS650052", "AADSTS650057",
            "AADSTS65001",  "AADSTS70011",  "AADSTS700016"
        };

        string? oauthError = null;
        string? aadCode = null;
        string description = string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(errorJson);
            if (doc.RootElement.TryGetProperty("error", out var errElem) && errElem.ValueKind == JsonValueKind.String)
                oauthError = errElem.GetString();
            if (doc.RootElement.TryGetProperty("error_description", out var descElem))
                description = descElem.GetString() ?? string.Empty;
        }
        catch
        {
            // Not JSON — fall through; nothing to detect.
            return;
        }

        foreach (var c in skippableAadCodes)
        {
            if (description.Contains(c, StringComparison.Ordinal))
            {
                aadCode = c;
                break;
            }
        }

        if (aadCode != null)
        {
            throw new ResourcePrincipalNotFoundException(resource, aadCode,
                $"Cannot acquire a token for '{resource}' in this tenant ({aadCode}). " +
                "This typically means the service is not licensed, has never been used, or admin consent " +
                "has not been granted for it. Skipping this scan.");
        }

        // OAuth2 'invalid_client' or 'invalid_scope' on a refresh-token grant for a sub-resource is
        // almost always a tenant-side issue with that specific resource (not our app — we just signed in
        // successfully on Graph). Treat it as skippable so other scans still run.
        if (oauthError is "invalid_client" or "invalid_scope" or "unauthorized_client")
        {
            throw new ResourcePrincipalNotFoundException(resource, oauthError,
                $"Cannot acquire a token for '{resource}' in this tenant (oauth error '{oauthError}'). " +
                $"Details: {description}. Skipping this scan.");
        }
    }

    /// <summary>
    /// Interactive PKCE browser login for a specific client + scope.
    /// Used for incremental consent and Power Platform client flows.
    /// </summary>
    private async Task AcquireTokenInteractiveAsync(string clientId, string cacheKey, string scope, CancellationToken ct, bool isPP = false, bool forceConsentPrompt = false)
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state = GenerateState();

        var redirectUri = "http://localhost:1985/";
        var listener = StartLoopbackListener(redirectUri);

        try
        {
            var authUrl = $"{Authority}/oauth2/v2.0/authorize" +
                $"?client_id={Uri.EscapeDataString(clientId)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_mode=query" +
                $"&scope={Uri.EscapeDataString(scope)}" +
                (forceConsentPrompt ? "&prompt=consent" : "") +
                $"&state={Uri.EscapeDataString(state)}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256";

            OpenBrowser(authUrl);

            var code = await WaitForOAuthCallbackAsync(listener, state,
                "<html><body><h2>Authentication successful!</h2><p>You can close this window.</p></body></html>",
                $"Interactive auth failed for '{cacheKey}'", ct);

            using var http = new HttpClient();
            var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier,
                ["scope"] = scope
            });

            var response = await http.PostAsync($"{Authority}/oauth2/v2.0/token", body, ct);
            var json = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
            {
                ThrowIfResourcePrincipalMissing(cacheKey, json);
                throw new InvalidOperationException($"Token exchange for '{cacheKey}' failed: {json}");
            }

            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            _tokenCache.Set(cacheKey,
                root.GetProperty("access_token").GetString()!,
                TimeSpan.FromSeconds(root.GetProperty("expires_in").GetInt32() - 300));

            if (root.TryGetProperty("refresh_token", out var rt))
            {
                long? rtExpiry = root.TryGetProperty("refresh_token_expires_in", out var rtExp) ? rtExp.GetInt64() : null;
                if (isPP)
                    _tokenCache.SetPPRefreshToken(rt.GetString()!, rtExpiry);
                else
                    _tokenCache.SetRefreshToken(rt.GetString()!, rtExpiry);
            }
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    private async Task ExchangeCodeForTokens(string code, string redirectUri, string codeVerifier, CancellationToken ct)
    {
        using var http = new HttpClient();
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = codeVerifier,
            ["scope"] = MinimalGraphScope
        });

        var response = await http.PostAsync($"{Authority}/oauth2/v2.0/token", body, ct);
        var json = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Token exchange failed: {json}");

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        _tokenCache.Set("graph",
            root.GetProperty("access_token").GetString()!,
            TimeSpan.FromSeconds(root.GetProperty("expires_in").GetInt32() - 300));

        if (root.TryGetProperty("refresh_token", out var rt))
        {
            long? rtExpiry = root.TryGetProperty("refresh_token_expires_in", out var rtExp) ? rtExp.GetInt64() : null;
            _tokenCache.SetRefreshToken(rt.GetString()!, rtExpiry);
        }

        // Sign-in succeeded, so User.Read is consented. Track it so future Graph token requests
        // include it explicitly (instead of relying on .default).
        _tokenCache.AddConsentedGraphScopes(new[] { "User.Read" });
    }

    private async Task RefreshTokensAsync(string refreshToken, CancellationToken ct)
    {
        await AcquireTokenForResourceAsync(refreshToken, ClientId, "graph", BuildGraphScopeString(), ct, false);
    }

    private async Task DiscoverTenantInfoAsync(CancellationToken ct)
    {
        var token = _tokenCache.Get("graph")
            ?? throw new InvalidOperationException("No access token available");

        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Get current user
        var userResponse = await http.GetStringAsync("https://graph.microsoft.com/v1.0/me?$select=userPrincipalName,mail", ct);
        var userDoc = JsonDocument.Parse(userResponse);
        _userPrincipalName = userDoc.RootElement.GetProperty("userPrincipalName").GetString();

        // Get organization info
        var orgResponse = await http.GetStringAsync("https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains", ct);
        var orgDoc = JsonDocument.Parse(orgResponse);
        var orgs = orgDoc.RootElement.GetProperty("value");
        if (orgs.GetArrayLength() > 0)
        {
            var org = orgs[0];
            _tenantId = org.GetProperty("id").GetString();

            // Find the default verified domain
            foreach (var domain in org.GetProperty("verifiedDomains").EnumerateArray())
            {
                if (domain.TryGetProperty("isDefault", out var isDefault) && isDefault.GetBoolean())
                {
                    _tenantDomain = domain.GetProperty("name").GetString();
                    break;
                }
            }
        }

        // Discover the actual SharePoint tenant prefix from the root site webUrl
        // (the verified domain prefix may differ from the SharePoint tenant name)
        var rootSiteResponse = await http.GetStringAsync("https://graph.microsoft.com/v1.0/sites/root", ct);
        var rootSiteDoc = JsonDocument.Parse(rootSiteResponse);
        if (rootSiteDoc.RootElement.TryGetProperty("webUrl", out var webUrlProp))
        {
            var webUrl = webUrlProp.GetString() ?? "";
            _sharePointTenant = webUrl.Replace("https://", "", StringComparison.OrdinalIgnoreCase).Split('.')[0];
        }
    }

    /// <summary>Random opaque value bound to one authorize request; verified on the callback.</summary>
    private static string GenerateState() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// Wait for the OAuth redirect on the loopback listener and return the authorization code.
    /// The listener stays open across stray requests (favicon fetches, other local tools polling
    /// the same port, duplicate/stale redirects): anything without our exact <c>state</c> is
    /// answered and ignored rather than aborting the flow. Only a request carrying the matching
    /// state is acted on — that preserves the login-CSRF protection (S2) while being robust to
    /// noise on the fixed port 1985 (the Entra app registration only redirects there).
    /// </summary>
    private static async Task<string> WaitForOAuthCallbackAsync(
        HttpListener listener, string expectedState, string successHtml, string failureTitle, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddMinutes(5);
        while (true)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
                throw new TimeoutException("Timed out waiting for the sign-in redirect. Please try connecting again.");

            var context = await listener.GetContextAsync().WaitAsync(remaining, ct);
            var query = context.Request.QueryString;
            var returnedState = query["state"];
            var code = query["code"];
            var error = query["error"];
            var errorDescription = query["error_description"];

            // Not our callback (no OAuth params at all) — a favicon fetch or another tool polling
            // this port. Answer politely and keep waiting for the real redirect.
            if (string.IsNullOrEmpty(returnedState) && string.IsNullOrEmpty(code) && string.IsNullOrEmpty(error))
            {
                await WriteBrowserResponseAsync(context, "<html><body>Waiting for sign-in…</body></html>", ct);
                continue;
            }

            // Carries state (or an error) but the state doesn't match ours: a stale/duplicate
            // redirect or a forgery attempt. Reject it but keep listening for the legitimate one.
            if (!string.Equals(returnedState, expectedState, StringComparison.Ordinal))
            {
                await WriteBrowserResponseAsync(context,
                    "<html><body>Unexpected sign-in response — ignoring. You can close this tab.</body></html>", ct);
                continue;
            }

            if (!string.IsNullOrEmpty(error))
            {
                await WriteBrowserResponseAsync(context,
                    $"<html><body style='font-family:sans-serif'><h2>{failureTitle}</h2><p><b>{WebUtility.HtmlEncode(error)}</b></p><pre style='white-space:pre-wrap'>{WebUtility.HtmlEncode(errorDescription)}</pre></body></html>", ct);
                throw new InvalidOperationException($"{failureTitle}: {error} — {errorDescription}");
            }

            if (!string.IsNullOrEmpty(code))
            {
                await WriteBrowserResponseAsync(context, successHtml, ct);
                return code;
            }

            // Matching state but neither code nor error — unusual; keep waiting.
            await WriteBrowserResponseAsync(context, "<html><body>Waiting for sign-in…</body></html>", ct);
        }
    }

    private static async Task WriteBrowserResponseAsync(HttpListenerContext context, string html, CancellationToken ct)
    {
        var buffer = System.Text.Encoding.UTF8.GetBytes(html);
        context.Response.ContentType = "text/html";
        context.Response.ContentLength64 = buffer.Length;
        await context.Response.OutputStream.WriteAsync(buffer, ct);
        context.Response.Close();
    }

    /// <summary>
    /// Bind the loopback listener on the fixed redirect port (1985, the only URI registered on the
    /// Entra app). Fails fast with an actionable message if the port is already in use (R4/S6).
    /// </summary>
    private static HttpListener StartLoopbackListener(string redirectUri)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add(redirectUri);
        try
        {
            listener.Start();
        }
        catch (HttpListenerException ex)
        {
            throw new InvalidOperationException(
                "Cannot start the sign-in listener on http://localhost:1985 — the port is in use by " +
                "another application. Free port 1985 and try connecting again. (The Entra app only " +
                $"permits this redirect URI.) Details: {ex.Message}", ex);
        }
        return listener;
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void OpenBrowser(string url)
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
}
