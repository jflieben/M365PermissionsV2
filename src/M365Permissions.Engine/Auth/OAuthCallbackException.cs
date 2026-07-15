namespace M365Permissions.Engine.Auth;

/// <summary>
/// Raised when the OAuth authorize redirect returns an error instead of an authorization code.
/// <see cref="SkippableResourceCode"/> is non-null when the error means the requested resource
/// simply isn't provisioned or subscribed in this tenant (for example AADSTS650052 for Azure
/// DevOps). Callers acquiring a per-resource token treat that as a graceful skip rather than a
/// hard failure, so the rest of the sign-in / consent flow keeps working.
/// </summary>
public sealed class OAuthCallbackException : Exception
{
    public string? Error { get; }
    public string? ErrorDescription { get; }
    public string? SkippableResourceCode { get; }

    public OAuthCallbackException(string message, string? error, string? errorDescription, string? skippableResourceCode)
        : base(message)
    {
        Error = error;
        ErrorDescription = errorDescription;
        SkippableResourceCode = skippableResourceCode;
    }
}
