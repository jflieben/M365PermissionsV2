using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Exchange Online for mailbox permissions (FullAccess, SendAs, SendOnBehalf).
/// Uses Exchange REST API (InvokeCommand pattern), matching V1's get-ExOPermissions.ps1.
/// </summary>
public sealed class ExchangeScanner : IScanProvider
{
    public string Category => "Exchange";

    public const string OrphanedSidType = "Orphaned SID";

    private readonly ExchangeRestClient _exoClient;
    private readonly GraphClient _graphClient;

    public ExchangeScanner(ExchangeRestClient exoClient, GraphClient graphClient)
    {
        _exoClient = exoClient;
        _graphClient = graphClient;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Exchange mailboxes...", 3);

        // Tenant ID, as the EXO module uses. The default domain is not always an accepted domain in Exchange.
        var organization = string.IsNullOrEmpty(context.TenantId) ? context.TenantDomain : context.TenantId;

        // Get all mailboxes
        var mailboxes = await _exoClient.GetMailboxesAsync(organization, ct);

        context.SetTotalTargets(mailboxes.Count);
        context.ReportProgress($"Found {mailboxes.Count} mailboxes to scan.", 3);

        var trustees = new TrusteeResolver(_exoClient, organization);

        // Exchange throttles per user harder than Graph, so cap the per-mailbox parallelism.
        var dop = Math.Min(context.Config?.MaxThreads ?? 5, 4);
        await foreach (var entry in ParallelScan.RunAsync(mailboxes, dop,
            (mailbox, writer, tok) => ScanMailboxAsync(mailbox, organization, context, trustees, writer, tok), ct))
        {
            yield return entry;
        }

        if (trustees.Unresolved > 0)
            context.ReportProgress($"{trustees.Unresolved} trustee(s) could not be resolved to a recipient; their rows carry the raw trustee name.", 3);
    }

    private async Task ScanMailboxAsync(JsonElement mailbox, string organization, ScanContext context,
        TrusteeResolver trustees, ChannelWriter<PermissionEntry> writer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var identity = mailbox.TryGetProperty("Identity", out var id) ? id.GetString() ?? "" : "";
        var displayName = mailbox.TryGetProperty("DisplayName", out var dn) ? dn.GetString() ?? "" : "";
        var primarySmtp = mailbox.TryGetProperty("PrimarySmtpAddress", out var smtp) ? smtp.GetString() ?? "" : "";
        var externalId = mailbox.TryGetProperty("ExternalDirectoryObjectId", out var edi) ? edi.GetString() ?? "" : "";
        var recipientType = mailbox.TryGetProperty("RecipientTypeDetails", out var rtd) && rtd.ValueKind == JsonValueKind.String
            ? rtd.GetString() ?? "" : "";

        // Skip system mailboxes (e.g. DiscoverySearchMailbox)
        if (string.IsNullOrEmpty(identity) || displayName.StartsWith("DiscoverySearchMailbox", StringComparison.OrdinalIgnoreCase))
        {
            context.CompleteTarget();
            return;
        }

        context.ReportProgress($"Scanning mailbox: {displayName}", 5);
        var target = new MailboxTarget(primarySmtp, MapMailboxTargetType(recipientType), externalId);
        var failed = false;

        // --- Mailbox permissions (FullAccess) ---
        try
        {
            foreach (var perm in await _exoClient.GetMailboxPermissionsAsync(organization, identity, ct))
                foreach (var entry in MapMailboxPermission(perm, target))
                    await writer.WriteAsync(await trustees.EnrichAsync(entry, ct), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Failed to get mailbox permissions for {displayName}: {ex.Message}", 2);
            failed = true;
        }

        // --- Recipient permissions (SendAs) ---
        try
        {
            foreach (var perm in await _exoClient.GetRecipientPermissionsAsync(organization, identity, ct))
                foreach (var entry in MapRecipientPermission(perm, target))
                    await writer.WriteAsync(await trustees.EnrichAsync(entry, ct), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            context.ReportProgress($"Failed to get recipient permissions for {displayName}: {ex.Message}", 2);
            failed = true;
        }

        // --- SendOnBehalf (from mailbox properties) ---
        if (mailbox.TryGetProperty("GrantSendOnBehalfTo", out var delegates))
        {
            foreach (var del in ReadStringValues(delegates))
            {
                await writer.WriteAsync(await trustees.EnrichAsync(new PermissionEntry
                {
                    TargetPath = target.Path,
                    TargetType = target.Type,
                    TargetId = target.Id,
                    PrincipalSysId = del,
                    PrincipalSysName = del,
                    PrincipalType = "User",
                    PrincipalRole = "SendOnBehalf",
                    Through = "GrantSendOnBehalfTo",
                    AccessType = "Allow",
                    Tenure = "Permanent"
                }, ct), ct);
            }
        }

        if (failed) context.FailTarget();
        else context.CompleteTarget();
    }

    private readonly record struct MailboxTarget(string Path, string Type, string Id);

    private static List<PermissionEntry> MapMailboxPermission(JsonElement perm, MailboxTarget target)
    {
        var entries = new List<PermissionEntry>();

        var user = perm.TryGetProperty("User", out var u) ? u.GetString() ?? "" : "";

        // Skip self and inherited
        if (user.Equals("NT AUTHORITY\\SELF", StringComparison.OrdinalIgnoreCase)) return entries;
        if (perm.TryGetProperty("IsInherited", out var inh) && GetBool(inh)) return entries;

        var deny = perm.TryGetProperty("Deny", out var d) && GetBool(d);
        foreach (var right in perm.TryGetProperty("AccessRights", out var rights) ? ParseAccessRights(rights) : new List<string>())
        {
            entries.Add(new PermissionEntry
            {
                TargetPath = target.Path,
                TargetType = target.Type,
                TargetId = target.Id,
                PrincipalSysId = user,
                PrincipalSysName = user,
                PrincipalType = MapExoUserType(user),
                PrincipalRole = right,
                Through = "MailboxPermission",
                AccessType = deny ? "Deny" : "Allow",
                Tenure = "Permanent"
            });
        }

        return entries;
    }

    private static List<PermissionEntry> MapRecipientPermission(JsonElement perm, MailboxTarget target)
    {
        var entries = new List<PermissionEntry>();
        var trustee = perm.TryGetProperty("Trustee", out var t) ? t.GetString() ?? "" : "";

        // Skip self and inherited, as for FullAccess.
        if (trustee.Equals("NT AUTHORITY\\SELF", StringComparison.OrdinalIgnoreCase)) return entries;
        if (perm.TryGetProperty("IsInherited", out var inh) && GetBool(inh)) return entries;

        var deny = perm.TryGetProperty("AccessControlType", out var act) && IsDeny(act);
        var rights = perm.TryGetProperty("AccessRights", out var ar) ? ParseAccessRights(ar) : new List<string>();
        if (rights.Count == 0) rights.Add("SendAs");

        foreach (var right in rights)
        {
            entries.Add(new PermissionEntry
            {
                TargetPath = target.Path,
                TargetType = target.Type,
                TargetId = target.Id,
                PrincipalSysId = trustee,
                PrincipalSysName = trustee,
                PrincipalType = MapExoUserType(trustee),
                PrincipalRole = right,
                Through = "RecipientPermission",
                AccessType = deny ? "Deny" : "Allow",
                Tenure = "Permanent"
            });
        }
        return entries;
    }

    /// <summary>AccessRights as an array or as a comma-separated string ("FullAccess, ReadPermission").</summary>
    public static List<string> ParseAccessRights(JsonElement rights)
    {
        var result = new List<string>();
        foreach (var value in ReadStringValues(rights))
            foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                if (!result.Contains(part, StringComparer.OrdinalIgnoreCase)) result.Add(part);
        return result;
    }

    /// <summary>Strings from a JSON array or a single string value.</summary>
    private static IEnumerable<string> ReadStringValues(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                    yield return item.GetString()!;
        }
        else if (el.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(el.GetString()))
        {
            yield return el.GetString()!;
        }
    }

    /// <summary>AccessControlType as "Deny" or its enum value 1.</summary>
    public static bool IsDeny(JsonElement act) => act.ValueKind switch
    {
        JsonValueKind.String => string.Equals(act.GetString(), "Deny", StringComparison.OrdinalIgnoreCase),
        JsonValueKind.Number => act.TryGetInt32(out var n) && n == 1,
        _ => false
    };

    /// <summary>Read a JSON value as bool, handling both JSON booleans and string representations.</summary>
    private static bool GetBool(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String => bool.TryParse(el.GetString(), out var b) && b,
        _ => false
    };

    /// <summary>A SID left behind by a deleted account (cleanup finding).</summary>
    public static bool IsOrphanedSid(string user) => user.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);

    private static string MapExoUserType(string user)
    {
        if (IsOrphanedSid(user)) return OrphanedSidType;
        if (user.Equals("Default", StringComparison.OrdinalIgnoreCase)) return "AllInternalUsers";
        if (user.Equals("Anonymous", StringComparison.OrdinalIgnoreCase)) return "Anonymous";
        if (user.Contains("ExchangePublishedUser", StringComparison.OrdinalIgnoreCase)) return "External User";
        return "User";
    }

    /// <summary>Mailbox RecipientTypeDetails to the row's TargetType.</summary>
    public static string MapMailboxTargetType(string recipientTypeDetails) => recipientTypeDetails switch
    {
        "SharedMailbox" => "SharedMailbox",
        "RoomMailbox" => "RoomMailbox",
        "EquipmentMailbox" => "EquipmentMailbox",
        _ => "Mailbox"
    };

    /// <summary>Trustee RecipientTypeDetails to PrincipalType; null when unknown (keep the name-based guess).</summary>
    public static string? MapRecipientPrincipalType(string recipientTypeDetails) => recipientTypeDetails switch
    {
        "GuestMailUser" => "Guest",
        "MailContact" => "External User",
        "GroupMailbox" => "M365Group",
        "MailUniversalSecurityGroup" or "UniversalSecurityGroup" or "RoleGroup" => "SecurityGroup",
        "MailUniversalDistributionGroup" or "MailNonUniversalGroup" or "DynamicDistributionGroup" or "RoomList" => "DistributionList",
        // MailUser covers hybrid users whose mailbox is on-premises: internal, not external.
        "UserMailbox" or "SharedMailbox" or "RoomMailbox" or "EquipmentMailbox" or "LinkedMailbox"
            or "SchedulingMailbox" or "MailUser" or "User" or "LinkedUser" or "RemoteUserMailbox" => "User",
        _ => null
    };

    /// <summary>
    /// Resolves each distinct trustee once via Get-Recipient so rows carry the Entra object id, UPN and
    /// a real principal type. Cost is bounded by the number of distinct trustees, not rows.
    /// </summary>
    private sealed class TrusteeResolver
    {
        private readonly ExchangeRestClient _exo;
        private readonly string _organization;
        private readonly ConcurrentDictionary<string, Lazy<Task<JsonElement?>>> _cache = new(StringComparer.OrdinalIgnoreCase);
        private int _unresolved;

        public int Unresolved => _unresolved;

        public TrusteeResolver(ExchangeRestClient exo, string organization)
        {
            _exo = exo;
            _organization = organization;
        }

        public async Task<PermissionEntry> EnrichAsync(PermissionEntry entry, CancellationToken ct)
        {
            var trustee = entry.PrincipalSysId;
            if (!IsResolvable(trustee, entry.PrincipalType)) return entry;

            var recipient = await _cache.GetOrAdd(trustee,
                key => new Lazy<Task<JsonElement?>>(() => LookupAsync(key, ct))).Value;
            if (recipient is not { } r) return entry;

            string Str(string name) => r.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

            var objectId = Str("ExternalDirectoryObjectId");
            var upn = Str("WindowsLiveID");
            if (string.IsNullOrEmpty(upn)) upn = Str("PrimarySmtpAddress");
            var name = Str("DisplayName");

            if (!string.IsNullOrEmpty(objectId)) entry.PrincipalEntraId = objectId;
            if (!string.IsNullOrEmpty(upn)) entry.PrincipalEntraUpn = upn;
            if (!string.IsNullOrEmpty(name)) entry.PrincipalSysName = name;
            if (MapRecipientPrincipalType(Str("RecipientTypeDetails")) is { } type) entry.PrincipalType = type;
            return entry;
        }

        private static bool IsResolvable(string trustee, string principalType)
            => !string.IsNullOrWhiteSpace(trustee)
               && principalType == "User"
               // DOMAIN\account forms are Exchange system accounts that Get-Recipient cannot resolve.
               && !trustee.Contains('\\')
               && !trustee.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase);

        private async Task<JsonElement?> LookupAsync(string trustee, CancellationToken ct)
        {
            try
            {
                var r = await _exo.GetRecipientAsync(_organization, trustee, ct);
                if (r == null) Interlocked.Increment(ref _unresolved);
                return r;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Not found (deleted trustee) or not resolvable: the row keeps the raw trustee.
                Interlocked.Increment(ref _unresolved);
                return null;
            }
        }
    }
}
