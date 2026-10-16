using System.Text.Json;
using System.Threading.Channels;
using M365Permissions.Engine.Graph;
using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Scans Microsoft Teams: team owners/members/guests and channel memberships (including private
/// and shared channels). All via Graph (/teams, /channels, /members) — no elevation needed (A6).
/// </summary>
public sealed class TeamsScanner : IScanProvider
{
    public string Category => "Teams";

    private readonly GraphClient _graphClient;

    public TeamsScanner(GraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async IAsyncEnumerable<PermissionEntry> ScanAsync(
        ScanContext context,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        context.ReportProgress("Enumerating Teams...", 3);

        // Teams are Microsoft 365 groups with the "Team" provisioning option.
        var teams = new List<JsonElement>();
        await foreach (var team in _graphClient.GetPaginatedAsync(
            "groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName", ct: ct))
        {
            teams.Add(team);
        }

        context.SetTotalTargets(teams.Count);
        context.ReportProgress($"Found {teams.Count} teams to scan.", 3);

        var dop = context.Config?.MaxThreads ?? 5;
        await foreach (var entry in ParallelScan.RunAsync(teams, dop,
            (team, writer, tok) => ScanTeamAsync(team, context, writer, tok), ct))
        {
            yield return entry;
        }

        context.ReportProgress("Completed Teams scan.", 3);
    }

    private async Task ScanTeamAsync(JsonElement team, ScanContext context,
        ChannelWriter<PermissionEntry> writer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var teamId = team.TryGetProperty("id", out var tid) ? tid.GetString() ?? "" : "";
        var teamName = team.TryGetProperty("displayName", out var tdn) ? tdn.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(teamId))
        {
            context.CompleteTarget();
            return;
        }

        try
        {
            // --- Team-level members (owners / members / guests) ---
            await foreach (var member in _graphClient.GetPaginatedAsync($"teams/{teamId}/members", ct: ct))
            {
                var entry = MapTeamMember(member, $"Team/{teamName}", "Team", teamId, "TeamMembership", context.TenantId);
                if (entry != null) await writer.WriteAsync(entry, ct);
            }

            var channelErrors = 0;

            // --- Channel memberships (private & shared channels carry their own membership) ---
            await foreach (var channel in _graphClient.GetPaginatedAsync(
                $"teams/{teamId}/channels?$select=id,displayName,membershipType", ct: ct))
            {
                var channelId = channel.TryGetProperty("id", out var cid) ? cid.GetString() ?? "" : "";
                var channelName = channel.TryGetProperty("displayName", out var cdn) ? cdn.GetString() ?? "" : "";
                var membershipType = channel.TryGetProperty("membershipType", out var mt) ? mt.GetString() ?? "standard" : "standard";

                // Standard channels inherit the team roster (already captured above). Only private
                // and shared channels have a distinct membership worth enumerating.
                if (membershipType.Equals("standard", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(channelId))
                    continue;

                var channelPath = $"Team/{teamName}/Channel/{channelName} ({membershipType})";
                try
                {
                    await foreach (var member in _graphClient.GetPaginatedAsync(
                        $"teams/{teamId}/channels/{channelId}/members", ct: ct))
                    {
                        var entry = MapTeamMember(member, channelPath, "Channel", channelId, "ChannelMembership", context.TenantId);
                        if (entry != null) await writer.WriteAsync(entry, ct);
                    }

                    // Shared channels can also be shared with whole teams, whose members then have access.
                    if (membershipType.Equals("shared", StringComparison.OrdinalIgnoreCase))
                    {
                        await foreach (var shared in _graphClient.GetPaginatedAsync(
                            $"teams/{teamId}/channels/{channelId}/sharedWithTeams", ct: ct))
                        {
                            var sharedId = shared.TryGetProperty("id", out var sid) ? sid.GetString() ?? "" : "";
                            if (string.IsNullOrEmpty(sharedId) || sharedId.Equals(teamId, StringComparison.OrdinalIgnoreCase)) continue;
                            var sharedTenant = shared.TryGetProperty("tenantId", out var stid) ? stid.GetString() ?? "" : "";
                            await writer.WriteAsync(new PermissionEntry
                            {
                                TargetPath = channelPath,
                                TargetType = "Channel",
                                TargetId = channelId,
                                PrincipalEntraId = sharedId,
                                PrincipalSysName = shared.TryGetProperty("displayName", out var sdn) ? sdn.GetString() ?? "" : sharedId,
                                PrincipalType = IsExternalTenant(sharedTenant, context.TenantId) ? "External Group" : "M365Group",
                                PrincipalRole = "Member",
                                Through = "SharedChannelTeam",
                                AccessType = "Allow",
                                Tenure = "Permanent"
                            }, ct);
                        }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    channelErrors++;
                    context.ReportProgress($"Failed to read members of {channelPath}: {ex.Message}", 2);
                }
            }

            if (channelErrors > 0) context.FailTarget();
            else context.CompleteTarget();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            context.ReportProgress($"Failed to scan team '{teamName}': {ex.Message}", 2);
            context.FailTarget();
        }
    }

    /// <summary>Map a Graph conversationMember (aadUserConversationMember) to a permission entry.</summary>
    private static bool IsExternalTenant(string memberTenantId, string homeTenantId)
        => !string.IsNullOrEmpty(memberTenantId) && !string.IsNullOrEmpty(homeTenantId)
           && !memberTenantId.Equals(homeTenantId, StringComparison.OrdinalIgnoreCase);

    private static PermissionEntry? MapTeamMember(JsonElement member, string targetPath, string targetType,
        string targetId, string through, string homeTenantId)
    {
        var displayName = member.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
        var userId = member.TryGetProperty("userId", out var uid) ? uid.GetString() ?? "" : "";
        var email = member.TryGetProperty("email", out var em) ? em.GetString() ?? "" : "";

        // roles is an array like ["owner"] or ["guest"]; empty means a regular member.
        var role = "Member";
        var isGuest = false;
        if (member.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in roles.EnumerateArray())
            {
                var rv = r.GetString() ?? "";
                if (rv.Equals("owner", StringComparison.OrdinalIgnoreCase)) role = "Owner";
                else if (rv.Equals("guest", StringComparison.OrdinalIgnoreCase)) isGuest = true;
            }
        }

        if (string.IsNullOrEmpty(displayName) && string.IsNullOrEmpty(email) && string.IsNullOrEmpty(userId))
            return null;

        return new PermissionEntry
        {
            TargetPath = targetPath,
            TargetType = targetType,
            TargetId = targetId,
            PrincipalEntraId = userId,
            PrincipalEntraUpn = email,
            PrincipalSysName = displayName,
            // Shared channel members from other tenants (B2B direct connect) are not guests but are external.
            PrincipalType = isGuest ? "Guest"
                : IsExternalTenant(member.TryGetProperty("tenantId", out var mt) ? mt.GetString() ?? "" : "", homeTenantId) ? "External User"
                : "User",
            PrincipalRole = role,
            Through = through,
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }
}
