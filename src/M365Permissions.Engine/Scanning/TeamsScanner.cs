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
                var entry = MapTeamMember(member, $"Team/{teamName}", "SecurityGroup", teamId, "TeamMembership");
                if (entry != null) await writer.WriteAsync(entry, ct);
            }

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

                await foreach (var member in _graphClient.GetPaginatedAsync(
                    $"teams/{teamId}/channels/{channelId}/members", ct: ct))
                {
                    var entry = MapTeamMember(member, $"Team/{teamName}/Channel/{channelName} ({membershipType})",
                        "Channel", channelId, "ChannelMembership");
                    if (entry != null) await writer.WriteAsync(entry, ct);
                }
            }

            context.CompleteTarget();
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
    private static PermissionEntry? MapTeamMember(JsonElement member, string targetPath, string targetType,
        string targetId, string through)
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
            PrincipalType = isGuest ? "Guest" : "User",
            PrincipalRole = role,
            Through = through,
            AccessType = "Allow",
            Tenure = "Permanent"
        };
    }
}
