using System.Text.Json;
using M365Permissions.Engine.Scanning;
using Xunit;

namespace M365Permissions.Engine.Tests.Scanning;

public sealed class ExchangeMappingTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Theory]
    [InlineData("[\"FullAccess\"]", new[] { "FullAccess" })]
    [InlineData("[\"FullAccess\", \"ReadPermission\"]", new[] { "FullAccess", "ReadPermission" })]
    [InlineData("\"FullAccess, ReadPermission\"", new[] { "FullAccess", "ReadPermission" })]
    [InlineData("\"SendAs\"", new[] { "SendAs" })]
    [InlineData("\"\"", new string[0])]
    [InlineData("null", new string[0])]
    public void ParseAccessRights_HandlesArraysAndCommaSeparatedStrings(string json, string[] expected)
    {
        Assert.Equal(expected, ExchangeScanner.ParseAccessRights(Json(json)));
    }

    [Theory]
    [InlineData("UserMailbox", "Mailbox")]
    [InlineData("SharedMailbox", "SharedMailbox")]
    [InlineData("RoomMailbox", "RoomMailbox")]
    [InlineData("EquipmentMailbox", "EquipmentMailbox")]
    [InlineData("LinkedMailbox", "Mailbox")]
    [InlineData("", "Mailbox")]
    public void MapMailboxTargetType_UsesRecipientTypeDetails(string recipientType, string expected)
    {
        Assert.Equal(expected, ExchangeScanner.MapMailboxTargetType(recipientType));
    }

    [Theory]
    [InlineData("UserMailbox", "User")]
    [InlineData("SharedMailbox", "User")]
    [InlineData("MailUser", "User")]
    [InlineData("GuestMailUser", "Guest")]
    [InlineData("MailContact", "External User")]
    [InlineData("MailUniversalSecurityGroup", "SecurityGroup")]
    [InlineData("MailUniversalDistributionGroup", "DistributionList")]
    [InlineData("GroupMailbox", "M365Group")]
    [InlineData("SomethingNew", null)]
    public void MapRecipientPrincipalType_MapsTrusteeTypes(string recipientType, string? expected)
    {
        Assert.Equal(expected, ExchangeScanner.MapRecipientPrincipalType(recipientType));
    }

    [Theory]
    [InlineData("\"Deny\"", true)]
    [InlineData("\"Allow\"", false)]
    [InlineData("1", true)]
    [InlineData("0", false)]
    public void IsDeny_ReadsStringAndEnumValue(string json, bool expected)
    {
        Assert.Equal(expected, ExchangeScanner.IsDeny(Json(json)));
    }

    [Theory]
    [InlineData("S-1-5-21-1234-5678-9012-1001", true)]
    [InlineData("user@contoso.com", false)]
    [InlineData("NT AUTHORITY\\SELF", false)]
    public void IsOrphanedSid_MatchesDomainSids(string user, bool expected)
    {
        Assert.Equal(expected, ExchangeScanner.IsOrphanedSid(user));
    }
}
