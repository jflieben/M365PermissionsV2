using System.Text;
using System.Text.Json;
using M365Permissions.Engine.Auth;
using Xunit;

namespace M365Permissions.Engine.Tests.Auth;

public sealed class TokenClaimsTests
{
    /// <summary>Unsigned JWT with the given payload, base64url-encoded like Entra tokens.</summary>
    internal static string Jwt(object payload)
    {
        static string B64Url(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"{B64Url("{\"alg\":\"none\"}")}.{B64Url(JsonSerializer.Serialize(payload))}.sig";
    }

    [Fact]
    public void TryParse_ReadsRolesScopesTenantAndAudience()
    {
        var claims = TokenClaims.TryParse(Jwt(new
        {
            aud = "https://contoso-admin.sharepoint.com",
            tid = "11111111-1111-1111-1111-111111111111",
            scp = "AllSites.FullControl User.Read.All",
            wids = new[] { DirectoryRoles.SharePointAdministrator, DirectoryRoles.DefaultUserRole }
        }));

        Assert.NotNull(claims);
        Assert.True(claims!.HasScope("allsites.fullcontrol"));
        Assert.False(claims.HasScope("Sites.Read.All"));
        Assert.True(claims.HasAnyRole(new[] { DirectoryRoles.GlobalAdministrator, DirectoryRoles.SharePointAdministrator }));
        Assert.Equal("11111111-1111-1111-1111-111111111111", claims.TenantId);
        Assert.Equal("https://contoso-admin.sharepoint.com", claims.Audience);
    }

    [Fact]
    public void TryParse_WithoutWids_LeavesRolesUnknown()
    {
        var claims = TokenClaims.TryParse(Jwt(new { scp = "User.Read" }));

        Assert.NotNull(claims);
        Assert.Null(claims!.RoleTemplateIds);
        Assert.False(claims.HasAnyRole(new[] { DirectoryRoles.GlobalAdministrator }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("a.%%%.c")]
    public void TryParse_ReturnsNullForNonJwt(string? value)
    {
        Assert.Null(TokenClaims.TryParse(value));
    }
}
