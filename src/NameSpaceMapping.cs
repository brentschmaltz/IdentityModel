using System.IdentityModel.Tokens.Jwt;
using SecurityTokenDescriptor = Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor;
using TokenDescriptor = Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor;

namespace Wilson5x
{
    public class NameSpaceMapping
    {
        public static void Run()
        {
            // System.IdentityModel.dll
            var securityTokenDescriptor = new SecurityTokenDescriptor();

            // System.IdentityModel.Tokens.Jwt.dll
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new TokenDescriptor();
            tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        }
    }
}
