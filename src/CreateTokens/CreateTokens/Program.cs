using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace CreateTokens
{
    /// <summary>
    /// Creating and validating JwtTokens with symmetric and asymmetric keys
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {

            ProtectedForwardedTokens.Run();

            var audience = "microsoft.com";
            var issuer = "contoso.com";
            var subject = new ClaimsIdentity(
                new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Email, "bob@contoso.com"),
                    new Claim(JwtRegisteredClaimNames.GivenName, "bob"),
                });

            var tokenHandler = new JwtSecurityTokenHandler();

            // symmetric key
            var encodedJwtSymmetric = CreateEncodedToken(subject, audience, issuer, tokenHandler, new SigningCredentials(KeyMaterial.SymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256));
            var claimsPrincipalSymmetric = ValidateToken(encodedJwtSymmetric, tokenHandler, audience, issuer, KeyMaterial.SymmetricSecurityKey_256);

            // asymmetric key
            var encodedJwtAsymmetric = CreateEncodedToken(subject, audience, issuer, tokenHandler, new SigningCredentials(KeyMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256));
            var claimsPrincipalAsymmetric = ValidateToken(encodedJwtAsymmetric, tokenHandler, audience, issuer, KeyMaterial.RsaSecurityKey_2048);

            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }

        private static string CreateEncodedToken(ClaimsIdentity subject, string audience, string issuer, JwtSecurityTokenHandler tokenHandler, SigningCredentials signingCredentials)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Audience = audience,
                Issuer = issuer,
                SigningCredentials = signingCredentials,
                Subject = subject
            };

            try
            {
                return tokenHandler.CreateEncodedJwt(tokenDescriptor);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CreateEncodedJwt threw: '{ex}'");
            }

            return null;
        }

        private static ClaimsPrincipal ValidateToken(string encodedJwt, JwtSecurityTokenHandler tokenHandler, string audience, string issuer,  SecurityKey securityKey)
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = securityKey
            };

            SecurityToken securityToken = null;
            try
            {
                return tokenHandler.ValidateToken(encodedJwt, validationParameters, out securityToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ValidateToken threw: {ex}'");
            }

            return null;
        }
    }
}
