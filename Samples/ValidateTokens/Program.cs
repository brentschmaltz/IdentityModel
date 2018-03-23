using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Shows how to validate a token while restricting to a set of algorithms.
/// </summary>
namespace ValidateTokens
{
    class Program
    {
        static void Main(string[] args)
        {
            var audience = "microsoft.com";
            var issuer = "contoso.com";
            var subject = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, "bob@contoso.com"),
                new Claim(JwtRegisteredClaimNames.GivenName, "bob"),
            });

            var tokenHandler = new JwtSecurityTokenHandler();

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

        private static ClaimsPrincipal ValidateToken(string encodedJwt, JwtSecurityTokenHandler tokenHandler, string audience, string issuer, SecurityKey securityKey)
        {

            // method 1, set CryptoProviderFactory on TokenValidationParameters. Will be scoped to all keys.
            var validationParameters = new TokenValidationParameters
            {
                CryptoProviderFactory = new RestrictedCryptoProviderFactory(SecurityAlgorithms.EcdsaSha512),
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = securityKey
            };

            try
            {
                return tokenHandler.ValidateToken(encodedJwt, validationParameters, out SecurityToken securityToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine("===============================");
                Console.WriteLine("");
                Console.WriteLine($"Method1 - ValidateToken threw: {ex}'");
                Console.WriteLine("");
            }

            // method 2, set CryptoProviderFactory on securityKey. Use this method to scope to specific keys.
            validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = new RestrictedRsaSecurityKey(KeyMaterial.RsaParameters_2048, SecurityAlgorithms.EcdsaSha512)
            };

            try
            {
                return tokenHandler.ValidateToken(encodedJwt, validationParameters, out SecurityToken securityToken2);
            }
            catch (Exception ex)
            {
                Console.WriteLine("===============================");
                Console.WriteLine("");
                Console.WriteLine($"Method2 - ValidateToken threw: {ex}'");
                Console.WriteLine("");
                Console.WriteLine("===============================");

            }

            return null;
        }
    }

    public class RestrictedRsaSecurityKey : RsaSecurityKey
    {
        public RestrictedRsaSecurityKey(RSAParameters rsaParameters, params string[] validAlgorithms)
            : base(rsaParameters)
        {
            CryptoProviderFactory = new RestrictedCryptoProviderFactory(validAlgorithms);
        }

    }

    public class RestrictedCryptoProviderFactory : CryptoProviderFactory
    {
        public RestrictedCryptoProviderFactory(params string[] validAlgorithms)
        {
            ValidAlgorithms = new List<string>(validAlgorithms);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            foreach (var supportedAlgorithm in ValidAlgorithms)
                if (algorithm.Equals(supportedAlgorithm))
                    return true;

            return false;
        }

        public IList<string> ValidAlgorithms
        {
            get;
            private set;
        }
    }
}
