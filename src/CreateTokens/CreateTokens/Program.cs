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
            // some local variables for all cases
            var audience = "microsoft.com";
            var issuer = "contoso.com";
            var subject = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, "bob@contoso.com"),
                new Claim(JwtRegisteredClaimNames.GivenName, "bob"),
            });

            var tokenHandler = new JwtSecurityTokenHandler();

            // Create and validate a Compact JWS see: https://tools.ietf.org/html/rfc7515#section-3.1

            // sign with shared symmetric key
            var symmetricSigningCredentials = new SigningCredentials(KeyMaterial.SymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256);
            var jwtSymmetric = CreateEncodedJwt(subject, audience, issuer, tokenHandler, symmetricSigningCredentials, null);
            var claimsPrincipalSymmetric = ValidateToken(jwtSymmetric, tokenHandler, audience, issuer, KeyMaterial.SymmetricSecurityKey_256, null);

            // sign with asymmetric key that has private key, validate with public key
            var asymmetricSigningCredentials = new SigningCredentials(KeyMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256);
            var jwtAsymmetric = CreateEncodedJwt(subject, audience, issuer, tokenHandler, asymmetricSigningCredentials, null);
            var claimsPrincipalAsymmetric = ValidateToken(jwtAsymmetric, tokenHandler, audience, issuer, KeyMaterial.RsaSecurityKey_2048_Public, null);

            // Create and validate a JWE see: https://tools.ietf.org/html/rfc7516#section-3

            // encrypt with a shared symmetric key to wrap the key that encrypts the payload
            var symmetricEncryptionCredentials = new EncryptingCredentials(KeyMaterial.SymmetricSecurityKey_256, "dir", SecurityAlgorithms.Aes128CbcHmacSha256);
            var jweSymmetric = CreateEncodedJwt(subject, audience, issuer, tokenHandler, asymmetricSigningCredentials, symmetricEncryptionCredentials);
            var claimsPrincipalJweSymmetric = ValidateToken(jweSymmetric, tokenHandler, audience, issuer, KeyMaterial.RsaSecurityKey_2048_Public, KeyMaterial.SymmetricSecurityKey_256);

            // encrypt with recipients public key to wrap a key that encrypts the payload. Decrypt using pirvate key.
            var asymmetricEncryptionCredentials = new EncryptingCredentials(KeyMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
            var jweAymmetric = CreateEncodedJwt(subject, audience, issuer, tokenHandler, symmetricSigningCredentials, asymmetricEncryptionCredentials);
            var claimsPrincipalJweAsymmetric = ValidateToken(jweAymmetric, tokenHandler, audience, issuer, KeyMaterial.SymmetricSecurityKey_256, KeyMaterial.RsaSecurityKey_2048);

            Console.WriteLine("CreateTokens completed. If no exceptions, all went well.");
            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }

        private static string CreateEncodedJwt(ClaimsIdentity subject, string audience, string issuer, JwtSecurityTokenHandler tokenHandler, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Audience = audience,
                EncryptingCredentials = encryptingCredentials,
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

        private static ClaimsPrincipal ValidateToken(string encodedJwt, JwtSecurityTokenHandler tokenHandler, string audience, string issuer, SecurityKey signingKey, SecurityKey encryptionKey)
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = signingKey,
                TokenDecryptionKey = encryptionKey
            };

            try
            {
                return tokenHandler.ValidateToken(encodedJwt, validationParameters, out SecurityToken securityToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ValidateToken threw: {ex}'");
            }

            return null;
        }
    }
}
