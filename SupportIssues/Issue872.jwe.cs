// Code from issue below
// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/872
//

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace SupportIssues
{
    class Issue872
    {
        private static string Audience { get => "http://Audience"; }
        private static string Issuer { get => "http://Issuer"; }

        // we need some static keys for creating and verifying signatures
        // we could also define some public keys to simulate what is returned from a 'discovery' or 'metadat' endpoint.
        private static string x509PrivateCertData = @"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";
        private static X509Certificate2 x509Cert = new X509Certificate2(Convert.FromBase64String(x509PrivateCertData), "SelfSigned2048_SHA256", X509KeyStorageFlags.PersistKeySet);
        private static X509SecurityKey x509SigningKey = new X509SecurityKey(x509Cert);

        public static void Run()
        {
            // ensure log and exception messages have full info.
            IdentityModelEventSource.ShowPII = true;

            Console.WriteLine($"============================");
            Console.WriteLine($"");

            // works like a charm
            try
            {
                var token = CreateJwe(null);
                var validationParamters = GetValidationParameters(null);
                validationParamters.RequireSignedTokens = false;
                var claimsPrincipalSuccess = ValidateToken(token, validationParamters, out var validatedTokenSuccess);
                Console.WriteLine($"JWE with embeded JWT - validated (RequireSignedTokens == false): {validatedTokenSuccess}");
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown when validating JWE: {ex}");
            }

            Console.WriteLine($"============================");
            Console.WriteLine($"");

            // fails and throws an IDX10504 - as JWE inner token is not signed
            try
            {
                var faultyToken = CreateJwe(null);
                var claimsPrincipalFailure = ValidateToken(faultyToken, GetValidationParameters(x509SigningKey), out var validatedTokenFailure);
                Console.WriteLine($"JWE with embeded JWT - validated (RequireSignedTokens == true): {validatedTokenFailure}");
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown when validating JWE with embeded JWT (RequireSignedTokens == true): {ex}");
            }

            Console.WriteLine($"============================");
            Console.WriteLine($"");

            // succeeds as JWE inner token is signed
            try
            {
                var jwe = CreateJwe(x509SigningKey);
                var claimsPrincipalFailure = ValidateToken(jwe, GetValidationParameters(x509SigningKey), out var validatedjwe);
                Console.WriteLine($"JWE with imbeded JWS - validated: {validatedjwe}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception thrown when validating JWE with embeded JWS (RequireSignedTokens == true): {ex}");
            }

            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }

        private static string CreateJwe(SecurityKey signingKey)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = Audience,
                EncryptingCredentials = new EncryptingCredentials(GetSecurityKey(), JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512),
                Issuer = Issuer
            };

            if (signingKey != null)
                tokenDescriptor.SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

            return new JwtSecurityTokenHandler().CreateEncodedJwt(tokenDescriptor);
        }

        private static ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out validatedToken);
            return claimsPrincipal;
        }

        private static SymmetricSecurityKey GetSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.Default.GetBytes("C5AxWRAoC/lp3Ayt1RcAxMQDZ74fy1f6rzA7ko1GME06/FkBhRML1BNLXMwTVeoRAJ2oVvIdTy8b4Px8FgJ7e36hCp6SopZhoAng1HwPtLYg4QUXMfjCjaKEqba4/e5nsZXaJpn9a6CaSFy6WL3PPV5m7ZyFK+jLlhT+X5inqPk="));
        }

        private static TokenValidationParameters GetValidationParameters(SecurityKey signingKey)
        {
            return new TokenValidationParameters
            {
                IssuerSigningKey = signingKey,
                TokenDecryptionKey = GetSecurityKey(),
                ValidAudience = Audience,
                ValidIssuer = Issuer
            };
        }

        private static List<Claim> GetClaims()
        {
            return new List<Claim>
            {
                new Claim("iss", "TheMan"),
            };
        }
    }
}
