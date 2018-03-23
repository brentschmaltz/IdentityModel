// Code from issue below
// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/872
//

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SupportIssues
{
    class Issue872
    {
        private const string Key = "C5AxWRAoC/lp3Ayt1RcAxMQDZ74fy1f6rzA7ko1GME06/FkBhRML1BNLXMwTVeoRAJ2oVvIdTy8b4Px8FgJ7e36hCp6SopZhoAng1HwPtLYg4QUXMfjCjaKEqba4/e5nsZXaJpn9a6CaSFy6WL3PPV5m7ZyFK+jLlhT+X5inqPk=";

        public static void Run()
        {
            // works like a charm
            var token = CreateJwe();
            var validationParamters = GetValidationParameters();
            validationParamters.RequireSignedTokens = false;
            var claimsPrincipalSuccess = ValidateToken(token, validationParamters, out var validatedTokenSuccess);


            //fails and throws an IDX10504
            var faultyToken = CreateJwe();
            var claimsPrincipalFailure = ValidateToken(faultyToken, GetValidationParameters(), out var validatedTokenFailure);
        }

        private static string CreateJwe()
        {
            var header = new JwtHeader(new EncryptingCredentials(GetSecurityKey(), JwtConstants.DirectKeyUseAlg,
                SecurityAlgorithms.Aes256CbcHmacSha512));
            var payload = new JwtPayload(GetClaims());
            var token = new JwtSecurityToken(header, payload);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out validatedToken);
            return claimsPrincipal;
        }

        private static SymmetricSecurityKey GetSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.Default.GetBytes(Key));
        }

        private static TokenValidationParameters GetValidationParameters()
        {
            return new TokenValidationParameters
            {
                IssuerSigningKey = GetSecurityKey(),
                ValidIssuer = "TheMan",
                ValidateIssuer = true,
                ValidateLifetime = true,
                ValidateAudience = false,
                TokenDecryptionKey = new EncryptingCredentials(GetSecurityKey(),
                    JwtConstants.DirectKeyUseAlg,
                    SecurityAlgorithms.Aes256CbcHmacSha512).Key

            };
        }

        private static List<Claim> GetClaims()
        {
            return new List<Claim>
            {
                new Claim("exp", "1517638188"),
                new Claim("iat", "1517609388"),
                new Claim("iss", "TheMan"),
                new Claim("nbf", "1517609388")
            };
        }
    }
}
