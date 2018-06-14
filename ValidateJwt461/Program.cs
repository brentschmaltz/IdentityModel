using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace ValidateJwt461
{
    class Program
    {
        static void Main(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;
            var jwt = "<put jwt here>";
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>("https://sts.windows.net/51641c40-ad65-4736-88fc-2f0e10072d85/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            var config = configManager.GetConfigurationAsync().GetAwaiter().GetResult();
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = config.SigningKeys,
                ValidAudience = "29635cdc-ca9a-48b7-b242-05a31810e8c9",
                ValidIssuer = "https://sts.windows.net/51641c40-ad65-4736-88fc-2f0e10072d85/",
                ValidateLifetime = false,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out SecurityToken securityToken);
                Console.WriteLine("===============================");
                Console.WriteLine("");
                Console.WriteLine($"Token Validated");
                Console.WriteLine("");

                foreach (var claim in claimsPrincipal.Claims)
                    Console.WriteLine($"Claim: '{claim.Type}, {claim.Value}'");

                Console.WriteLine("");
                Console.WriteLine($"ClaimsPrincipal (type): {claimsPrincipal}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("===============================");
                Console.WriteLine("");
                Console.WriteLine($"ValidateToken threw: {ex}'");
                Console.WriteLine("");
            }

            Console.WriteLine("Press Any Key to continue");
            Console.ReadKey();
        }
    }

}
