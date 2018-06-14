using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ValidateJwtToken
{
    class Program
    {
        static void Main(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;
            var jwt = "<put jwt here>";
            var jsonWebKey = new JsonWebKey(@"{""kty"":""RSA"",""kid"":""ys2QMYg2fD0NdB8i3bpMseLu9eI="",""use"":""sig"",""alg"":""RS256"",""n"":""AL3DjpA1pyphepl3vwtUK75j2nWl96ZCmXt09buOL8JzYvLL2wAhDIZFL74RIjWkH1fxY4futJHPjedW-ck25CUyu4dTgPXvMipLJZwYjzqAsOKfFAxoQ2dUHqNCPyw3qKOTOvY04-MoIr2M2NU25kgwIN0Yy0yeHbOEtDWTXah9kBsbhUGXJ-IAxflH56bDzjRN8O-ptR0tfE-EDUn5A8URp0kGaIX5DucLbCg71bmZ7kPaJf31nGqHGd487v5dhlTn0E6L-x9GfA7J-XXPQ8Fbx0-ReQRIXJJtGNFRGQeXJ12FAbun3giRfYZTZaEtor6cHXCTfrW0f7nB7f7pQUc"",""e"":""AQAB""}");
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = jsonWebKey,
                ValidAudience = "<put audience here>",
                ValidIssuer = "<put issuer here>",
                ValidateLifetime = false,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out SecurityToken securityToken);
                foreach (var claim in claimsPrincipal.Claims)
                    Console.WriteLine($"Claim: '{claim.Type}, {claim.Value}'");

                Console.WriteLine($"ClaimsPrincipal: {claimsPrincipal}");
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
