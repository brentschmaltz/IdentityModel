//
// Shows how to sign and validate a JWT using cached SignatureProviders
// using IdentityModel: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet
// By caching SignatureProviders, there will be fewer creation of crypto operators. Performance will increase
//

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using CachingCryptoProvider;
using IdentityModelSampleUtilities;
using Microsoft.IdentityModel.Tokens;

namespace SignAndVerifyJwtUsingCachedProviders
{
    class Program
    {
        static void Main(string[] args)
        {
            var issuer = "http://issuer.com";
            var audience = "http://audience.com";
            var claimsIdentity = new ClaimsIdentity(new Claim[] { new Claim("claimtype", "claimValue", issuer) });
            var tokenHandler = new JwtSecurityTokenHandler();
            var cachingCryptoProviderFactory = new CachingCryptoProviderFactory();

            // create token
            var signingCredentials = new SigningCredentials(KeyMaterial.X509SecurityKeyWithPrivateKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = cachingCryptoProviderFactory
            };

            var jwt = tokenHandler.CreateEncodedJwt(
                issuer,
                audience,
                claimsIdentity,
                DateTime.UtcNow,
                DateTime.UtcNow + TimeSpan.FromDays(1),
                DateTime.UtcNow,
                signingCredentials
                );

            // second creation will not create new crypto operator
            jwt = tokenHandler.CreateEncodedJwt(
                issuer,
                audience,
                claimsIdentity,
                DateTime.UtcNow,
                DateTime.UtcNow + TimeSpan.FromDays(1),
                DateTime.UtcNow,
                signingCredentials
                );

            // validate token
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = KeyMaterial.X509SecurityKeyWithPublicKey,
                ValidAudience = audience,
                ValidIssuer = issuer,
                CryptoProviderFactory = cachingCryptoProviderFactory
            };

            var claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out SecurityToken securityToken);

            // second call will not create a new crypto operator
            claimsPrincipal = tokenHandler.ValidateToken(jwt, validationParameters, out securityToken);

            // release crypto operators
            cachingCryptoProviderFactory.Release();
        }
    }
}
