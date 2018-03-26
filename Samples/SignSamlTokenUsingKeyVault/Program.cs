using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using KeyVaultExtensions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;

namespace SignSamlTokenUsingKeyVault
{
    class Program
    {
        // KeyVault information
        // The secret needed to obtain AccessToken for KeyVault
        private static string Base64EncodedSecrect { get => "<put secret here>"; }

        // ClientId of an application that has permissions to KeyVault
        private static string ClientId { get => "<put clientid here>"; }

        // Uri of the KeyIdentifier for KeyVault
        private static string KeyVaultKeyId { get => "<put key identifier (uri) here>"; }

        // TokenCreation information
        // properties for SamlSecurityToken creation and validation
        private static string Audience { get => @"http://audience"; }
        private static string Issuer { get => @"http://issuer"; }

        static void Main(string[] args)
        {
            // set log and exception messages to have full info.
            IdentityModelEventSource.ShowPII = true;

            // SamlToken is created specifying public key so that KeyInfo will be written correctly
            var publicCert = new X509Certificate2(@"<put path to public 'cer' file here>");
            var publicKey = new X509SecurityKey(publicCert)
            {
                // Attach KeyVault aware CryptoProviderFactory
                CryptoProviderFactory = new KeyVaultCryptoProviderFactory(ClientId, Base64EncodedSecrect, KeyVaultKeyId)
            };

            // Validate Token with public key that matches the one from KeyVault
            try
            {
                // SamlToken is created specifying public key so that KeyInfo will be written correctly
                var samlToken = CreateSamlToken(publicKey);
                Console.WriteLine($"Created SamlToken: {samlToken}");

                // Validate SamlToken using public key and normal crypto providers
                var validationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new X509SecurityKey(publicCert),
                    ValidAudience = Audience,
                    ValidIssuer = Issuer
                };
                var tokenHandler = new SamlSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(samlToken, validationParameters, out SecurityToken validatedToken);
                Console.WriteLine($"Validated ClaimsPrincipal: {principal}");

            }
            catch(Exception ex)
            {
                Console.WriteLine($"Creating / Validating SamlToken threw exception: {ex}");
            }

            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        /// <summary>
        /// Create a signed <see cref="SamlSecurityToken"/> using a <see cref="SecurityTokenDescriptor"/>
        /// </summary>
        /// <returns>the <see cref="SamlSecurityToken"/> serialized as a string.</returns>
        public static string CreateSamlToken(SecurityKey signingKey)
        {
            // Set the Audience, Issuer
            // SigningCredentials is used to provide key material and definition of signature and digest algorithms
            // Subject contains claims to place in token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = Audience,
                Issuer = Issuer,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256),
                Subject = new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Email, "bob@foo.com") })
            };

            var tokenHandler = new SamlSecurityTokenHandler();
            var samlToken = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(samlToken);
        }
    }
}
