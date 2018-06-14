//
// Shows how to extend crypto support to an external crypto provider.
// This sample show how to Sign a SamlToken using KeyVault
// using IdentityModel: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet 
//

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;

namespace ExtendingCryptoSupport
{
    class Program
    {
        static ClientCredential _clientCredential;
        static KeyVaultClient keyVaultClient;

        static void Main(string[] args)
        {
            var keyVaultUrl = "";
            var clientId = "";
            var clientSecret = "";
            _clientCredential = new ClientCredential(clientId, clientSecret);
            var keyVaultCryptoProviderFactory = new KeyVaultCryptoProviderFactory(clientId, clientSecret, keyVaultUrl);
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessToken), GetHttpClient());
            var keyVaultKey = new KeyVaultSecurityKey("");
            keyVaultKey.CryptoProviderFactory = keyVaultCryptoProviderFactory;

            // this same certificate has been added to keyvault
            var cert = new X509Certificate2();
            var tokenHandler = new JwtSecurityTokenHandler();

            var localSignedJwt = tokenHandler.CreateEncodedJwt(SecurityTokenDescriptor(new X509SecurityKey(cert)));
            var keyVaultSignedJwt = tokenHandler.CreateEncodedJwt(SecurityTokenDescriptor(keyVaultKey));

            try
            {
                SecurityToken localSignedToken = null;
                tokenHandler.ValidateToken(localSignedJwt, TokenValidationParameters(new X509SecurityKey(cert)), out localSignedToken);
                Console.WriteLine($"localSignedToken (validated using KeyVault): \n{localSignedToken}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Validating: localSignedToken threw {ex}");
            }

            try
            {
                SecurityToken keyVaultSignedToken = null;
                tokenHandler.ValidateToken(keyVaultSignedJwt, TokenValidationParameters(keyVaultKey), out keyVaultSignedToken);
                Console.WriteLine($"keyVaultSignedToken: \n{keyVaultSignedToken}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Validating: keyVaultSignedJwt threw {ex}");
            }

            try
            {
                SecurityToken keyVaultSignedToken = null;
                tokenHandler.ValidateToken(keyVaultSignedJwt, TokenValidationParameters(new X509SecurityKey(cert)), out keyVaultSignedToken);
                Console.WriteLine($"keyVaultSignedToken (validating with local cert): \n{keyVaultSignedToken}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Validating: keyVaultSignedJwt (validating with local cert) threw {ex}");
            }

            Console.WriteLine("Press a key...");
            Console.ReadKey();
        }

        public static string Audience { get { return "KeyVault.Client"; } }

        public static ClaimsIdentity Identity
        {
            get
            {
                return new ClaimsIdentity(
                    new List<Claim>
                    {
                        new Claim("name", "bob"),
                        new Claim("sub", "subject"),
                        new Claim("iss", Issuer)
                    });
            }
        }

        public static string Issuer { get { return "cyrano.onmicrosoft.com"; } }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(SecurityKey key)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Audience,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
                Subject = Identity
            };
        }

        public static TokenValidationParameters TokenValidationParameters(SecurityKey key)
        {
            return new TokenValidationParameters
            {
                IssuerSigningKey = key,
                ValidAudience = Audience,
                ValidIssuer = Issuer,
            };
        }

        /// <summary>
        /// Gets the access token
        /// </summary>
        /// <param name="authority"> Authority </param>
        /// <param name="resource"> Resource </param>
        /// <param name="scope"> scope </param>
        /// <returns> token </returns>
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, _clientCredential);

            return result.AccessToken;
        }

        /// <summary>
        /// Create an HttpClient object that optionally includes logic to override the HOST header
        /// field for advanced testing purposes.
        /// </summary>
        /// <returns>HttpClient instance to use for Key Vault service communication</returns>
        private static HttpClient GetHttpClient()
        {
            return (HttpClientFactory.Create(new InjectHostHeaderHttpMessageHandler()));
        }
    }
}
}
