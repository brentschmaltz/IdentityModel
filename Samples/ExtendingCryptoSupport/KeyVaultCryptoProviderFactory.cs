using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;

namespace ExtendingCryptoSupport
{
    public class KeyVaultCryptoProviderFactory : CryptoProviderFactory
    {
        private string _keyId;
        private KeyVaultClient _keyVaultClient;
        private string _clientId;
        private string _clientSecret;
        private string _baseUrl;
        private ClientCredential _clientCredential;

        public KeyVaultCryptoProviderFactory(string clientId, string clientSecret, string baseUrl)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _clientCredential = new ClientCredential(clientId, clientSecret);
            _baseUrl = baseUrl;
            _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessToken), GetHttpClient());
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return new KeyVaultSignatureProvider(key as KeyVaultSecurityKey, algorithm, _keyVaultClient);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return new KeyVaultSignatureProvider(key as KeyVaultSecurityKey, algorithm, _keyVaultClient);
        }

        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            base.ReleaseSignatureProvider(signatureProvider);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return true;
        }

        /// <summary>
        /// Gets the access token
        /// </summary>
        /// <param name="authority"> Authority </param>
        /// <param name="resource"> Resource </param>
        /// <param name="scope"> scope </param>
        /// <returns> token </returns>
        private async Task<string> GetAccessToken(string authority, string resource, string scope)
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
        private HttpClient GetHttpClient()
        {
            return (HttpClientFactory.Create(new InjectHostHeaderHttpMessageHandler()));
        }
    }
}
