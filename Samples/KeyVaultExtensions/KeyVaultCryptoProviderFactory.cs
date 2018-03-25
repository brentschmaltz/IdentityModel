using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;

namespace KeyVaultExtensions
{
    /// <summary>
    /// A extension to <see cref="CryptoProviderFactory"/> that uses AzureAd Key Vault for Signing and Validating"/>
    /// </summary>
    public class KeyVaultCryptoProviderFactory : CryptoProviderFactory
    {
        private KeyVaultClient _keyVaultClient;
        private ClientCredential _clientCredential;

        public KeyVaultCryptoProviderFactory(string clientId, string clientSecret, string keyIdentifier)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));

            if (string.IsNullOrEmpty(clientSecret))
                throw new ArgumentNullException(nameof(clientSecret));

            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException(nameof(keyIdentifier));

            _clientCredential = new ClientCredential(clientId, clientSecret);
            _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessToken), new HttpClient());
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
    }
}
