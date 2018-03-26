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
        private ClientCredential _clientCredential;
        private KeyVaultClient _keyVaultClient;
        private string _keyVaultKeyIdentifier;

        /// <summary>
        /// Instaintates a CryptoProviderFactory that delegates to KeyVault for Signing and Verifying signatures
        /// </summary>
        /// <param name="clientId">the client that has permissions to access KeyVault</param>
        /// <param name="clientSecret">the base64encoded secret to show proof when obtaining access token</param>
        /// <param name="keyIdentifier">the uri identifier of the key</param>
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
            _keyVaultKeyIdentifier = keyIdentifier;
        }

        /// <summary>
        /// Creates a new signature provider that delegates to KeyVault for Signing
        /// </summary>
        /// <param name="key">the security key to use for a KeyId. this key is not used.</param>
        /// <param name="algorithm">the <see cref="SecurityAlgorithms"/> to use must be RS256</param>
        /// <returns>a <see cref="KeyVaultSignatureProvider"/></returns>
        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return new KeyVaultSignatureProvider(key, algorithm, _keyVaultClient, _keyVaultKeyIdentifier);
        }

        /// <summary>
        /// Creates a new signature provider that delegates to KeyVault for verifying
        /// </summary>
        /// <param name="key">the security key to use for a KeyId. this key is not used.</param>
        /// <param name="algorithm">the <see cref="SecurityAlgorithms"/> to use must be RS256</param>
        /// <returns>a <see cref="KeyVaultSignatureProvider"/></returns>
        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return new KeyVaultSignatureProvider(key, algorithm, _keyVaultClient, _keyVaultKeyIdentifier);
        }

        /// <summary>
        /// Called when signature has been completed
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to release</param>
        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            signatureProvider.Dispose();
        }

        /// <summary>
        /// Returns if algorithm / key pair is supported
        /// </summary>
        /// <param name="algorithm">signature algorithm to use</param>
        /// <param name="key">key to use</param>
        /// <returns></returns>
        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (string.IsNullOrEmpty(algorithm) || key == null)
                return false;

            if (key is X509SecurityKey && algorithm.Equals(SecurityAlgorithms.RsaSha256))
                return true;

            return false;
        }

        /// <summary>
        /// Gets the access token required for KeyVault
        /// </summary>
        /// <param name="authority">the authority from which to obtain token</param>
        /// <param name="resource">the resource associatied with the key</param>
        /// <param name="scope">scope  not used</param>
        /// <returns>access token for key vault</returns>
        private async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, _clientCredential);
            return result.AccessToken;
        }
    }
}
