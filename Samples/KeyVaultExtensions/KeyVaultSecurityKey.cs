using System;
using Microsoft.IdentityModel.Tokens;

namespace KeyVaultExtensions
{
    /// <summary>
    /// Provides a hook into using KeyVault
    /// </summary>
    public class KeyVaultSecurityKey : SecurityKey
    {
        /// <summary>
        /// Constructor for KeyVaultSecurityKey
        /// </summary>
        /// <param name="clientId">clientid of the application registered to use keyvault</param>
        /// <param name="clientSecret">secret needed to get access token for keyvault</param>
        /// <param name="keyIdentifier">KeyVault key identifier</param>
        public KeyVaultSecurityKey(string clientId, string clientSecret, string keyIdentifier)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));

            if (string.IsNullOrEmpty(clientSecret))
                throw new ArgumentNullException(nameof(clientSecret));

            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException(nameof(keyIdentifier));

            KeyId = keyIdentifier;
            ClientId = clientId;
            ClientSecret = clientSecret;
            KeyIdentifier = keyIdentifier;
            CryptoProviderFactory = new KeyVaultCryptoProviderFactory(clientId, clientSecret, keyIdentifier);
        }
            
        public string ClientId { get; private set; }

        public string ClientSecret { get; private set; }

        public string KeyIdentifier { get; private set; }

        /// <summary>
        /// What is the key size
        /// </summary>
        public override int KeySize
        {
            get
            {
                // TODO how do we figure out the size?
                return 2048;
            }
        }
    }
}
