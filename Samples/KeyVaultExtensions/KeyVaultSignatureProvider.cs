using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace KeyVaultExtensions
{
    /// <summary>
    /// A extension to <see cref="SignatureProvider"/> that uses AzureAd Key Vault for Signing and Validating"/>
    /// </summary>
    public class KeyVaultSignatureProvider : SignatureProvider
    {
        private KeyVaultClient _keyVaultClient;
        private string _keyVaultKeyIdentifier;

        /// <summary>
        /// Instaintates a SignatureProvider that delegates to KeyVault for Signing and Verifying signatures
        /// </summary>
        /// <param name="key">the SecurityKey that contains keyid only. Not used.</param>
        /// <param name="algorithm">the algorithm to use. Must be RS256</param>
        /// <param name="keyVaultClient">used to obtain key vault services</param>
        /// <param name="keyVaultKeyIdentifier">the uri identifier of the key</param>

        public KeyVaultSignatureProvider(SecurityKey key, string algorithm, KeyVaultClient keyVaultClient, string keyVaultKeyIdentifier)
            : base(key, algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException(nameof(algorithm));

            if (!Algorithm.Equals(SecurityAlgorithms.RsaSha256))
                throw new ArgumentException($"Only {SecurityAlgorithms.RsaSha256} is supported. algorithm == {algorithm}.");

            if (string.IsNullOrEmpty(keyVaultKeyIdentifier))
                throw new ArgumentNullException(nameof(keyVaultKeyIdentifier));

            _keyVaultClient = keyVaultClient ?? throw new ArgumentNullException(nameof(keyVaultClient));
            _keyVaultKeyIdentifier = keyVaultKeyIdentifier;
        }

        /// <summary>
        /// Creates the signature over a set of bytes
        /// </summary>
        /// <param name="input">the bytes to sign</param>
        /// <returns>the signature as bytes</returns>
        public override byte[] Sign(byte[] input)
        {
            using (var hash = SHA256.Create())
            {
                return (_keyVaultClient.SignAsync(
                    _keyVaultKeyIdentifier,
                    Algorithm,
                    hash.ComputeHash(input)
                    ).GetAwaiter().GetResult()).Result;
            }
        }

        /// <summary>
        /// Verifies the input is equal to the signautre using key vault
        /// </summary>
        /// <param name="input">the bytes to verigy</param>
        /// <param name="signature">the signature to verify</param>
        /// <returns>true or false if signature matches</returns>
        public override bool Verify(byte[] input, byte[] signature)
        {
            using (var hash = SHA256.Create())
            {
                return _keyVaultClient.VerifyAsync(
                    _keyVaultKeyIdentifier,
                    Algorithm,
                    hash.ComputeHash(input),
                    signature).GetAwaiter().GetResult();
            }
        }

        /// <summary>
        /// Called when cleaning up. No-op
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
        }
    }
}
