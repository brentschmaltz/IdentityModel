using System;
using System.Security.Cryptography;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Tokens;

namespace ExtendingCryptoSupport
{
    public class KeyVaultSignatureProvider : SignatureProvider
    {
        private SHA256 _hash;
        private KeyVaultClient _keyVaultClient;
        private KeyVaultSecurityKey _keyVaultSecurityKey;

        public KeyVaultSignatureProvider(KeyVaultSecurityKey key, string algorithm, KeyVaultClient keyVaultClient)
            : base(key, algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException(nameof(algorithm));

            if (!Algorithm.Equals(SecurityAlgorithms.RsaSha256))
                throw new ArgumentException($"Only {SecurityAlgorithms.RsaSha256} is supported. algorithm == {algorithm}.");

            _hash = SHA256.Create();
            _keyVaultSecurityKey = key;
            _keyVaultClient = keyVaultClient;
        }

        public override byte[] Sign(byte[] input)
        {
            byte[] digest = _hash.ComputeHash(input);

            KeyOperationResult signature = _keyVaultClient.SignAsync(
                _keyVaultSecurityKey.KeyId,
                Algorithm,
                digest
                ).GetAwaiter().GetResult();

            return signature.Result;
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            byte[] digest = _hash.ComputeHash(input);
            var verifyResult = _keyVaultClient.VerifyAsync(
                _keyVaultSecurityKey.KeyId,
                Algorithm,
                digest,
                signature).GetAwaiter().GetResult();

            return verifyResult;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
