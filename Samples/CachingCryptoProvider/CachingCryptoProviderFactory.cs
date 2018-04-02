using System.Collections.Concurrent;
using Microsoft.IdentityModel.Tokens;

namespace CachingCryptoProvider
{
    /// <summary>
    /// Extends <see cref="CryptoProviderFactory"/> to cache a <see cref="SignatureProvider"/> by key-algorithm
    /// This can improve performance as each <see cref="SignatureProvider"/> can be used multiple times.
    /// </summary>
    public class CachingCryptoProviderFactory : CryptoProviderFactory
    {
        // two caches for 
        private ConcurrentDictionary<string, SignatureProvider> _signingCache = new ConcurrentDictionary<string, SignatureProvider>();
        private ConcurrentDictionary<string, SignatureProvider> _verifyingCache = new ConcurrentDictionary<string, SignatureProvider>();

        /// <summary>
        /// Instaintates a CryptoProviderFactory that caches <see cref="SignatureProvider> for Signing and Verifying
        /// </summary>
        public CachingCryptoProviderFactory()
        {
        }

        /// <summary>
        /// Looks into cache for existing <see cref="SignatureProvider"/> returns it if found. 
        /// Calls base to create a new one if not found.
        /// </summary>
        /// <param name="key">the security key to use for a KeyId. this key is not used.</param>
        /// <param name="algorithm">the <see cref="SecurityAlgorithms"/> to use must be RS256</param>
        /// <returns>a <see cref="SignatureProvider"/></returns>
        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            var cacheKey = $"{key.GetType().ToString()}-{algorithm}";
            if (_signingCache.TryGetValue(cacheKey, out SignatureProvider signatureProvider))
                return signatureProvider;
            else
                signatureProvider = base.CreateForSigning(key, algorithm);

            _signingCache[cacheKey] = signatureProvider;
            return signatureProvider;
        }

        /// <summary>
        /// Looks into cache for existing <see cref="SignatureProvider"/> returns it if found. 
        /// Calls base to create a new one if not found.
        /// </summary>
        /// <param name="key">the security key to use for a KeyId. this key is not used.</param>
        /// <param name="algorithm">the <see cref="SecurityAlgorithms"/> to use must be RS256</param>
        /// <returns>a <see cref="SignatureProvider"/></returns>
        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            var cacheKey = $"{key.GetType().ToString()}-{algorithm}";
            if (_verifyingCache.TryGetValue(cacheKey, out SignatureProvider signatureProvider))
                return signatureProvider;
            else
                signatureProvider = base.CreateForVerifying(key, algorithm);

            _verifyingCache[cacheKey] = signatureProvider;
            return signatureProvider;
        }

        /// <summary>
        /// Returns if algorithm / key pair is supported
        /// </summary>
        /// <param name="algorithm">signature algorithm to use</param>
        /// <param name="key">key to use</param>
        /// <returns>true if supported</returns>
        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return base.IsSupportedAlgorithm(algorithm, key);
        }

        /// <summary>
        /// Call this method once, when the application is closing.
        /// All <see cref="SignatureProvider"/> will be release and caches cleared.
        /// </summary>
        public void Release()
        {
            foreach (var signatureProvider in _signingCache.Values)
                signatureProvider.Dispose();

            _signingCache.Clear();

            foreach (var signatureProvider in _verifyingCache.Values)
                signatureProvider.Dispose();

            _verifyingCache.Clear();
        }

        /// <summary>
        /// Called by some runtimes to release signature provider.
        /// Override with a no-op. Call Release before exiting application.
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to release</param>
        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {            
        }
    }
}
