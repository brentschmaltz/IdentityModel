using Microsoft.IdentityModel.Tokens;

namespace SigningForPerformance
{
    public class SigningForPerformanceCryptoProviderFactory : CryptoProviderFactory
    {
        private SignatureProvider _signatureProvider;

        public SigningForPerformanceCryptoProviderFactory(SignatureProvider signatureProvider)
        {
            _signatureProvider = signatureProvider;
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return _signatureProvider;
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return _signatureProvider;
        }

        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
        }
    }
}
