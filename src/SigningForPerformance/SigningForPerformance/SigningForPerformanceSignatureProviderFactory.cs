using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SigningForPerformance
{
    public class SigningForPerformanceSignatureProviderFactory : SignatureProviderFactory
    {
        Dictionary<KeyValuePair<SecurityKey, string>, SignatureProvider> signatureProviders;

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return base.CreateForSigning(key, algorithm);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return base.CreateForVerifying(key, algorithm);
        }

        public override void ReleaseProvider(SignatureProvider signatureProvider)
        {
            base.ReleaseProvider(signatureProvider);
        }
    }
}
