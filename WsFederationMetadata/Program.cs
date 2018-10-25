//
// Shows how to  validate a SamlToken obtaining metadata from an authority
// using IdentityModel: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet 
//

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;

namespace WsFederationMetadata
{
    class Program
    {
        static void Main(string[] args)
        {
            var clientId = "<put clientid here>";
            var configurationManager = new ConfigurationManager<WsFederationConfiguration>(
                "https://login.microsoftonline.com/common/FederationMetadata/2007-06/FederationMetadata.xml",
                new WsFederationConfigurationRetriever());

            var wsFedConfiguration = configurationManager.GetConfigurationAsync().GetAwaiter().GetResult();
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = wsFedConfiguration.SigningKeys,
                IssuerSigningKeyValidator = IssuerSigningKeyValidator,
                ValidAudience = clientId,
                ValidIssuer = wsFedConfiguration.Issuer
            };

            var samlToken = "<put saml token here>";
            var samlTokenHandler = new SamlSecurityTokenHandler();
            var claimsPrincipal = samlTokenHandler.ValidateToken(
                                    samlToken,
                                    validationParameters, 
                                    out SecurityToken samlSecurityToken);
        }

        private static bool IssuerSigningKeyValidator(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityKey is X509SecurityKey x509SecurityKey)
            {
                // compare x509SecurityKey.Certificate
                //< add thumbprint = "022d5e4993a87c2d693bf01912a8333d5ff58df8" name = "identityserver1.mycompany.net" />
                //< add thumbprint = "c58a90087a548d4c1bc1e609a9caa658e916ca83" name = "identityserver2.mycompany.net" />
            }

            return true;
        }
    }
}
