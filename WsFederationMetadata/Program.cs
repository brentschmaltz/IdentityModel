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
    }
}
