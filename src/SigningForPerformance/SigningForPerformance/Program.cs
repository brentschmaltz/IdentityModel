using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace SigningForPerformance
{
    /// <summary>
    /// This sample shows how to use the same SignatureProvider for signing multiple jwts. The default behavior of JwtSecurityTokenHandler is to ask for a new SigningProvider every time
    /// a signature is requested.
    /// This sample shows two ways to use the same provider.
    /// 1. pass the signature provider to the handler on CreateToken. This a good solution if you use only one key.
    /// 2. use a custom SignatureProviderFactory to supply a provider that caches the provider based on 'key, algorithm'. This is handy if you have multiple keys or algorithms.
    /// </summary>
    class Program
    {        
        static void Main(string[] args)
        {
	    // big bug fix here
            X509Certificate2 signingCertificate = new X509Certificate2( @"Certs\SigningForPerformance.pfx", "SigningForPerformance" );            
            X509SigningCredentials signingCredentials = new X509SigningCredentials( signingCertificate );

            // Simple identity with one claim.
            ClaimsIdentity identity = new ClaimsIdentity( new List<Claim>{ new Claim( ClaimTypes.Name, "Bob" ) } );

            // for simplicity and reuse, use SecurityTokenDescriptor to package up variables.
            // Big bug fix in dev
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                                                      { 
                                                        AppliesToAddress = "https://www.SigningForPerformance.com", 
                                                        SigningCredentials = signingCredentials, 
                                                        Subject = identity, 
                                                        TokenIssuerName = "https://GotJwt.com" 
                                                      };
            SignatureProvider signatureProvider = (new SignatureProviderFactory()).CreateForSigning( signingCredentials.SigningKey, signingCredentials.SignatureAlgorithm );
            
            // intialize runtime
            RunPerfTest( 10, string.Empty, tokenDescriptor, signatureProvider: signatureProvider );
            RunPerfTest( 10, string.Empty, tokenDescriptor );

            // see what 5000 signatures takes.
            RunPerfTest( 5000, "Using single asymmetric signatureProvider", tokenDescriptor, signatureProvider: signatureProvider );
            RunPerfTest( 5000, "Creating asymmetric signature provider for each token.", tokenDescriptor );

            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        static void RunPerfTest(int numberOfIterations, string description, SecurityTokenDescriptor tokenDescriptor, SignatureProvider signatureProvider = null, SignatureProviderFactory signatureProviderFactory = null)
        {
            DateTime timeStart = DateTime.UtcNow;

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            if ( signatureProviderFactory != null )
            {
                jwtSecurityTokenHandler.SignatureProviderFactory = signatureProviderFactory;
            }

            if (signatureProvider == null)
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    JwtSecurityToken jwt = jwtSecurityTokenHandler.CreateToken( issuer: tokenDescriptor.TokenIssuerName, audience: tokenDescriptor.AppliesToAddress, subject: tokenDescriptor.Subject, signingCredentials: tokenDescriptor.SigningCredentials );
                }
            }
            else
            {
                for (int i = 0; i < numberOfIterations; i++)
                {
                    JwtSecurityToken jwt = jwtSecurityTokenHandler.CreateToken( issuer: tokenDescriptor.TokenIssuerName, audience: tokenDescriptor.AppliesToAddress, subject: tokenDescriptor.Subject, signatureProvider: signatureProvider );
                }
            }

            DateTime timeStop = DateTime.UtcNow;

            if (!string.IsNullOrEmpty( description ))
            {
                Console.WriteLine( "Test: '" + description + ".\nNumber of iterations: " + numberOfIterations.ToString() + ". Time: " + (timeStop - timeStart).ToString() + "." );
            }
        }
    }
}
