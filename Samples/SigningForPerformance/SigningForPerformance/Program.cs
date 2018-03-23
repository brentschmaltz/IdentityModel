using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens.Jwt;

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
            var signingKey = new X509SecurityKey(new X509Certificate2( @"Certs\TestCert1.pfx", "TestCert1", X509KeyStorageFlags.MachineKeySet));
            var identity = new ClaimsIdentity( new List<Claim>{ new Claim( ClaimTypes.Name, "Bob" ) } );
            var tokenDescriptorWithoutSignatureProvider = new SecurityTokenDescriptor
            {
                Audience = "https://www.SigningForPerformance.com",
                Issuer = "https://SigningForPerformance.com",
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
                Subject = identity
            };

            var signatureProvider = CryptoProviderFactory.Default.CreateForSigning(signingKey, SecurityAlgorithms.RsaSha256);
            var tokenDescriptorWithSignatureProvider = new SecurityTokenDescriptor
            {
                Audience = "https://www.SigningForPerformance.com",
                Issuer = "https://SigningForPerformance.com",
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
                {
                    CryptoProviderFactory = new SigningForPerformanceCryptoProviderFactory(signatureProvider)
                },
                Subject = identity
            };

            // intialize runtime
            Iterations = 10;
            RunPerfTest(string.Empty, new JwtSecurityTokenHandler(), tokenDescriptorWithoutSignatureProvider);
            RunPerfTest(string.Empty, new JwtSecurityTokenHandler(), tokenDescriptorWithSignatureProvider);

            Iterations = 2000;
            RunPerfTest("Single SignatureProvider", new JwtSecurityTokenHandler(), tokenDescriptorWithSignatureProvider);
            RunPerfTest("Create SignatureProvider", new JwtSecurityTokenHandler(), tokenDescriptorWithoutSignatureProvider);

            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        static public int Iterations { get; set; }

        static void RunPerfTest(string description, JwtSecurityTokenHandler tokenHandler, SecurityTokenDescriptor tokenDescriptor)
        {
            var timeStart = DateTime.UtcNow;
            var jwtTokenHandler = tokenHandler ?? new JwtSecurityTokenHandler();
            for (int i = 0; i < Iterations; i++)
                jwtTokenHandler.CreateEncodedJwt(tokenDescriptor);

            if (!string.IsNullOrEmpty(description))
                Console.WriteLine($"{description}: Iterations: {Iterations}, Time: {DateTime.UtcNow - timeStart}.");
        }
    }
}
