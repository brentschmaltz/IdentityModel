using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CreateTokens
{
    /// <summary>
    /// Creating JwtTokens with symmetric and asymmetric keys
    /// Using JsonWebToken
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // handler will be reused
            var tokenHandler = new JsonWebTokenHandler();

            // create JWT using SecurityTokenDescriptor
            // first case just sign
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = "microsoft.com",
                Claims = new Dictionary<string, object>
                {
                    {JwtRegisteredClaimNames.Email, "bob@contoso.com" },
                    {JwtRegisteredClaimNames.GivenName, "bob"},
                },
                Issuer = "contoso.com",
                SigningCredentials = new SigningCredentials(KeyMaterial.SymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256)
            };

            var jwsSymmetric = tokenHandler.CreateToken(securityTokenDescriptor);

            // encrypt using shared secret
            securityTokenDescriptor.EncryptingCredentials = new EncryptingCredentials(KeyMaterial.SymmetricSecurityKey_256, "dir", SecurityAlgorithms.Aes128CbcHmacSha256);
            var jweSymmetric = tokenHandler.CreateToken(securityTokenDescriptor);

            // encrypt with recipients public key to wrap a key that encrypts the payload. Decrypt using private key.
            securityTokenDescriptor.EncryptingCredentials = new EncryptingCredentials(KeyMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
            var jweAymmetric = tokenHandler.CreateToken(securityTokenDescriptor);

            Console.WriteLine("CreateTokens completed. If no exceptions, all went well.");
            Console.WriteLine("Press any key to close");
            Console.ReadKey();
        }
    }
}
