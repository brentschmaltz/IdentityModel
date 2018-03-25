using System;
using KeyVaultExtensions;
using Microsoft.IdentityModel.Tokens;

namespace SignSamlTokenUsingKeyVault
{
    class Program
    {
        static void Main(string[] args)
        {
            var keyVaultKey = new KeyVaultSecurityKey();
            var signingProvider = keyVaultKey.CryptoProviderFactory.CreateForSigning(keyVaultKey, SecurityAlgorithms.RsaSha256);
            var bytes = new byte[256];
            var signedBytes = signingProvider.Sign(bytes);
            Console.WriteLine("Hello World!");
        }
    }
}
