using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AesGcm472
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string plainText = "Here is some plain text.";
                Aes aes = Aes.Create();
                AesGcm aesGcm = new AesGcm(aes.Key);
                // Get parameter sizes
                int nonceSize = AesGcm.NonceByteSizes.MaxSize;
                int tagSize = AesGcm.TagByteSizes.MaxSize;

                // We write everything into one big array for easier encoding
                byte[] nonce = new byte[nonceSize];
                byte[] tag = new byte[tagSize];

                // Generate secure nonce
                var random = RandomNumberGenerator.Create();
                random.GetBytes(nonce);

                string cipherText = Encrypt(plainText, aes.Key, nonce, tag);
                string clearText = Decrypt(cipherText, aes.Key, nonce, tag);
                Console.WriteLine($"plainText: '{plainText}'.");
                Console.WriteLine($"clearText: '{clearText}'.");
                Console.WriteLine($"base64EncodedCipherText: '{cipherText}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: '{ex}'");
            }

            Console.WriteLine("");
            Console.WriteLine("===================================");
            Console.WriteLine("Press a key to close");
            Console.ReadKey();
        }

        public static string Encrypt(string plain, byte[] key, byte[] nonce, byte[] tag)
        {
            // Get bytes of plaintext string
            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);

            // Get parameter sizes
            byte[] encryptedData = new byte[plainBytes.Length];

            // Encrypt
            var aes = new AesGcm(key);
            aes.Encrypt(nonce, plainBytes, encryptedData, tag, null);

            // Encode for transmission
            return Convert.ToBase64String(encryptedData.ToArray());
        }

        public static string Decrypt(string cipherText, byte[] key, byte[] nonce, byte[] tag)
        {
            byte[] encryptedData = Convert.FromBase64String(cipherText);
            byte[] clearBytes = new byte[encryptedData.Length];
            var aes = new AesGcm(key);
            aes.Decrypt(nonce, encryptedData, tag, clearBytes, null);

            // Convert plain bytes back into string
            return Encoding.UTF8.GetString(clearBytes);
        }
    }
}
