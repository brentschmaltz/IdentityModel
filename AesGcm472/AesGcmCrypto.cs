using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AesGcm472
{
    public class AesGcm : IDisposable
    {
        private const int NonceSize = 12;
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(12, 16, 1);
        private static readonly SafeAlgorithmHandle s_aesGcm = AesBCryptModes.OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_GCM).Value;
        private SafeKeyHandle _keyHandle;
        public AesGcm(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            AesAEAD.CheckKeySize(key.Length * 8);
            ImportKey(key);
        }

        private void ImportKey(byte[] key)
        {
            _keyHandle = Interop.BCrypt.BCryptImportKey(s_aesGcm, key);
        }

        private void EncryptInternal(
            byte[] nonce,
            byte[] plaintext,
            byte[] ciphertext,
            byte[] tag,
            byte[] associatedData = default)
        {
            AesAEAD.Encrypt(s_aesGcm, _keyHandle, nonce, associatedData, plaintext, ciphertext, tag);
        }

        private void DecryptInternal(
            byte[] nonce,
            byte[] ciphertext,
            byte[] tag,
            byte[] plaintext,
            byte[] associatedData = default)
        {
            AesAEAD.Decrypt(s_aesGcm, _keyHandle, nonce, associatedData, ciphertext, tag, plaintext, clearPlaintextOnFailure: true);
        }

        public void Dispose()
        {
            _keyHandle.Dispose();
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            EncryptInternal(nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            DecryptInternal(nonce, ciphertext, tag, plaintext, associatedData);
        }
    }
}
