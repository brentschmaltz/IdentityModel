using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AesGcm472
{
    internal static class KeySizeHelpers
    {
        public static KeySizes[] CloneKeySizesArray(this KeySizes[] src)
        {
            return (KeySizes[])(src.Clone());
        }

        public static bool IsLegalSize(this int size, KeySizes legalSizes)
        {
            return size.IsLegalSize(legalSizes, out _);
        }

        public static bool IsLegalSize(this int size, KeySizes[] legalSizes)
        {
            return size.IsLegalSize(legalSizes, out _);
        }

        public static bool IsLegalSize(this int size, KeySizes legalSizes, out bool validatedByZeroSkipSizeKeySizes)
        {
            validatedByZeroSkipSizeKeySizes = false;

            // If a cipher has only one valid key size, MinSize == MaxSize and SkipSize will be 0
            if (legalSizes.SkipSize == 0)
            {
                if (legalSizes.MinSize == size)
                {
                    // Signal that we were validated by a 0-skipsize KeySizes entry. Needed to preserve a very obscure
                    // piece of back-compat behavior.
                    validatedByZeroSkipSizeKeySizes = true;
                    return true;
                }
            }
            else if (size >= legalSizes.MinSize && size <= legalSizes.MaxSize)
            {
                // If the number is in range, check to see if it's a legal increment above MinSize
                int delta = size - legalSizes.MinSize;

                // While it would be unusual to see KeySizes { 10, 20, 5 } and { 11, 14, 1 }, it could happen.
                // So don't return false just because this one doesn't match.
                if (delta % legalSizes.SkipSize == 0)
                {
                    return true;
                }
            }

            return false;
        }

        public static bool IsLegalSize(this int size, KeySizes[] legalSizes, out bool validatedByZeroSkipSizeKeySizes)
        {
            for (int i = 0; i < legalSizes.Length; i++)
            {
                if (size.IsLegalSize(legalSizes[i], out validatedByZeroSkipSizeKeySizes))
                {
                    return true;
                }
            }

            validatedByZeroSkipSizeKeySizes = false;
            return false;
        }
    }

    internal static class CryptoThrowHelper
    {
        public static CryptographicException ToCryptographicException(this int hr)
        {
            string message = Interop.Kernel32.GetMessage(hr);

            if ((hr & 0x80000000) != 0x80000000)
                hr = (hr & 0x0000FFFF) | unchecked((int)0x80070000);

            return new WindowsCryptographicException(hr, message);
        }

        private sealed class WindowsCryptographicException : CryptographicException
        {
            public WindowsCryptographicException(int hr, string message)
                : base(message)
            {
                HResult = hr;
            }
        }
    }

    internal static class BCryptPropertyStrings
    {
        internal const string BCRYPT_CHAINING_MODE = "ChainingMode";
        internal const string BCRYPT_ECC_PARAMETERS = "ECCParameters";
        internal const string BCRYPT_EFFECTIVE_KEY_LENGTH = "EffectiveKeyLength";
        internal const string BCRYPT_HASH_LENGTH = "HashDigestLength";
        internal const string BCRYPT_MESSAGE_BLOCK_LENGTH = "MessageBlockLength";
    }

    internal static class AesBCryptModes
    {
        private static readonly Lazy<SafeAlgorithmHandle> s_hAlgCbc = OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_CBC);
        private static readonly Lazy<SafeAlgorithmHandle> s_hAlgEcb = OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_ECB);
        private static readonly Lazy<SafeAlgorithmHandle> s_hAlgCfb128 = OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_CFB, 16);
        private static readonly Lazy<SafeAlgorithmHandle> s_hAlgCfb8 = OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_CFB, 1);

        internal static SafeAlgorithmHandle GetSharedHandle(CipherMode cipherMode, int feedback)
        {
            if (cipherMode == CipherMode.CBC)
                return s_hAlgCbc.Value;

            if (cipherMode == CipherMode.ECB)
                return s_hAlgEcb.Value;

            if (cipherMode == CipherMode.CFB && feedback == 16)
                return s_hAlgCfb128.Value;

            if (cipherMode == CipherMode.CFB && feedback == 1)
                return s_hAlgCfb8.Value;

            throw new NotSupportedException();
        }

        internal static Lazy<SafeAlgorithmHandle> OpenAesAlgorithm(string cipherMode, int feedback = 0)
        {
            return new Lazy<SafeAlgorithmHandle>(() =>
            {
                SafeAlgorithmHandle hAlg = Cng.BCryptOpenAlgorithmProvider(Cng.BCRYPT_AES_ALGORITHM, null, Cng.OpenAlgorithmProviderFlags.NONE);
                hAlg.SetCipherMode(cipherMode);

                // feedback is in bytes!
                // The default feedback size is 1 (CFB8) on Windows. Do not set the CNG property
                // if we would be setting it to the default. Windows 7 only supports CFB8 and
                // does not permit setting the feedback size, so we don't call the property
                // setter at all in that case.
                if (feedback > 0 && feedback != 1)
                {
                    try
                    {
                        hAlg.SetFeedbackSize(feedback);
                    }
                    catch (CryptographicException ex)
                    {
                        throw new CryptographicException("SR.Cryptography_FeedbackSizeNotSupported", ex);
                    }
                }

                return hAlg;
            });
        }
    }

    public static class CryptographicOperations
    {
        /// <summary>
        /// Determine the equality of two byte sequences in an amount of time which depends on
        /// the length of the sequences, but not the values.
        /// </summary>
        /// <param name="left">The first buffer to compare.</param>
        /// <param name="right">The second buffer to compare.</param>
        /// <returns>
        ///   <c>true</c> if <paramref name="left"/> and <paramref name="right"/> have the same
        ///   values for <see cref="ReadOnlySpan{T}.Length"/> and the same contents, <c>false</c>
        ///   otherwise.
        /// </returns>
        /// <remarks>
        ///   This method compares two buffers' contents for equality in a manner which does not
        ///   leak timing information, making it ideal for use within cryptographic routines.
        ///   This method will short-circuit and return <c>false</c> only if <paramref name="left"/>
        ///   and <paramref name="right"/> have different lengths.
        ///
        ///   Fixed-time behavior is guaranteed in all other cases, including if <paramref name="left"/>
        ///   and <paramref name="right"/> reference the same address.
        /// </remarks>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroMemory(byte[] buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is unnecessary
            // NoInlining to prevent the inliner from forgetting that the method was no-optimize
            Array.Clear(buffer, 0, buffer.Length);
        }
    }

    //
    // Interop layer around Windows CNG api.
    //
    internal static class Cng
    {
        [Flags]
        public enum OpenAlgorithmProviderFlags : int
        {
            NONE = 0x00000000,
            BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008,
        }

        public const string BCRYPT_3DES_ALGORITHM = "3DES";
        public const string BCRYPT_AES_ALGORITHM = "AES";
        public const string BCRYPT_DES_ALGORITHM = "DES";
        public const string BCRYPT_RC2_ALGORITHM = "RC2";

        public const string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        public const string BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB";
        public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public const string BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB";
        public const string BCRYPT_CHAIN_MODE_CCM = "ChainingModeCCM";

        public static SafeAlgorithmHandle BCryptOpenAlgorithmProvider(string pszAlgId, string pszImplementation, OpenAlgorithmProviderFlags dwFlags)
        {
            SafeAlgorithmHandle hAlgorithm;
            NTSTATUS ntStatus = Interop.BCryptOpenAlgorithmProvider(out hAlgorithm, pszAlgId, pszImplementation, (int)dwFlags);
            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                throw CreateCryptographicException(ntStatus);
            return hAlgorithm;
        }

        public static void SetFeedbackSize(this SafeAlgorithmHandle hAlg, int dwFeedbackSize)
        {
            NTSTATUS ntStatus = Interop.BCryptSetIntProperty(hAlg, BCryptPropertyStrings.BCRYPT_MESSAGE_BLOCK_LENGTH, ref dwFeedbackSize, 0);

            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
            {
                throw CreateCryptographicException(ntStatus);
            }
        }

        public static void SetCipherMode(this SafeAlgorithmHandle hAlg, string cipherMode)
        {
            NTSTATUS ntStatus = Interop.BCryptSetProperty(hAlg, BCryptPropertyStrings.BCRYPT_CHAINING_MODE, cipherMode, (cipherMode.Length + 1) * 2, 0);

            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
            {
                throw CreateCryptographicException(ntStatus);
            }
        }

        public static void SetEffectiveKeyLength(this SafeAlgorithmHandle hAlg, int effectiveKeyLength)
        {
            NTSTATUS ntStatus = Interop.BCryptSetIntProperty(hAlg, BCryptPropertyStrings.BCRYPT_EFFECTIVE_KEY_LENGTH, ref effectiveKeyLength, 0);

            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
            {
                throw CreateCryptographicException(ntStatus);
            }
        }

        private static Exception CreateCryptographicException(NTSTATUS ntStatus)
        {
            int hr = ((int)ntStatus) | 0x01000000;
            return hr.ToCryptographicException();
        }

        internal static class Interop
        {
            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
            public static extern NTSTATUS BCryptOpenAlgorithmProvider(out SafeAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
            public static extern NTSTATUS BCryptSetProperty(SafeAlgorithmHandle hObject, string pszProperty, string pbInput, int cbInput, int dwFlags);

            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode, EntryPoint = "BCryptSetProperty")]
            private static extern NTSTATUS BCryptSetIntPropertyPrivate(SafeBCryptHandle hObject, string pszProperty, ref int pdwInput, int cbInput, int dwFlags);

            public static unsafe NTSTATUS BCryptSetIntProperty(SafeBCryptHandle hObject, string pszProperty, ref int pdwInput, int dwFlags)
            {
                return BCryptSetIntPropertyPrivate(hObject, pszProperty, ref pdwInput, sizeof(int), dwFlags);
            }
        }
    }

    internal class AesAEAD
    {
        public static void CheckKeySize(int keySizeInBits)
        {
            if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256)
            {
                throw new CryptographicException("SR.Cryptography_InvalidKeySize");
            }
        }

        public static void CheckArgumentsForNull(
            byte[] nonce,
            byte[] plaintext,
            byte[] ciphertext,
            byte[] tag)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (tag == null)
                throw new ArgumentNullException(nameof(tag));
        }

        public static unsafe void Encrypt(
            SafeAlgorithmHandle algorithm,
            SafeKeyHandle keyHandle,
            byte[] nonce,
            byte[] associatedData,
            byte[] plaintext,
            byte[] ciphertext,
            byte[] tag)
        {
            fixed (byte* plaintextBytes = plaintext)
            fixed (byte* nonceBytes = nonce)
            fixed (byte* ciphertextBytes = ciphertext)
            fixed (byte* tagBytes = tag)
            fixed (byte* associatedDataBytes = associatedData)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                authInfo.pbNonce = nonceBytes;
                authInfo.cbNonce = nonce.Length;
                authInfo.pbTag = tagBytes;
                authInfo.cbTag = tag.Length;
                authInfo.pbAuthData = associatedDataBytes;
                if (associatedData == null)
                    authInfo.cbAuthData = 0;
                else
                    authInfo.cbAuthData = associatedData.Length;

                NTSTATUS ntStatus = Interop.BCrypt.BCryptEncrypt(
                    keyHandle,
                    plaintextBytes,
                    plaintext.Length,
                    new IntPtr(&authInfo),
                    null,
                    0,
                    ciphertextBytes,
                    ciphertext.Length,
                    out int ciphertextBytesWritten,
                    0);

                Debug.Assert(plaintext.Length == ciphertextBytesWritten);

                if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    throw Interop.BCrypt.CreateCryptographicException(ntStatus);
                }
            }
        }

        public static unsafe void Decrypt(
            SafeAlgorithmHandle algorithm,
            SafeKeyHandle keyHandle,
            byte[] nonce,
            byte[] associatedData,
            byte[] ciphertext,
            byte[] tag,
            byte[] plaintext,
            bool clearPlaintextOnFailure)
        {
            fixed (byte* plaintextBytes = plaintext)
            fixed (byte* nonceBytes = nonce)
            fixed (byte* ciphertextBytes = ciphertext)
            fixed (byte* tagBytes = tag)
            fixed (byte* associatedDataBytes = associatedData)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                authInfo.pbNonce = nonceBytes;
                authInfo.cbNonce = nonce.Length;
                authInfo.pbTag = tagBytes;
                authInfo.cbTag = tag.Length;
                authInfo.pbAuthData = associatedDataBytes;
                if (associatedData == null)
                    authInfo.cbAuthData = 0;
                else
                    authInfo.cbAuthData = associatedData.Length;

                NTSTATUS ntStatus = Interop.BCrypt.BCryptDecrypt(
                    keyHandle,
                    ciphertextBytes,
                    ciphertext.Length,
                    new IntPtr(&authInfo),
                    null,
                    0,
                    plaintextBytes,
                    plaintext.Length,
                    out int plaintextBytesWritten,
                    0);

                Debug.Assert(ciphertext.Length == plaintextBytesWritten);

                switch (ntStatus)
                {
                    case NTSTATUS.STATUS_SUCCESS:
                        return;
                    case NTSTATUS.STATUS_AUTH_TAG_MISMATCH:
                        if (clearPlaintextOnFailure)
                        {
                            CryptographicOperations.ZeroMemory(plaintext);
                        }

                        throw new CryptographicException("SR.Cryptography_AuthTagMismatch");
                    default:
                        throw Interop.BCrypt.CreateCryptographicException(ntStatus);
                }
            }
        }
    }
}
