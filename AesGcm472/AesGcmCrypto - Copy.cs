using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AesGcm472
{
    internal partial class Interop
    {
        internal partial class BCrypt
        {
            internal static Exception CreateCryptographicException(NTSTATUS ntStatus)
            {
                int hr = unchecked((int)ntStatus) | 0x01000000;
                return hr.ToCryptographicException();
            }
        }
    }

    internal partial class Interop
    {
        internal partial class BCrypt
        {
            internal static unsafe SafeKeyHandle BCryptImportKey(SafeAlgorithmHandle hAlg, ReadOnlySpan<byte> key)
            {
                const string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
                int keySize = key.Length;
                int blobSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keySize;
                byte[] blob = new byte[blobSize];
                fixed (byte* pbBlob = blob)
                {
                    BCRYPT_KEY_DATA_BLOB_HEADER* pBlob = (BCRYPT_KEY_DATA_BLOB_HEADER*)pbBlob;
                    pBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_HEADER.BCRYPT_KEY_DATA_BLOB_MAGIC;
                    pBlob->dwVersion = BCRYPT_KEY_DATA_BLOB_HEADER.BCRYPT_KEY_DATA_BLOB_VERSION1;
                    pBlob->cbKeyData = (uint)keySize;
                }

                key.CopyTo(blob.AsSpan(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)));
                SafeKeyHandle hKey;
                NTSTATUS ntStatus = BCryptImportKey(hAlg, IntPtr.Zero, BCRYPT_KEY_DATA_BLOB, out hKey, IntPtr.Zero, 0, blob, blobSize, 0);
                if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    throw CreateCryptographicException(ntStatus);
                }

                return hKey;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct BCRYPT_KEY_DATA_BLOB_HEADER
            {
                public uint dwMagic;
                public uint dwVersion;
                public uint cbKeyData;

                public const uint BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b;
                public const uint BCRYPT_KEY_DATA_BLOB_VERSION1 = 0x1;
            }

            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
            private static extern NTSTATUS BCryptImportKey(SafeAlgorithmHandle hAlgorithm, IntPtr hImportKey, string pszBlobType, out SafeKeyHandle hKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbInput, int cbInput, int dwFlags);
        }
    }

    internal static partial class Interop
    {
        internal static partial class Kernel32
        {
            private const int FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
            private const int FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            private const int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            private const int FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
            private const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
            private const int ERROR_INSUFFICIENT_BUFFER = 0x7A;

            [DllImport(Libraries.Kernel32, CharSet = CharSet.Unicode, EntryPoint = "FormatMessageW", SetLastError = true, BestFitMapping = true, ExactSpelling = true)]
            private static extern unsafe int FormatMessage(
                int dwFlags,
                IntPtr lpSource,
                uint dwMessageId,
                int dwLanguageId,
                void* lpBuffer,
                int nSize,
                IntPtr arguments);

            /// <summary>
            ///     Returns a string message for the specified Win32 error code.
            /// </summary>
            internal static string GetMessage(int errorCode) =>
                GetMessage(errorCode, IntPtr.Zero);

            internal static unsafe string GetMessage(int errorCode, IntPtr moduleHandle)
            {
                int flags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY;
                if (moduleHandle != IntPtr.Zero)
                {
                    flags |= FORMAT_MESSAGE_FROM_HMODULE;
                }

                // First try to format the message into the stack based buffer.  Most error messages willl fit.
                Span<char> stackBuffer = stackalloc char[256]; // arbitrary stack limit
                fixed (char* bufferPtr = stackBuffer)
                {
                    int length = FormatMessage(flags, moduleHandle, unchecked((uint)errorCode), 0, bufferPtr, stackBuffer.Length, IntPtr.Zero);
                    if (length > 0)
                    {
                        return GetAndTrimString(stackBuffer.Slice(0, length));
                    }
                }

                // We got back an error.  If the error indicated that there wasn't enough room to store
                // the error message, then call FormatMessage again, but this time rather than passing in
                // a buffer, have the method allocate one, which we then need to free.
                if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
                {
                    IntPtr nativeMsgPtr = default;
                    try
                    {
                        int length = FormatMessage(flags | FORMAT_MESSAGE_ALLOCATE_BUFFER, moduleHandle, unchecked((uint)errorCode), 0, &nativeMsgPtr, 0, IntPtr.Zero);
                        if (length > 0)
                        {
                            return GetAndTrimString(new Span<char>((char*)nativeMsgPtr, length));
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(nativeMsgPtr);
                    }
                }

                // Couldn't get a message, so manufacture one.
                return string.Format("Unknown error (0x{0:x})", errorCode);
            }

            private static string GetAndTrimString(Span<char> buffer)
            {
                int length = buffer.Length;
                while (length > 0 && buffer[length - 1] <= 32)
                {
                    length--; // trim off spaces and non-printable ASCII chars at the end of the resource
                }
                return buffer.Slice(0, length).ToString();
            }
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
                SafeAlgorithmHandle hAlg = Cng.BCryptOpenAlgorithmProvider(Cng.BCRYPT_AES_ALGORITHM, null,
                    Cng.OpenAlgorithmProviderFlags.NONE);
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

    //internal static partial class BCrypt
    //{
    internal enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0x0,
            STATUS_NOT_FOUND = 0xc0000225,
            STATUS_INVALID_PARAMETER = 0xc000000d,
            STATUS_NO_MEMORY = 0xc0000017,
            STATUS_AUTH_TAG_MISMATCH = 0xc000a002,
        }
    //}

    internal abstract class SafeBCryptHandle : SafeHandle, IDisposable
    {
        protected SafeBCryptHandle()
            : base(IntPtr.Zero, true)

        {
        }

        public sealed override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }

        protected abstract override bool ReleaseHandle();
    }

    // https://msdn.microsoft.com/en-us/library/cc231198.aspx
    internal enum HRESULT : int
    {
        S_OK = 0,
        S_FALSE = 1,
        E_NOTIMPL = unchecked((int)0x80004001),
        E_ABORT = unchecked((int)0x80004004),
        E_FAIL = unchecked((int)0x80004005),
        E_UNEXPECTED = unchecked((int)0x8000FFFF),
        STG_E_INVALIDFUNCTION = unchecked((int)0x80030001L),
        STG_E_INVALIDPARAMETER = unchecked((int)0x80030057),
        STG_E_INVALIDFLAG = unchecked((int)0x800300FF),
        E_ACCESSDENIED = unchecked((int)0x80070005),
        E_INVALIDARG = unchecked((int)0x80070057),
    }

    internal static partial class Libraries
    {
        internal const string Advapi32 = "advapi32.dll";
        internal const string BCrypt = "BCrypt.dll";
        internal const string Crypt32 = "crypt32.dll";
        internal const string CryptUI = "cryptui.dll";
        internal const string Gdi32 = "gdi32.dll";
        internal const string HttpApi = "httpapi.dll";
        internal const string IpHlpApi = "iphlpapi.dll";
        internal const string Kernel32 = "kernel32.dll";
        internal const string Mswsock = "mswsock.dll";
        internal const string NCrypt = "ncrypt.dll";
        internal const string NtDll = "ntdll.dll";
        internal const string Odbc32 = "odbc32.dll";
        internal const string Ole32 = "ole32.dll";
        internal const string OleAut32 = "oleaut32.dll";
        internal const string Pdh = "pdh.dll";
        internal const string Secur32 = "secur32.dll";
        internal const string Shell32 = "shell32.dll";
        internal const string SspiCli = "sspicli.dll";
        internal const string User32 = "user32.dll";
        internal const string Version = "version.dll";
        internal const string WebSocket = "websocket.dll";
        internal const string WinHttp = "winhttp.dll";
        internal const string WinMM = "winmm.dll";
        internal const string Wldap32 = "wldap32.dll";
        internal const string Ws2_32 = "ws2_32.dll";
        internal const string Wtsapi32 = "wtsapi32.dll";
        internal const string CompressionNative = "System.IO.Compression.Native";
        internal const string GlobalizationNative = "System.Globalization.Native";
        internal const string MsQuic = "msquic.dll";
        internal const string HostPolicy = "hostpolicy.dll";
    }

    //
    // Interop layer around Windows CNG api.
    //
    internal static partial class Cng
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
    }

    internal static partial class Cng
    {
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

    internal sealed class SafeAlgorithmHandle : SafeBCryptHandle
    {
        protected sealed override bool ReleaseHandle()
        {
            uint ntStatus = BCryptCloseAlgorithmProvider(handle, 0);
            return ntStatus == 0;
        }

        [DllImport(Libraries.BCrypt)]
        private static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);
    }

    internal sealed class SafeKeyHandle : SafeBCryptHandle
    {
        private SafeAlgorithmHandle _parentHandle;

        public void SetParentHandle(SafeAlgorithmHandle parentHandle)
        {
            Debug.Assert(_parentHandle == null);
            Debug.Assert(parentHandle != null);
            Debug.Assert(!parentHandle.IsInvalid);

            bool ignore = false;
            parentHandle.DangerousAddRef(ref ignore);

            _parentHandle = parentHandle;
        }

        protected sealed override bool ReleaseHandle()
        {
            if (_parentHandle != null)
            {
                _parentHandle.DangerousRelease();
                _parentHandle = null;
            }

            uint ntStatus = BCryptDestroyKey(handle);
            return ntStatus == 0;
        }

        [DllImport(Libraries.BCrypt)]
        private static extern uint BCryptDestroyKey(IntPtr hKey);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        private int cbSize;
        private uint dwInfoVersion;
        internal byte* pbNonce;
        internal int cbNonce;
        internal byte* pbAuthData;
        internal int cbAuthData;
        internal byte* pbTag;
        internal int cbTag;
        internal byte* pbMacContext;
        internal int cbMacContext;
        internal int cbAAD;
        internal ulong cbData;
        internal uint dwFlags;

        public static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Create()
        {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ret = default;

            ret.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

            const uint BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;
            ret.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

            return ret;
        }
    }

    internal static partial class Interop
    {
        internal static partial class BCrypt
        {
            // Note: input and output are allowed to be the same buffer. BCryptEncrypt will correctly do the encryption in place according to CNG documentation.
            internal static int BCryptEncrypt(SafeKeyHandle hKey, ReadOnlySpan<byte> input, byte[] iv, Span<byte> output)
            {
                unsafe
                {
                    fixed (byte* pbInput = input)
                    fixed (byte* pbOutput = output)
                    {
                        int cbResult;
                        NTSTATUS ntStatus = BCryptEncrypt(hKey, pbInput, input.Length, IntPtr.Zero, iv, iv == null ? 0 : iv.Length, pbOutput, output.Length, out cbResult, 0);

                        if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                        {
                            throw CreateCryptographicException(ntStatus);
                        }

                        return cbResult;
                    }
                }
            }

            // Note: input and output are allowed to be the same buffer. BCryptDecrypt will correctly do the decryption in place according to CNG documentation.
            internal static int BCryptDecrypt(SafeKeyHandle hKey, ReadOnlySpan<byte> input, byte[] iv, Span<byte> output)
            {
                unsafe
                {
                    fixed (byte* pbInput = input)
                    fixed (byte* pbOutput = output)
                    {
                        int cbResult;
                        NTSTATUS ntStatus = BCryptDecrypt(hKey, pbInput, input.Length, IntPtr.Zero, iv, iv == null ? 0 : iv.Length, pbOutput, output.Length, out cbResult, 0);

                        if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                        {
                            throw CreateCryptographicException(ntStatus);
                        }

                        return cbResult;
                    }
                }
            }

            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
            public static extern unsafe NTSTATUS BCryptEncrypt(SafeKeyHandle hKey, byte* pbInput, int cbInput, IntPtr paddingInfo, [In, Out] byte[] pbIV, int cbIV, byte* pbOutput, int cbOutput, out int cbResult, int dwFlags);

            [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
            public static extern unsafe NTSTATUS BCryptDecrypt(SafeKeyHandle hKey, byte* pbInput, int cbInput, IntPtr paddingInfo, [In, Out] byte[] pbIV, int cbIV, byte* pbOutput, int cbOutput, out int cbResult, int dwFlags);
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
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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
        public static void ZeroMemory(Span<byte> buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is unnecessary
            // NoInlining to prevent the inliner from forgetting that the method was no-optimize
            buffer.Clear();
        }
    }

    internal partial class AesAEAD
    {
        public static unsafe void Encrypt(
            SafeAlgorithmHandle algorithm,
            SafeKeyHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag)
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
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
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

    public partial class AesGcm
    {
        private static readonly SafeAlgorithmHandle s_aesGcm = AesBCryptModes.OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_GCM).Value;
        private SafeKeyHandle _keyHandle;

        private void ImportKey(ReadOnlySpan<byte> key)
        {
            _keyHandle = Interop.BCrypt.BCryptImportKey(s_aesGcm, key);
        }

        private void EncryptInternal(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            AesAEAD.Encrypt(s_aesGcm, _keyHandle, nonce, associatedData, plaintext, ciphertext, tag);
        }

        private void DecryptInternal(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            AesAEAD.Decrypt(s_aesGcm, _keyHandle, nonce, associatedData, ciphertext, tag, plaintext, clearPlaintextOnFailure: true);
        }

        public void Dispose()
        {
            _keyHandle.Dispose();
        }
    }

    public class AesGcmCrypto
    {
        public static void Run()
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
        }

        public static string Encrypt(string plain, byte[] key, byte[] nonce, byte[] tag)
        {
            // Get bytes of plaintext string
            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);

            // Get parameter sizes
            int nonceSize = AesGcm.NonceByteSizes.MaxSize;
            int tagSize = AesGcm.TagByteSizes.MaxSize;
            byte[] encryptedData = new byte[plainBytes.Length];

            // Encrypt
            var aes = new AesGcm(key);
            aes.Encrypt(nonce, plainBytes, encryptedData, tag);

            // Encode for transmission
            return Convert.ToBase64String(encryptedData.ToArray());
        }

        public static string Decrypt(string cipherText, byte[] key, byte[] nonce, byte[] tag)
        {
            byte[] encryptedData = Convert.FromBase64String(cipherText);
            byte[] clearBytes = new byte[encryptedData.Length];
            var aes = new AesGcm(key);
            aes.Decrypt(nonce, encryptedData, tag, clearBytes);

            // Convert plain bytes back into string
            return Encoding.UTF8.GetString(clearBytes);
        }
    }

    internal partial class AesAEAD
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
    }

    public sealed partial class AesGcm : IDisposable
    {
        private const int NonceSize = 12;
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(12, 16, 1);

        public AesGcm(ReadOnlySpan<byte> key)
        {
            AesAEAD.CheckKeySize(key.Length * 8);
            ImportKey(key);
        }

        public AesGcm(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            AesAEAD.CheckKeySize(key.Length * 8);
            ImportKey(key);
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, nonce, tag);
            EncryptInternal(nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
        }

        public void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, nonce, tag);
            DecryptInternal(nonce, ciphertext, tag, plaintext, associatedData);
        }

        private static void CheckParameters(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag)
        {
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException("SR.Cryptography_PlaintextCiphertextLengthMismatch");

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("SR.Cryptography_InvalidNonceLength", nameof(nonce));

            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException("SR.Cryptography_InvalidTagLength", nameof(tag));
        }
    }
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
}
