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
            internal static unsafe SafeKeyHandle BCryptImportKey(SafeAlgorithmHandle hAlg, byte[] key)
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

                key.CopyTo(blob, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
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
                char[] stackBuffer = new char[256]; // arbitrary stack limit
                fixed (char* bufferPtr = stackBuffer)
                {
                    int length = FormatMessage(flags, moduleHandle, unchecked((uint)errorCode), 0, bufferPtr, stackBuffer.Length, IntPtr.Zero);
                    if (length > 0)
                    {
                        //return GetAndTrimString(stackBuffer.Slice(0, length));
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
                            //return GetAndTrimString(new Span<char>((char*)nativeMsgPtr, length));
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

            //private static string GetAndTrimString(Span<char> buffer)
            //{
            //    int length = buffer.Length;
            //    while (length > 0 && buffer[length - 1] <= 32)
            //    {
            //        length--; // trim off spaces and non-printable ASCII chars at the end of the resource
            //    }
            //    return buffer.Slice(0, length).ToString();
            //}
        }
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
            internal static int BCryptEncrypt(SafeKeyHandle hKey, byte[] input, byte[] iv, byte[] output)
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
            internal static int BCryptDecrypt(SafeKeyHandle hKey, byte[] input, byte[] iv, byte[] output)
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

    internal enum NTSTATUS : uint
    {
        STATUS_SUCCESS = 0x0,
        STATUS_NOT_FOUND = 0xc0000225,
        STATUS_INVALID_PARAMETER = 0xc000000d,
        STATUS_NO_MEMORY = 0xc0000017,
        STATUS_AUTH_TAG_MISMATCH = 0xc000a002,
    }

}