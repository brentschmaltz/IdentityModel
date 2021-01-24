﻿using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AesGcm472
{
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

}