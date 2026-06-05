using System;
using System.Runtime.InteropServices;
// using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using System.IO;

namespace IR_Collect.MFT
{
    public static class NativeMethods
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            SafeFileHandle hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(
            SafeFileHandle hFile,
            long liDistanceToMove,
            out long lpNewFilePointer,
            uint dwMoveMethod);

        public const uint FILE_BEGIN = 0;

        // Enable SeBackupPrivilege to allow reading protected files like $MFT when possible.
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        public static bool EnableBackupPrivilege(out string status)
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            {
                int err = Marshal.GetLastWin32Error();
                status = "OpenProcessToken failed (Win32=" + err + ")";
                return false;
            }

            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out luid))
                {
                    int err = Marshal.GetLastWin32Error();
                    status = "LookupPrivilegeValue failed (Win32=" + err + ")";
                    return false;
                }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                };

                if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    status = "AdjustTokenPrivileges failed (Win32=" + err + ")";
                    return false;
                }

                int lastErr = Marshal.GetLastWin32Error();
                if (lastErr == ERROR_NOT_ALL_ASSIGNED)
                {
                    status = "SeBackupPrivilege not assigned (Win32=1300)";
                    return false;
                }

                status = "SeBackupPrivilege enabled";
                return true;
            }
            finally
            {
                CloseHandle(token);
            }
        }
    }

    public class RawDiskReader : IDisposable
    {
        private SafeFileHandle _handle;
        private string _drivePath;

        public RawDiskReader(string driveLetter)
        {
            // format: \\.\C: — require single A-Z to prevent path traversal
            if (string.IsNullOrWhiteSpace(driveLetter)) throw new ArgumentException("Drive letter is required.", "driveLetter");
            char c = driveLetter.Trim().ToUpperInvariant()[0];
            if (c < 'A' || c > 'Z') throw new ArgumentException("Drive letter must be A-Z.", "driveLetter");
            _drivePath = string.Format(@"\\.\{0}:", c);
            _handle = NativeMethods.CreateFile(
                _drivePath,
                NativeMethods.GENERIC_READ,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero,
                NativeMethods.OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (_handle.IsInvalid)
            {
                throw new Exception("Error code: " + Marshal.GetLastWin32Error());
            }
        }

        public void Seek(long offset)
        {
            long newPtr;
            if (!NativeMethods.SetFilePointerEx(_handle, offset, out newPtr, NativeMethods.FILE_BEGIN))
            {
                throw new Exception("Error code: " + Marshal.GetLastWin32Error());
            }
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            uint bytesRead;
            // Native ReadFile writes directly to buffer[0], so we might need a temp buffer if offset != 0
            // but for simplicity we assume full buffer read or handle offset carefully.
            // Simplified for now: always read to start of buffer
            byte[] tempBuf = new byte[count];
            if (!NativeMethods.ReadFile(_handle, tempBuf, (uint)count, out bytesRead, IntPtr.Zero))
            {
                throw new Exception("Error code: " + Marshal.GetLastWin32Error());
            }
            Array.Copy(tempBuf, 0, buffer, offset, (int)bytesRead);
            return (int)bytesRead;
        }

        public void Dispose()
        {
            if (_handle != null && !_handle.IsInvalid)
            {
                _handle.Close();
            }
        }
    }
}
