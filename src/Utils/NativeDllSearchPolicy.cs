using System;
using System.Runtime.InteropServices;

namespace IR_Collect.Utils
{
    /// <summary>Best-effort hardening: load native DLLs from System32 only when the OS supports it.</summary>
    internal static class NativeDllSearchPolicy
    {
        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate bool SetDefaultDllDirectoriesDelegate(uint DirectoryFlags);

        internal static void TryApplyAtStartup()
        {
            try
            {
                IntPtr kernel = GetModuleHandle("kernel32.dll");
                if (kernel == IntPtr.Zero) return;
                IntPtr proc = GetProcAddress(kernel, "SetDefaultDllDirectories");
                if (proc == IntPtr.Zero) return;
                var setDirs = (SetDefaultDllDirectoriesDelegate)Marshal.GetDelegateForFunctionPointer(
                    proc, typeof(SetDefaultDllDirectoriesDelegate));
                setDirs(LOAD_LIBRARY_SEARCH_SYSTEM32);
            }
            catch
            {
                // Win7 without KB2533623 or other hosts: skip without failing startup.
            }
        }
    }
}
