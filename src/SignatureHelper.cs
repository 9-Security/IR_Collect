using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace IR_Collect
{
    public static class SignatureHelper
    {
        public static string GetSignatureStatus(string filePath, out string signer)
        {
            signer = "";
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return "Missing";

            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                if (cert != null)
                {
                    X509Certificate2 cert2 = new X509Certificate2(cert);
                    signer = cert2.Subject;
                }
            }
            catch
            {
                return "Unsigned";
            }

            if (string.IsNullOrEmpty(signer)) return "Unsigned";

            WinVerifyTrustResult result = WinVerifyTrust(filePath);
            if (result == WinVerifyTrustResult.Success) return "Signed-Trusted";

            return "Signed-Untrusted(0x" + ((uint)result).ToString("X") + ")";
        }

        private static WinVerifyTrustResult WinVerifyTrust(string fileName)
        {
            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(fileName);
            WINTRUST_DATA data = new WINTRUST_DATA(fileInfo);

            WinVerifyTrustResult result = WinVerifyTrust(IntPtr.Zero, action, data);
            data.Dispose();
            return result;
        }

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern WinVerifyTrustResult WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            WINTRUST_DATA pWVTData);

        private enum WinVerifyTrustResult : uint
        {
            Success = 0,
            SubjectNotTrusted = 0x800B0004,
            SubjectNotSigned = 0x800B0100,
            BadDigest = 0x80096010,
            UnknownProvider = 0x800B0001,
            ActionUnknown = 0x800B0002
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;

            public WINTRUST_FILE_INFO(string filePath)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
                pcwszFilePath = filePath;
                hFile = IntPtr.Zero;
                pgKnownSubject = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_DATA : IDisposable
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;

            private IntPtr fileInfoPtr;

            public WINTRUST_DATA(WINTRUST_FILE_INFO fileInfo)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                pPolicyCallbackData = IntPtr.Zero;
                pSIPClientData = IntPtr.Zero;
                dwUIChoice = 2; // WTD_UI_NONE
                fdwRevocationChecks = 0; // WTD_REVOKE_NONE
                dwUnionChoice = 1; // WTD_CHOICE_FILE
                dwStateAction = 0; // WTD_STATEACTION_IGNORE
                hWVTStateData = IntPtr.Zero;
                pwszURLReference = null;
                dwProvFlags = 0x00000010; // WTD_REVOCATION_CHECK_NONE
                dwUIContext = 0;

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
                pFile = fileInfoPtr;
            }

            public void Dispose()
            {
                if (fileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(fileInfoPtr);
                    fileInfoPtr = IntPtr.Zero;
                }
            }
        }
    }
}
