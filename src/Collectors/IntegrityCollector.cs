using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    // Checks hash of critical system files
    public static class IntegrityCollector
    {
        private static readonly string[] CriticalFiles = new string[] 
        {
            "cmd.exe",
            "powershell.exe",
            "svchost.exe",
            "explorer.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "services.exe",
            "smss.exe",
            "taskmgr.exe",
            "regedit.exe",
            "notepad.exe",
            "user32.dll",
            "kernel32.dll",
            "ntdll.dll"
        };

        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting File Integrity (System32)...");
            string outFile = Path.Combine(outputDir, ArtifactNames.FileIntegrityCsv);
            string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            bool hadHashErrors = false;

            try
            {
                using (StreamWriter sw = new StreamWriter(outFile, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("FileName,Path,SHA256,SignatureStatus,Signer,Status");

                    // 1. Critical Binaries
                    foreach (var file in CriticalFiles)
                    {
                        string path = Path.Combine(sys32, file);
                        if (!File.Exists(path))
                        {
                            if (file == "powershell.exe")
                                path = Path.Combine(sys32, @"WindowsPowerShell\v1.0\powershell.exe");
                        }
                        if (!WriteFileHash(sw, file, path)) hadHashErrors = true;
                    }

                    // 2. Hosts File
                    string hostsPath = Path.Combine(sys32, @"drivers\etc\hosts");
                    if (!WriteFileHash(sw, "hosts", hostsPath)) hadHashErrors = true;

                    // 3. Startup Folders
                    if (!ScanDirectory(sw, Environment.GetFolderPath(Environment.SpecialFolder.Startup))) hadHashErrors = true;
                    if (!ScanDirectory(sw, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))) hadHashErrors = true;
                }
                Console.WriteLine("    + Integrity hashes collected (Binaries + Hosts + Startup).");
                if (hadHashErrors)
                    throw new InvalidOperationException("One or more integrity hashes could not be computed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting integrity: " + ex.Message);
                Logger.Warning("IntegrityCollector: " + ex.Message);
                throw;
            }
        }

        private static bool ScanDirectory(StreamWriter sw, string dir)
        {
            if (!Directory.Exists(dir)) return true;
            bool ok = true;
            try
            {
               foreach(var file in Directory.GetFiles(dir))
               {
                   if (!WriteFileHash(sw, Path.GetFileName(file), file)) ok = false;
               }
            }
            catch (Exception ex) { Logger.Warning("IntegrityCollector: " + ex.Message); ok = false; }
            return ok;
        }

        private static bool WriteFileHash(StreamWriter sw, string name, string path)
        {
            if (File.Exists(path))
            {
                string hash = ComputeSha256(path);
                string signer;
                string sigStatus = IR_Collect.SignatureHelper.GetSignatureStatus(path, out signer);
                string status = string.IsNullOrEmpty(hash) ? "HashError" : "Present";
                sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5}", 
                    name,
                    path,
                    hash,
                    sigStatus,
                    IR_Collect.Utils.CsvUtils.EscapeField(signer),
                    status
                ));
                return !string.IsNullOrEmpty(hash);
            }
            sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5}", 
                name,
                "N/A",
                "",
                "",
                "",
                "Missing"
            ));
            return true;
        }

        private static string ComputeSha256(string file)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    using (var stream = File.OpenRead(file))
                    {
                        var hash = sha256.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch 
            {
                return "";
            }
        }
    }
}
