using System;
using System.IO;
using System.Diagnostics;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class RegistryCollector
    {
        public static void CollectRegistryHives(string outputDir)
        {
            Console.WriteLine("[*] Collecting Registry Hives...");
            string registryDir = Path.Combine(outputDir, "Registry");
            Directory.CreateDirectory(registryDir);
            int failedArtifacts = 0;

            // Enable backup privilege so child process (reg save) may inherit; helps some hives
            try { string s; IR_Collect.MFT.NativeMethods.EnableBackupPrivilege(out s); } catch (Exception ex) { IR_Collect.Utils.Logger.Warning("EnableBackupPrivilege: " + ex.Message); }

            string[] systemHives = {
                "HKLM\\SYSTEM",
                "HKLM\\SOFTWARE",
                "HKLM\\SAM",
                "HKLM\\SECURITY"
            };

            int systemOk = 0;
            foreach (string hive in systemHives)
            {
                string fileName = hive.Replace("HKLM\\", "") + ".hiv";
                string destPath = Path.Combine(registryDir, fileName);
                if (SaveHive(hive, destPath)) systemOk++;
                // SAM and SECURITY both normally require LocalSystem to `reg save`; a plain-admin
                // failure there is expected and must not fail the whole Registry step (treat both alike).
                else if (!string.Equals(hive, "HKLM\\SECURITY", StringComparison.OrdinalIgnoreCase)
                      && !string.Equals(hive, "HKLM\\SAM", StringComparison.OrdinalIgnoreCase)) failedArtifacts++;
            }
            Console.WriteLine("    System hives: {0}/4 saved (SAM/SECURITY often fail without LocalSystem).", systemOk);

            // 2. User Hives (Try to enumerate HKEY_USERS)
            // Note: In C#, enumerating HKU requires P/Invoke or using Microsoft.Win32, but running 'reg save' simply works if we know the SID.
            // We can use 'reg query HKEY_USERS' to get loaded SIDs.
            
            try 
            {
                string[] sids = GetLoadedUserSids();
                foreach(string sid in sids)
                {
                    // Skip system accounts broadly if desired, but collecting all is safer for IR.
                    // S-1-5-18 (System), S-1-5-19 (LocalService), S-1-5-20 (NetworkService)
                    
                    if (sid.Length > 10) // Simple filter for short names
                    {
                        // NTUSER.DAT (mapped to HKU\<SID>)
                        string ntuserPath = Path.Combine(registryDir, "NTUSER_" + sid + ".dat");
                        if (!SaveHive("HKEY_USERS\\" + sid, ntuserPath)) failedArtifacts++;

                        // UsrClass.dat (mapped to HKU\<SID>_Classes)
                        string usrClassPath = Path.Combine(registryDir, "UsrClass_" + sid + ".dat");
                        if (!SaveHive("HKEY_USERS\\" + sid + "_Classes", usrClassPath)) failedArtifacts++;

                        // ShellBags (BagMRU/Bags) — explicit .reg export for parser tools
                        if (!ExportShellBagsReg(sid, registryDir)) failedArtifacts++;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [!] Error enumerating users for registry: " + ex.Message);
                throw;
            }
            try
            {
                string shellDetail;
                int shellRows = ShellBagsParser.TryGenerateAfterCollection(registryDir, out shellDetail);
                if (shellRows > 0)
                    Console.WriteLine("   [+] shellbags.csv: " + shellRows.ToString() + " row(s) (" + (shellDetail ?? "") + ").");
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [!] shellbags.csv build: " + ex.Message);
            }

            if (failedArtifacts > 0)
                throw new InvalidOperationException("Registry collection incomplete: " + failedArtifacts + " artifact(s) failed.");
        }

        /// <summary>Export Shell (BagMRU/Bags) subtree to .reg for ShellBags parsing tools.</summary>
        private static bool ExportShellBagsReg(string sid, string registryDir)
        {
            string shellPath = "HKEY_USERS\\" + sid + "_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell";
            string safeSid = sid.Replace("\\", "_").Replace(":", "_");
            string destPath = Path.Combine(registryDir, "ShellBags_" + safeSid + ".reg");
            try
            {
                IR_Collect.Collector.CommandHelper.RunCommand("reg", "export " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(shellPath) + " " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(destPath) + " /y");
                if (File.Exists(destPath))
                {
                    Console.WriteLine("   [+] Saved ShellBags: " + Path.GetFileName(destPath));
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [!] ShellBags export skipped: " + ex.Message);
            }
            return false;
        }

        private static bool SaveHive(string hivePath, string destPath)
        {
            try
            {
                IR_Collect.Collector.CommandHelper.RunCommand("reg", "save " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(hivePath) + " " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(destPath) + " /y");
                if (File.Exists(destPath))
                {
                    Console.WriteLine("   [+] Saved Hive: " + Path.GetFileName(destPath));
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("   [!] Failed to save {0}: {1}", hivePath, ex.Message));
            }
            return false;
        }

        private static string[] GetLoadedUserSids()
        {
            // Parse 'reg query HKEY_USERS' output
            // Output format:
            // HKEY_USERS\S-1-5-21-...
            // HKEY_USERS\S-1-5-21-....._Classes
            
            var list = new System.Collections.Generic.List<string>();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("reg", "query HKEY_USERS");
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    if (p.ExitCode != 0)
                        throw new InvalidOperationException("reg query HKEY_USERS exited with code " + p.ExitCode);
                    
                    using (StringReader sr = new StringReader(output))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            if (line.Contains("HKEY_USERS\\"))
                            {
                                string sid = line.Substring(line.IndexOf("HKEY_USERS\\") + 11).Trim();
                                if (!sid.Contains("_Classes") && !sid.EndsWith("Classes") && sid.IndexOf('"') < 0) // Skip SID with quote (safety)
                                {
                                    list.Add(sid);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [!] GetLoadedUserSids: " + ex.Message);
                throw;
            }
            return list.ToArray();
        }
    }
}
