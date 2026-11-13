using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    internal enum RegistryHiveProbeResult
    {
        Present,
        Absent,
        ProbeError
    }

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
                if (SaveHive(hive, destPath, registryDir)) systemOk++;
                // SAM and SECURITY both normally require LocalSystem to `reg save`; a plain-admin
                // failure there is expected and must not fail the whole Registry step (treat both alike).
                else if (!string.Equals(hive, "HKLM\\SECURITY", StringComparison.OrdinalIgnoreCase)
                      && !string.Equals(hive, "HKLM\\SAM", StringComparison.OrdinalIgnoreCase)) failedArtifacts++;
            }
            Console.WriteLine("    System hives: {0}/4 saved (SAM/SECURITY often fail without LocalSystem).", systemOk);

            try 
            {
                string[] sids = GetLoadedUserSids();
                foreach(string sid in sids)
                {
                    if (!RegistrySidHelper.IsValidLoadedUserSid(sid))
                    {
                        Logger.Warning("RegistryCollector: skipped non-SID HKEY_USERS subkey name: " + sid);
                        continue;
                    }
                    if (!RegistrySidHelper.ShouldCollectRegistryForLoadedUserSid(sid))
                        continue;

                    string ntuserPath = Path.Combine(registryDir, "NTUSER_" + RegistrySidHelper.SidToFileToken(sid) + ".dat");
                    if (!RegistrySidHelper.EnsurePathUnderDirectory(registryDir, ntuserPath))
                    {
                        Logger.Warning("RegistryCollector: refused NTUSER path outside registry output: " + ntuserPath);
                        failedArtifacts++;
                        continue;
                    }
                    if (!SaveHive("HKEY_USERS\\" + sid, ntuserPath, registryDir)) failedArtifacts++;

                    string usrClassPath = Path.Combine(registryDir, "UsrClass_" + RegistrySidHelper.SidToFileToken(sid) + ".dat");
                    if (!RegistrySidHelper.EnsurePathUnderDirectory(registryDir, usrClassPath))
                    {
                        Logger.Warning("RegistryCollector: refused UsrClass path outside registry output: " + usrClassPath);
                        failedArtifacts++;
                        continue;
                    }
                    RegistryHiveProbeResult usrClassProbe = ProbeUserClassesHive(sid);
                    if (usrClassProbe == RegistryHiveProbeResult.Absent)
                    {
                        Logger.Info("RegistryCollector: skipped UsrClass hive (key not loaded): " + sid);
                    }
                    else if (!SaveHive("HKEY_USERS\\" + sid + "_Classes", usrClassPath, registryDir))
                    {
                        failedArtifacts++;
                    }

                    // Returns true for a confirmed-absent Shell key (logged skip) and on success;
                    // any export failure (including after a probe error) counts as a failed artifact.
                    if (!ExportShellBagsReg(sid, registryDir)) failedArtifacts++;
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

        internal static RegistryHiveProbeResult ProbeUserClassesHive(string sid)
        {
            try
            {
                using (RegistryKey users = Registry.Users)
                {
                    if (users == null) return RegistryHiveProbeResult.ProbeError;
                    using (RegistryKey classes = users.OpenSubKey(sid + "_Classes", false))
                    {
                        return classes != null ? RegistryHiveProbeResult.Present : RegistryHiveProbeResult.Absent;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("RegistryCollector: could not probe UsrClass hive for " + sid + ": " + ex.Message);
                return RegistryHiveProbeResult.ProbeError;
            }
        }

        internal static RegistryHiveProbeResult ProbeShellBagsKey(string sid)
        {
            try
            {
                using (RegistryKey users = Registry.Users)
                {
                    if (users == null) return RegistryHiveProbeResult.ProbeError;
                    using (RegistryKey classes = users.OpenSubKey(sid + "_Classes", false))
                    {
                        if (classes == null) return RegistryHiveProbeResult.Absent;
                        using (RegistryKey shell = classes.OpenSubKey(@"Local Settings\Software\Microsoft\Windows\Shell", false))
                        {
                            return shell != null ? RegistryHiveProbeResult.Present : RegistryHiveProbeResult.Absent;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("RegistryCollector: could not probe ShellBags key for " + sid + ": " + ex.Message);
                return RegistryHiveProbeResult.ProbeError;
            }
        }

        /// <summary>Export Shell (BagMRU/Bags) subtree to .reg for ShellBags parsing tools.</summary>
        private static bool ExportShellBagsReg(string sid, string registryDir)
        {
            if (!RegistrySidHelper.IsValidLoadedUserSid(sid)) return false;
            RegistryHiveProbeResult shellProbe = ProbeShellBagsKey(sid);
            if (shellProbe == RegistryHiveProbeResult.Absent)
            {
                Logger.Info("RegistryCollector: skipped ShellBags export (Shell key not present): " + sid);
                return true;
            }
            string shellPath = "HKEY_USERS\\" + sid + "_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell";
            string destPath = Path.Combine(registryDir, "ShellBags_" + RegistrySidHelper.SidToFileToken(sid) + ".reg");
            if (!RegistrySidHelper.EnsurePathUnderDirectory(registryDir, destPath))
            {
                Logger.Warning("RegistryCollector: refused ShellBags export path outside registry output: " + destPath);
                return false;
            }
            try
            {
                string args = "export " + Collector.CommandHelper.QuoteProcessArgument(shellPath) + " " +
                    Collector.CommandHelper.QuoteProcessArgument(destPath) + " /y";
                Collector.CommandHelper.RunProcessDirect("reg", args);
                if (File.Exists(destPath))
                {
                    Console.WriteLine("   [+] Saved ShellBags: " + Path.GetFileName(destPath));
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [!] ShellBags export failed: " + ex.Message);
            }
            return false;
        }

        private static bool SaveHive(string hivePath, string destPath, string registryDir)
        {
            if (!RegistrySidHelper.EnsurePathUnderDirectory(registryDir, destPath))
            {
                Logger.Warning("RegistryCollector: refused hive save path outside registry output: " + destPath);
                return false;
            }
            try
            {
                string args = "save " + Collector.CommandHelper.QuoteProcessArgument(hivePath) + " " +
                    Collector.CommandHelper.QuoteProcessArgument(destPath) + " /y";
                Collector.CommandHelper.RunProcessDirect("reg", args);
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
            var list = new System.Collections.Generic.List<string>();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Collector.CommandHelper.ResolveSystemTool("reg");
                psi.Arguments = "query HKEY_USERS";
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Collector.CommandHelper.ApplyNoDefaultCurrentDirectoryInExePath(psi);
                
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
                                if (!sid.Contains("_Classes") && !sid.EndsWith("Classes"))
                                    list.Add(sid);
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
