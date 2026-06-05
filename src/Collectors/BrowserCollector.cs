using System;
using System.IO;
using System.Collections.Generic;

namespace IR_Collect.Collectors
{
    public static class BrowserCollector
    {
        public static void CollectBrowserHistory(string outputDir)
        {
            var failures = new List<string>();
            try
            {
                Console.WriteLine("[*] Collecting Browser History...");
                string browserDir = Path.Combine(outputDir, "Browsers");
                Directory.CreateDirectory(browserDir);

                foreach (UserProfileInfo profile in UserProfileHelper.GetUserProfiles())
                {
                    string username = profile.UserName;
                    string userDir = profile.ProfilePath;

                    var browsers = new Dictionary<string, string>
                    {
                        { "Chrome", "AppData\\Local\\Google\\Chrome\\User Data" },
                        { "Edge", "AppData\\Local\\Microsoft\\Edge\\User Data" },
                        { "Brave", "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" },
                        { "Vivaldi", "AppData\\Local\\Vivaldi\\User Data" }
                    };

                    foreach (var b in browsers)
                    {
                        CollectChromiumProfiles(Path.Combine(userDir, b.Value), b.Key, username, browserDir, failures);
                    }

                    CollectSingleHistory(Path.Combine(userDir, "AppData\\Roaming\\Opera Software\\Opera Stable\\History"),
                        Path.Combine(browserDir, string.Format("Opera_{0}_History", SanitizeFilePart(username))), failures);
                    CollectSingleHistory(Path.Combine(userDir, "AppData\\Roaming\\Opera Software\\Opera GX Stable\\History"),
                        Path.Combine(browserDir, string.Format("OperaGX_{0}_History", SanitizeFilePart(username))), failures);

                    string firefoxProfiles = Path.Combine(userDir, "AppData\\Roaming\\Mozilla\\Firefox\\Profiles");
                    if (Directory.Exists(firefoxProfiles))
                    {
                        foreach (string firefoxProfileDir in Directory.GetDirectories(firefoxProfiles))
                        {
                            string placesPath = Path.Combine(firefoxProfileDir, "places.sqlite");
                            if (File.Exists(placesPath))
                            {
                                string profileName = Path.GetFileName(firefoxProfileDir);
                                CopyBrowserDatabase(placesPath, Path.Combine(browserDir, string.Format("Firefox_{0}_{1}_places.sqlite", SanitizeFilePart(username), SanitizeFilePart(profileName))), failures);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("[!] Error collecting browser history: {0}", ex.Message));
                failures.Add(ex.Message);
            }
            if (failures.Count > 0)
            {
                throw new InvalidOperationException("Browser history collection incomplete: " + failures[0]);
            }
        }

        internal static List<string> EnumerateChromiumHistoryFiles(string userDataDir)
        {
            var files = new List<string>();
            if (string.IsNullOrEmpty(userDataDir) || !Directory.Exists(userDataDir)) return files;

            try
            {
                foreach (string profileDir in Directory.GetDirectories(userDataDir))
                {
                    string historyPath = Path.Combine(profileDir, "History");
                    if (File.Exists(historyPath))
                        files.Add(historyPath);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("   [!] Failed to enumerate Chromium profiles in {0}: {1}", userDataDir, ex.Message));
            }

            return files;
        }

        private static void CollectChromiumProfiles(string userDataDir, string browserName, string username, string browserDir, List<string> failures)
        {
            foreach (string historyPath in EnumerateChromiumHistoryFiles(userDataDir))
            {
                string profileName = Path.GetFileName(Path.GetDirectoryName(historyPath));
                string destName = string.Equals(profileName, "Default", StringComparison.OrdinalIgnoreCase)
                    ? string.Format("{0}_{1}_History", browserName, SanitizeFilePart(username))
                    : string.Format("{0}_{1}_{2}_History", browserName, SanitizeFilePart(username), SanitizeFilePart(profileName));
                CopyBrowserDatabase(historyPath, Path.Combine(browserDir, destName), failures);
            }
        }

        private static void CollectSingleHistory(string source, string dest, List<string> failures)
        {
            if (File.Exists(source))
                CopyBrowserDatabase(source, dest, failures);
        }

        private static string SanitizeFilePart(string value)
        {
            if (string.IsNullOrEmpty(value)) return "user";
            foreach (char c in Path.GetInvalidFileNameChars())
                value = value.Replace(c.ToString(), "_");
            return value.Replace(" ", "_");
        }

        internal static string[] GetSqliteSidecarPaths(string source)
        {
            return new string[]
            {
                source + "-wal",
                source + "-shm",
                source + "-journal"
            };
        }

        private static void CopyBrowserDatabase(string source, string dest, List<string> failures)
        {
            if (!CopyFileSafe(source, dest, failures)) return;
            foreach (string sidecar in GetSqliteSidecarPaths(source))
            {
                if (!File.Exists(sidecar)) continue;
                CopyOptionalSidecar(sidecar, dest + sidecar.Substring(source.Length), failures);
            }
        }

        private static bool CopyFileSafe(string source, string dest, List<string> failures)
        {
            try
            {
                // Try simple copy
                File.Copy(source, dest, true);
                Console.WriteLine(string.Format("   [+] Collected: {0}", Path.GetFileName(dest)));
                return true;
            }
            catch (IOException)
            {
                // If locked, try to read via FileStream with ReadWrite share
                try
                {
                    using (FileStream srcFs = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (FileStream destFs = new FileStream(dest, FileMode.Create, FileAccess.Write))
                    {
                        srcFs.CopyTo(destFs);
                    }
                    Console.WriteLine(string.Format("   [+] Collected (Locked): {0}", Path.GetFileName(dest)));
                    return true;
                }
                catch (Exception ex)
                {
                   Console.WriteLine(string.Format("   [!] Failed to copy {0}: {1}", source, ex.Message));
                   if (failures != null) failures.Add(source + ": " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("   [!] Failed to copy {0}: {1}", source, ex.Message));
                if (failures != null) failures.Add(source + ": " + ex.Message);
            }
            return false;
        }

        private static void CopyOptionalSidecar(string source, string dest, List<string> failures)
        {
            try
            {
                CopyFileSafe(source, dest, failures);
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("   [!] Failed to copy sidecar {0}: {1}", source, ex.Message));
                if (failures != null) failures.Add(source + ": " + ex.Message);
            }
        }
    }
}
