using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class UserActivityCollector
    {
        public static void CollectRecentFiles(string outputDir)
        {
            try
            {
                Console.WriteLine("[*] Collecting Recent Files List & LNK Copy...");
                string csvPath = Path.Combine(outputDir, ArtifactNames.RecentFilesCsv);
                string lnkDestDir = Path.Combine(outputDir, "LnkFiles");
                
                if (!Directory.Exists(lnkDestDir)) Directory.CreateDirectory(lnkDestDir);

                int skipAccessDenied = 0, skipPathTooLong = 0;
                using (StreamWriter sw = new StreamWriter(csvPath, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("FileName,Extension,LastModified,Created,Directory");

                    List<UserProfileInfo> profiles = UserProfileHelper.GetUserProfiles();
                    if (profiles.Count == 0)
                    {
                        string currentUserRecent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
                        string currentUserDesktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                        Console.WriteLine("    > Scanning Current User: " + Environment.UserName);
                        if (Directory.Exists(currentUserRecent)) ProcessDirectory(currentUserRecent, sw, lnkDestDir, ref skipAccessDenied, ref skipPathTooLong, recentFolderOnly: true);
                        if (Directory.Exists(currentUserDesktop)) ProcessDirectory(currentUserDesktop, sw, lnkDestDir, ref skipAccessDenied, ref skipPathTooLong, recentFolderOnly: false);
                    }
                    else
                    {
                        foreach (UserProfileInfo profile in profiles)
                        {
                            string recentPath = Path.Combine(profile.ProfilePath, "AppData\\Roaming\\Microsoft\\Windows\\Recent");
                            string desktopPath = Path.Combine(profile.ProfilePath, "Desktop");

                            Console.WriteLine("    > Scanning User: " + profile.UserName);
                            try
                            {
                                if (Directory.Exists(recentPath)) ProcessDirectory(recentPath, sw, lnkDestDir, ref skipAccessDenied, ref skipPathTooLong, recentFolderOnly: true);
                            }
                            catch (Exception ex) { skipAccessDenied++; if (skipAccessDenied <= 2) Logger.Warning("UserActivity recentPath: " + ex.Message); }
                            try
                            {
                                if (Directory.Exists(desktopPath)) ProcessDirectory(desktopPath, sw, lnkDestDir, ref skipAccessDenied, ref skipPathTooLong, recentFolderOnly: false);
                            }
                            catch (Exception ex) { skipAccessDenied++; if (skipAccessDenied <= 2) Logger.Warning("UserActivity desktopPath: " + ex.Message); }
                        }
                    }
                }
                if (skipAccessDenied > 0 || skipPathTooLong > 0)
                    Console.WriteLine("    (Skipped: {0} access denied, {1} path too long)", skipAccessDenied, skipPathTooLong);
                Console.WriteLine(string.Format("[+] Recent files list saved to {0}", csvPath));
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("[!] Error collecting recent files: {0}", ex.Message));
                Logger.Warning("UserActivityCollector.CollectRecentFiles: " + ex.Message);
                throw;
            }
        }

        private static void ProcessDirectory(string dir, StreamWriter sw, string copyDest, ref int skipAccessDenied, ref int skipPathTooLong, bool recentFolderOnly = false)
        {
            try
            {
                foreach (string file in Directory.GetFiles(dir))
                {
                    string fileName = Path.GetFileName(file);
                    // Exclude system/hidden noise so Recent Files tab shows meaningful entries (LNK); avoid single desktop.ini row
                    if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Equals("Thumbs.db", StringComparison.OrdinalIgnoreCase))
                        continue;

                    bool isLnk = Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase);
                    // In Recent folder per SPEC only LNK are "recent files"; skip non-LNK for CSV (still copy LNK below)
                    if (recentFolderOnly && !isLnk)
                        continue;

                    // Copy .lnk first so Lnk Files (Dump) is populated even when FileInfo fails (e.g. access denied on metadata)
                    if (isLnk)
                    {
                        try
                        {
                            string safeName = fileName.Replace(" ", "_");
                            string uniquePrefix = new DirectoryInfo(dir).Name + "_";
                            File.Copy(file, Path.Combine(copyDest, uniquePrefix + safeName), true);
                        }
                        catch { /* single file copy fail */ }
                    }

                    try
                    {
                        FileInfo fi = new FileInfo(file);
                        string line = string.Format("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\"",
                            fi.Name,
                            fi.Extension,
                            fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            fi.DirectoryName
                        );
                        sw.WriteLine(line);
                    }
                    catch (UnauthorizedAccessException) { skipAccessDenied++; }
                    catch (PathTooLongException) { skipPathTooLong++; }
                    catch (Exception ex) { if (ex.Message != null && ex.Message.IndexOf("拒絕存取", StringComparison.OrdinalIgnoreCase) >= 0) skipAccessDenied++; else if (ex.Message != null && (ex.Message.IndexOf("太長", StringComparison.OrdinalIgnoreCase) >= 0 || ex.Message.IndexOf("260", StringComparison.OrdinalIgnoreCase) >= 0)) skipPathTooLong++; }
                }

                foreach (string subDir in Directory.GetDirectories(dir))
                {
                    string subName = Path.GetFileName(subDir);
                    // Jump List data (.automaticDestinations-ms, .customDestinations-ms) is collected and parsed in Jump Lists tab; skip here to reduce noise in Recent Files
                    if (subName.Equals("AutomaticDestinations", StringComparison.OrdinalIgnoreCase) ||
                        subName.Equals("CustomDestinations", StringComparison.OrdinalIgnoreCase))
                        continue;
                    ProcessDirectory(subDir, sw, copyDest, ref skipAccessDenied, ref skipPathTooLong, recentFolderOnly);
                }
            }
            catch (UnauthorizedAccessException) { skipAccessDenied++; }
            catch (PathTooLongException) { skipPathTooLong++; }
            catch (Exception ex) 
            { 
                if (ex.Message != null && ex.Message.IndexOf("拒絕存取", StringComparison.OrdinalIgnoreCase) >= 0) skipAccessDenied++; 
                else if (ex.Message != null && (ex.Message.IndexOf("太長", StringComparison.OrdinalIgnoreCase) >= 0 || ex.Message.IndexOf("260", StringComparison.OrdinalIgnoreCase) >= 0)) skipPathTooLong++; 
            }
        }

        public static void CollectRecentModifications(string outputDir)
        {
            scannedFilesCount = 0;
            Console.WriteLine("[*] Collecting Files Created/Modified in Last 7 Days...");
            string csvPath = Path.Combine(outputDir, ArtifactNames.Filesystem7DaysCsv);
            DateTime limit = DateTime.Now.AddDays(-7);
            int count = 0;

            // Wall-clock budget so the recursive scan can't run away on a large profile (the recursive
            // walk + per-file SHA-256 of C:\Users + ProgramData can take tens of minutes on a dev box).
            // Configurable; 0 or negative = unlimited (full forensic scan). Truncation is logged honestly.
            int maxSeconds = 120;
            try { int p; if (int.TryParse(new ConfigManager().Get("RecentFileScanMaxSeconds"), out p)) maxSeconds = p; } catch { }
            DateTime deadline = maxSeconds > 0 ? DateTime.UtcNow.AddSeconds(maxSeconds) : DateTime.MaxValue;
            bool truncated = false;

            try
            {
                using (StreamWriter sw = new StreamWriter(csvPath, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("Path,Size,Created,Modified,Extension,SHA256");

                    var roots = new List<string>();
                    
                    // 1. Users Directory (Profiles)
                    string sysDrive = Path.GetPathRoot(Environment.SystemDirectory);
                    if (string.IsNullOrEmpty(sysDrive)) sysDrive = "C:\\";
                    
                    string usersLink = Path.Combine(sysDrive, "Users");
                    if (Directory.Exists(usersLink)) roots.Add(usersLink);

                    // 2. Windows Temp
                    string winTemp = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot"), "Temp");
                    if (Directory.Exists(winTemp)) roots.Add(winTemp);

                    // 3. ProgramData (Optional but useful for malware persistence)
                    string progData = Path.Combine(sysDrive, "ProgramData");
                    if (Directory.Exists(progData)) roots.Add(progData);

                    int skipAccessDenied = 0, skipPathTooLong = 0;
                    foreach (var root in roots)
                    {
                        Console.WriteLine("    > Scanning: " + root);
                        ScanRecursive(root, limit, sw, ref count, ref skipAccessDenied, ref skipPathTooLong, deadline, ref truncated);
                        if (truncated) break;
                    }
                    if (truncated)
                    {
                        sw.WriteLine(string.Format("\"[TRUNCATED: recent-file scan stopped to bound live-response time after ~{0}s / {1} files scanned; set config.ini RecentFileScanMaxSeconds higher (0 = unlimited) for a fuller scan]\",0,\"\",\"\",\"\",\"\"", maxSeconds, scannedFilesCount));
                        Console.WriteLine(string.Format("    (Scan truncated at {0}s budget: {1} files scanned, {2} recent files captured.)", maxSeconds, scannedFilesCount, count));
                    }
                    if (skipAccessDenied > 0 || skipPathTooLong > 0)
                        Console.WriteLine("    (Skipped: {0} access denied, {1} path too long)", skipAccessDenied, skipPathTooLong);
                }
                Console.WriteLine();
                Console.WriteLine(string.Format("    + Found {0} recent files.", count));
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting recent modifications: " + ex.Message);
                Logger.Warning("UserActivityCollector.CollectRecentModifications: " + ex.Message);
                throw;
            }
        }

        // Limit global scan count to prevent infinite loops or huge delays
        private static int scannedFilesCount = 0;

        /// <summary>Iterative scan to avoid stack overflow on deep trees (e.g. C:\Users\...\node_modules).</summary>
        private static void ScanRecursive(string rootDir, DateTime limit, StreamWriter sw, ref int count, ref int skipAccessDenied, ref int skipPathTooLong, DateTime deadline, ref bool truncated)
        {
            var toProcess = new Queue<string>();
            toProcess.Enqueue(rootDir);

            while (toProcess.Count > 0 && scannedFilesCount <= 500000)
            {
                if (DateTime.UtcNow >= deadline) { truncated = true; return; }
                string dir = toProcess.Dequeue();
                try
                {
                    string[] files = Directory.GetFiles(dir);
                    scannedFilesCount += files.Length;
                    if (scannedFilesCount % 5000 == 0) Console.Write(".");

                    foreach (string f in files)
                    {
                        try
                        {
                            FileInfo fi = new FileInfo(f);
                            if (fi.LastWriteTime >= limit || fi.CreationTime >= limit)
                            {
                                string hash = "";
                                if (fi.Length < 50 * 1024 * 1024) hash = ComputeSha256(fi.FullName);
                                sw.WriteLine(string.Format("\"{0}\",{1},\"{2}\",\"{3}\",\"{4}\",\"{5}\"",
                                    fi.FullName.Replace("\"", "\"\""),
                                    fi.Length,
                                    fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                    fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                    fi.Extension,
                                    hash
                                ));
                                count++;
                            }
                        }
                        catch (UnauthorizedAccessException) { skipAccessDenied++; }
                        catch (PathTooLongException) { skipPathTooLong++; }
                        catch (Exception ex)
                        {
                            if (ex.Message != null && ex.Message.IndexOf("拒絕存取", StringComparison.OrdinalIgnoreCase) >= 0) skipAccessDenied++;
                            else if (ex.Message != null && (ex.Message.IndexOf("太長", StringComparison.OrdinalIgnoreCase) >= 0 || ex.Message.IndexOf("260", StringComparison.OrdinalIgnoreCase) >= 0)) skipPathTooLong++;
                        }
                    }

                    foreach (string d in Directory.GetDirectories(dir))
                    {
                        try
                        {
                            DirectoryInfo di = new DirectoryInfo(d);
                            if ((di.Attributes & FileAttributes.ReparsePoint) != 0)
                                continue;
                            string name = di.Name;
                            if (name.Equals("INetCache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("History", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Temporary Internet Files", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Cache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Code Cache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Cache_Data", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("CacheStorage", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("GPUCache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("ShaderCache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("GrShaderCache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("DawnCache", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Service Worker", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Crashpad", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                                name.StartsWith("npm-", StringComparison.OrdinalIgnoreCase))
                                continue;
                            toProcess.Enqueue(d);
                        }
                        catch (UnauthorizedAccessException) { skipAccessDenied++; }
                        catch (PathTooLongException) { skipPathTooLong++; }
                        catch (Exception ex)
                        {
                            if (ex.Message != null && ex.Message.IndexOf("拒絕存取", StringComparison.OrdinalIgnoreCase) >= 0) skipAccessDenied++;
                            else if (ex.Message != null && (ex.Message.IndexOf("太長", StringComparison.OrdinalIgnoreCase) >= 0 || ex.Message.IndexOf("260", StringComparison.OrdinalIgnoreCase) >= 0)) skipPathTooLong++;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { skipAccessDenied++; }
                catch (PathTooLongException) { skipPathTooLong++; }
                catch (Exception ex)
                {
                    if (ex.Message != null && ex.Message.IndexOf("拒絕存取", StringComparison.OrdinalIgnoreCase) >= 0) skipAccessDenied++;
                    else if (ex.Message != null && (ex.Message.IndexOf("太長", StringComparison.OrdinalIgnoreCase) >= 0 || ex.Message.IndexOf("260", StringComparison.OrdinalIgnoreCase) >= 0)) skipPathTooLong++;
                }
            }
            // Hit the global file-count backstop (not just the time budget) -> also a truncation.
            if (scannedFilesCount > 500000) truncated = true;
        }

        // Test seam: run the bounded scan over an arbitrary root. maxSeconds: >0 = budget seconds,
        // 0 = unlimited, <0 = already-expired (forces immediate truncation).
        internal static void ScanRootForTest(string root, int maxSeconds, out int count, out bool truncated)
        {
            scannedFilesCount = 0;
            count = 0; truncated = false;
            int a = 0, p = 0;
            DateTime deadline = maxSeconds > 0 ? DateTime.UtcNow.AddSeconds(maxSeconds)
                : (maxSeconds == 0 ? DateTime.MaxValue : DateTime.UtcNow.AddSeconds(-1));
            string tmpCsv = Path.Combine(Path.GetTempPath(), "ircol_scan_" + Guid.NewGuid().ToString("N") + ".csv");
            try
            {
                using (var sw = new StreamWriter(tmpCsv, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("Path,Size,Created,Modified,Extension,SHA256");
                    ScanRecursive(root, DateTime.Now.AddDays(-7), sw, ref count, ref a, ref p, deadline, ref truncated);
                }
            }
            finally { try { File.Delete(tmpCsv); } catch { } }
        }


        private static string ComputeSha256(string file)
        {
            try
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
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

    internal sealed class UserProfileInfo
    {
        public string Sid { get; set; }
        public string UserName { get; set; }
        public string ProfilePath { get; set; }
    }

    internal static class UserProfileHelper
    {
        private static readonly object _lock = new object();
        private static List<UserProfileInfo> _cachedProfiles;

        public static List<UserProfileInfo> GetUserProfiles()
        {
            lock (_lock)
            {
                if (_cachedProfiles == null)
                    _cachedProfiles = LoadProfiles();
                return new List<UserProfileInfo>(_cachedProfiles);
            }
        }

        public static string GetUserNameForPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";

            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch { return ExtractUsersFolderName(path); }

            string bestUser = "";
            int bestLen = -1;
            foreach (UserProfileInfo profile in GetUserProfiles())
            {
                string profileRoot = AppendDirectorySeparator(profile.ProfilePath);
                if (string.IsNullOrEmpty(profileRoot)) continue;
                if (fullPath.StartsWith(profileRoot, StringComparison.OrdinalIgnoreCase) && profileRoot.Length > bestLen)
                {
                    bestUser = profile.UserName ?? "";
                    bestLen = profileRoot.Length;
                }
            }

            if (!string.IsNullOrEmpty(bestUser)) return bestUser;
            return ExtractUsersFolderName(fullPath);
        }

        private static List<UserProfileInfo> LoadProfiles()
        {
            var list = new List<UserProfileInfo>();
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using (RegistryKey profileList = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (profileList != null)
                    {
                        foreach (string sid in profileList.GetSubKeyNames())
                        {
                            using (RegistryKey profile = profileList.OpenSubKey(sid))
                            {
                                if (profile == null) continue;
                                string profilePath = profile.GetValue("ProfileImagePath") as string;
                                if (string.IsNullOrEmpty(profilePath)) continue;
                                profilePath = Environment.ExpandEnvironmentVariables(profilePath).Trim();
                                if (!Directory.Exists(profilePath)) continue;
                                if (!seenPaths.Add(profilePath)) continue;

                                string userName = Path.GetFileName(profilePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                                if (string.IsNullOrEmpty(userName)) userName = sid;
                                list.Add(new UserProfileInfo { Sid = sid, UserName = userName, ProfilePath = profilePath });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("UserProfileHelper.LoadProfiles: " + ex.Message);
            }

            string currentProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(currentProfile) && Directory.Exists(currentProfile) && seenPaths.Add(currentProfile))
            {
                string currentUser = Path.GetFileName(currentProfile.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                list.Add(new UserProfileInfo { Sid = "", UserName = currentUser, ProfilePath = currentProfile });
            }

            return list;
        }

        private static string AppendDirectorySeparator(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch { return ""; }

            if (!fullPath.EndsWith(Path.DirectorySeparatorChar.ToString()) &&
                !fullPath.EndsWith(Path.AltDirectorySeparatorChar.ToString()))
                fullPath += Path.DirectorySeparatorChar;
            return fullPath;
        }

        private static string ExtractUsersFolderName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";

            string marker = Path.DirectorySeparatorChar + "Users" + Path.DirectorySeparatorChar;
            int idx = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                marker = Path.AltDirectorySeparatorChar + "Users" + Path.AltDirectorySeparatorChar;
                idx = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            }
            if (idx < 0) return "";

            int start = idx + marker.Length;
            int end = path.IndexOfAny(new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, start);
            if (end < 0) end = path.Length;
            if (end <= start) return "";
            return path.Substring(start, end - start);
        }
    }

}
