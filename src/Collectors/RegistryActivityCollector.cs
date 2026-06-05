using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class RegistryActivityCollector
    {
        private class ActivityEntry
        {
            public DateTime Time;
            public string Source;
            public string Action;
            public string Path;
            public string User;
            public string Details;
        }

        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Registry Activity (UserAssist/RunMRU/RecentDocs)...");
            var entries = new List<ActivityEntry>();

            try
            {
                using (RegistryKey users = Registry.Users)
                {
                    foreach (string sid in users.GetSubKeyNames())
                    {
                        if (!sid.StartsWith("S-1-5-21-")) continue;
                        using (RegistryKey userRoot = users.OpenSubKey(sid))
                        {
                            if (userRoot == null) continue;
                            string userName = GetUserNameFromSid(sid);

                            CollectRunMru(userRoot, sid, userName, entries);
                            CollectUserAssist(userRoot, sid, userName, entries);
                            CollectRecentDocs(userRoot, sid, userName, entries);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Registry Activity Error: " + ex.Message);
                Logger.Warning("RegistryActivityCollector.Collect: " + ex.Message);
                throw;
            }

            try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.ActivityTimelineCsv);
                using (StreamWriter sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Time,Source,Action,Path,User,Details");
                    foreach (var e in entries.OrderByDescending(x => x.Time))
                    {
                        string time = e.Time.Year > 1980 ? e.Time.ToString("yyyy-MM-dd HH:mm:ss") : "";
                        sw.WriteLine(string.Join(",", new string[] {
                            IR_Collect.Utils.CsvUtils.EscapeField(time),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Source),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Action),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Path),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.User),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Details)
                        }));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Registry Activity Write Error: " + ex.Message);
                Logger.Warning("RegistryActivityCollector.Write: " + ex.Message);
                throw;
            }
        }

        private static void CollectRunMru(RegistryKey userRoot, string sid, string userName, List<ActivityEntry> entries)
        {
            try
            {
                using (RegistryKey runKey = userRoot.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
                {
                    if (runKey == null) return;
                    foreach (string name in runKey.GetValueNames())
                    {
                        if (string.Equals(name, "MRUList", StringComparison.OrdinalIgnoreCase)) continue;
                        object val = runKey.GetValue(name);
                        string cmd = val as string;
                        if (string.IsNullOrEmpty(cmd)) continue;
                        cmd = cmd.Replace("\0", "").Trim();
                        entries.Add(new ActivityEntry
                        {
                            Time = DateTime.MinValue,
                            Source = "RunMRU",
                            Action = "Run",
                            Path = cmd,
                            User = string.IsNullOrEmpty(userName) ? sid : userName,
                            Details = "Value: " + name
                        });
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("CollectRunMru: " + ex.Message); }
        }

        private static void CollectUserAssist(RegistryKey userRoot, string sid, string userName, List<ActivityEntry> entries)
        {
            try
            {
                using (RegistryKey uaRoot = userRoot.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (uaRoot == null) return;
                    foreach (string guid in uaRoot.GetSubKeyNames())
                    {
                        using (RegistryKey countKey = uaRoot.OpenSubKey(guid + "\\Count"))
                        {
                            if (countKey == null) continue;
                            foreach (string name in countKey.GetValueNames())
                            {
                                if (string.Equals(name, "Version", StringComparison.OrdinalIgnoreCase)) continue;
                                object val = countKey.GetValue(name);
                                byte[] data = val as byte[];
                                if (data == null) continue;

                                string decoded = Rot13(name);
                                int runCount = 0;
                                DateTime lastRun = DateTime.MinValue;

                                try
                                {
                                    if (data.Length >= 8)
                                    {
                                        runCount = BitConverter.ToInt32(data, 4);
                                    }
                                    if (data.Length >= 68)
                                    {
                                        long ft = BitConverter.ToInt64(data, 60);
                                        if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft).ToLocalTime();
                                    }
                                    else if (data.Length >= 16)
                                    {
                                        long ft = BitConverter.ToInt64(data, 8);
                                        if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft).ToLocalTime();
                                    }
                                }
                                catch (Exception ex) { Logger.Warning("UserAssist decode: " + ex.Message); }

                                entries.Add(new ActivityEntry
                                {
                                    Time = lastRun,
                                    Source = "UserAssist",
                                    Action = "Run",
                                    Path = decoded,
                                    User = string.IsNullOrEmpty(userName) ? sid : userName,
                                    Details = "RunCount=" + runCount.ToString()
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("CollectUserAssist: " + ex.Message); }
        }

        private static void CollectRecentDocs(RegistryKey userRoot, string sid, string userName, List<ActivityEntry> entries)
        {
            try
            {
                using (RegistryKey recentRoot = userRoot.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"))
                {
                    if (recentRoot == null) return;
                    CollectRecentDocsKey(recentRoot, "", sid, userName, entries);

                    foreach (string sub in recentRoot.GetSubKeyNames())
                    {
                        using (RegistryKey subKey = recentRoot.OpenSubKey(sub))
                        {
                            if (subKey == null) continue;
                            CollectRecentDocsKey(subKey, sub, sid, userName, entries);
                        }
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("CollectRecentDocs: " + ex.Message); }
        }

        private static void CollectRecentDocsKey(RegistryKey key, string ext, string sid, string userName, List<ActivityEntry> entries)
        {
            try
            {
                foreach (string name in key.GetValueNames())
                {
                    if (string.Equals(name, "MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
                    byte[] data = key.GetValue(name) as byte[];
                    if (data == null) continue;
                    string doc = ExtractUnicodeString(data);
                    if (string.IsNullOrEmpty(doc)) continue;

                    entries.Add(new ActivityEntry
                    {
                        Time = DateTime.MinValue,
                        Source = "RecentDocs",
                        Action = "Open",
                        Path = doc,
                        User = string.IsNullOrEmpty(userName) ? sid : userName,
                        Details = string.IsNullOrEmpty(ext) ? "" : ("Ext=" + ext)
                    });
                }
            }
            catch (Exception ex) { Logger.Warning("CollectRecentDocsKey: " + ex.Message); }
        }

        private static string ExtractUnicodeString(byte[] data)
        {
            try
            {
                string s = Encoding.Unicode.GetString(data);
                int idx = s.IndexOf('\0');
                if (idx >= 0) s = s.Substring(0, idx);
                return s.Trim();
            }
            catch (Exception ex) { Logger.Warning("ExtractUnicodeString: " + ex.Message); }
            return "";
        }

        private static string Rot13(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            char[] arr = input.ToCharArray();
            for (int i = 0; i < arr.Length; i++)
            {
                char c = arr[i];
                if (c >= 'a' && c <= 'z')
                {
                    arr[i] = (char)('a' + (c - 'a' + 13) % 26);
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    arr[i] = (char)('A' + (c - 'A' + 13) % 26);
                }
            }
            return new string(arr);
        }

        private static string GetUserNameFromSid(string sid)
        {
            try
            {
                using (RegistryKey prof = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid))
                {
                    if (prof == null) return sid;
                    string path = prof.GetValue("ProfileImagePath") as string;
                    if (string.IsNullOrEmpty(path)) return sid;
                    return Path.GetFileName(path);
                }
            }
            catch (Exception ex) { Logger.Warning("GetUserNameFromSid: " + ex.Message); }
            return sid;
        }
    }
}
