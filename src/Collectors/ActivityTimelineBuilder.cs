using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class ActivityTimelineBuilder
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

        public static void Build(string outputDir)
        {
            Console.WriteLine("[*] Building Unified Activity Timeline...");
            var allEntries = new List<ActivityEntry>();

            // 1. Registry Activity (already collected)
            LoadFromCsv(Path.Combine(outputDir, ArtifactNames.ActivityTimelineCsv), allEntries);

            // 2. Jump Lists
            LoadFromCsv(Path.Combine(outputDir, ArtifactNames.JumpListsCsv), allEntries, "JumpList");

            // 3. Prefetch (parse .pf files)
            LoadPrefetchActivities(outputDir, allEntries);

            // 4. Recent Files
            LoadRecentFilesActivities(outputDir, allEntries);

            // 5. Process List (from collection time)
            LoadProcessActivities(outputDir, allEntries);

            // Write unified timeline
            try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.ActivityTimelineCsv);
                using (StreamWriter sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Time,Source,Action,Path,User,Details");
                    foreach (var e in allEntries.OrderByDescending(x => x.Time))
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
                Console.WriteLine("    [+] Unified Timeline: " + allEntries.Count.ToString("N0") + " entries");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Activity Timeline Build Error: " + ex.Message);
                Logger.Error("ActivityTimelineBuilder.Build", ex);
            }
        }

        private static void LoadFromCsv(string path, List<ActivityEntry> entries, string sourceOverride = null)
        {
            if (!File.Exists(path)) return;
            try
            {
                using (StreamReader sr = new StreamReader(path))
                {
                    string header = sr.ReadLine();
                    if (string.IsNullOrEmpty(header)) return;

                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = SplitCsvLine(line);
                        if (parts.Length < 6) continue;

                        DateTime dt;
                        if (!DateTime.TryParse(parts[0], out dt)) dt = DateTime.MinValue;

                        entries.Add(new ActivityEntry
                        {
                            Time = dt,
                            Source = sourceOverride ?? parts[1],
                            Action = parts[2],
                            Path = parts[3],
                            User = parts[4],
                            Details = parts[5]
                        });
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("LoadRegistryActivities: " + ex.Message); }
        }

        private static void LoadPrefetchActivities(string outputDir, List<ActivityEntry> entries)
        {
            string prefetchDir = Path.Combine(outputDir, "Prefetch");
            if (!Directory.Exists(prefetchDir)) return;

            try
            {
                string[] pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
                foreach (string pf in pfFiles)
                {
                    string name = Path.GetFileNameWithoutExtension(pf);
                    DateTime modTime = File.GetLastWriteTime(pf);
                    
                    entries.Add(new ActivityEntry
                    {
                        Time = modTime,
                        Source = "Prefetch",
                        Action = "Execute",
                        Path = name,
                        User = "",
                        Details = "Last Run: " + modTime.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }
            }
            catch (Exception ex) { Logger.Warning("LoadPrefetchActivities: " + ex.Message); }
        }

        private static void LoadRecentFilesActivities(string outputDir, List<ActivityEntry> entries)
        {
            string csvPath = Path.Combine(outputDir, ArtifactNames.RecentFilesCsv);
            if (!File.Exists(csvPath)) return;

            try
            {
                using (StreamReader sr = new StreamReader(csvPath))
                {
                    string header = sr.ReadLine();
                    if (string.IsNullOrEmpty(header)) return;

                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = SplitCsvLine(line);
                        if (parts.Length < 5) continue;

                        DateTime dt;
                        if (!DateTime.TryParse(parts[2], out dt)) dt = DateTime.MinValue;

                        entries.Add(new ActivityEntry
                        {
                            Time = dt,
                            Source = "RecentFiles",
                            Action = "Access",
                            Path = parts[0],
                            User = ResolveUserFromPath(parts[4]),
                            Details = "Directory: " + parts[4]
                        });
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("LoadRecentFilesActivities: " + ex.Message); }
        }

        private static void LoadProcessActivities(string outputDir, List<ActivityEntry> entries)
        {
            string csvPath = Path.Combine(outputDir, ArtifactNames.ProcessListCsv);
            if (!File.Exists(csvPath)) return;

            try
            {
                using (StreamReader sr = new StreamReader(csvPath))
                {
                    string header = sr.ReadLine();
                    if (string.IsNullOrEmpty(header)) return;

                    int idxPath = -1, idxStartTime = -1, idxName = -1, idxCmd = -1, idxUser = -1;
                    string[] headers = SplitCsvLine(header);
                    for (int i = 0; i < headers.Length; i++)
                    {
                        string h = headers[i].Trim();
                        if (string.Equals(h, "Path", StringComparison.OrdinalIgnoreCase)) idxPath = i;
                        else if (string.Equals(h, "StartTime", StringComparison.OrdinalIgnoreCase)) idxStartTime = i;
                        else if (string.Equals(h, "Name", StringComparison.OrdinalIgnoreCase)) idxName = i;
                        else if (string.Equals(h, "CommandLine", StringComparison.OrdinalIgnoreCase)) idxCmd = i;
                        else if (string.Equals(h, "User", StringComparison.OrdinalIgnoreCase)) idxUser = i;
                    }

                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = SplitCsvLine(line);
                        if (parts.Length < Math.Max(idxPath, idxStartTime) + 1) continue;

                        DateTime dt = DateTime.MinValue;
                        if (idxStartTime >= 0 && idxStartTime < parts.Length)
                        {
                            DateTime.TryParse(parts[idxStartTime], out dt);
                        }

                        string path = (idxPath >= 0 && idxPath < parts.Length) ? parts[idxPath] : "";
                        string name = (idxName >= 0 && idxName < parts.Length) ? parts[idxName] : "";
                        string cmd = (idxCmd >= 0 && idxCmd < parts.Length) ? parts[idxCmd] : "";
                        string user = (idxUser >= 0 && idxUser < parts.Length) ? parts[idxUser] : "";

                        entries.Add(new ActivityEntry
                        {
                            Time = dt,
                            Source = "Process",
                            Action = "Run",
                            Path = path,
                            User = user,
                            Details = string.IsNullOrEmpty(cmd) ? name : cmd
                        });
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("LoadProcessActivities: " + ex.Message); }
        }

        internal static string ResolveUserFromPath(string path)
        {
            return UserProfileHelper.GetUserNameForPath(path);
        }

        private static string[] SplitCsvLine(string line)
        {
            line = line.Trim();
            List<string> result = new List<string>();
            bool inQuotes = false;
            StringBuilder current = new StringBuilder();

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '\"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '\"')
                    {
                        current.Append('\"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
            result.Add(current.ToString());
            return result.ToArray();
        }
    }
}
