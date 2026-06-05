using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class JumpListsCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Jump Lists...");
            var entries = new List<JumpListEntry>();
            int errorCount = 0;
            
            try
            {
                foreach (UserProfileInfo profile in UserProfileHelper.GetUserProfiles())
                {
                    string recentBase = Path.Combine(profile.ProfilePath, "AppData\\Roaming\\Microsoft\\Windows\\Recent");
                    try
                    {
                        CollectFromPath(Path.Combine(recentBase, "AutomaticDestinations"), entries, "Automatic", profile.UserName, ref errorCount);
                        CollectFromPath(Path.Combine(recentBase, "CustomDestinations"), entries, "Custom", profile.UserName, ref errorCount);
                    }
                    catch (Exception ex) { errorCount++; Logger.Warning("JumpLists user dir: " + ex.Message); }
                }
            }
            catch (Exception ex)
            {
                errorCount++;
                Logger.Error("Jump Lists Collect", ex);
                Console.WriteLine("Jump Lists Error: " + ex.Message);
            }

            // Write CSV
            try
            {
                string csvPath = Path.Combine(outputDir, ArtifactNames.JumpListsCsv);
                using (StreamWriter sw = new StreamWriter(csvPath, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Time,Source,AppId,Path,User,Details");
                    foreach (var e in entries.OrderByDescending(x => x.Time))
                    {
                        string time = e.Time.Year > 1980 ? e.Time.ToString("yyyy-MM-dd HH:mm:ss") : "";
                        sw.WriteLine(string.Join(",", new string[] {
                            IR_Collect.Utils.CsvUtils.EscapeField(time),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Source),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.AppId),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Path),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.User),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.Details)
                        }));
                    }
                }
            }
            catch (Exception ex)
            {
                errorCount++;
                Console.WriteLine("Jump Lists CSV Write Error: " + ex.Message);
            }

            // Copy raw files
            try
            {
                string destDir = Path.Combine(outputDir, "JumpLists");
                if (!Directory.Exists(destDir)) Directory.CreateDirectory(destDir);
                
                foreach (var e in entries)
                {
                    if (!string.IsNullOrEmpty(e.FilePath) && File.Exists(e.FilePath))
                    {
                        string destFile = Path.Combine(destDir, Path.GetFileName(e.FilePath));
                        try { File.Copy(e.FilePath, destFile, true); } catch (Exception ex) { errorCount++; Logger.Warning("JumpLists copy: " + ex.Message); }
                    }
                }
            }
            catch (Exception ex) { errorCount++; Logger.Warning("JumpLists copy raw: " + ex.Message); }
            if (errorCount > 0)
                throw new InvalidOperationException("Jump Lists collection incomplete: " + errorCount + " error(s).");
        }

        private static void CollectFromPath(string dir, List<JumpListEntry> entries, string type, string userName, ref int errorCount)
        {
            if (!Directory.Exists(dir)) return;
            
            try
            {
                string[] files = Directory.GetFiles(dir, "*.automaticDestinations-ms");
                if (type == "Custom")
                {
                    files = Directory.GetFiles(dir, "*.customDestinations-ms");
                }

                foreach (string file in files)
                {
                    string appId = Path.GetFileNameWithoutExtension(file);
                    ParseJumpListFile(file, appId, type, userName, entries, ref errorCount);
                }
            }
            catch (Exception ex) { errorCount++; Logger.Warning("CollectFromPath: " + ex.Message); }
        }

        private static void ParseJumpListFile(string filePath, string appId, string type, string user, List<JumpListEntry> entries, ref int errorCount)
        {
            try
            {
                // Jump list files live in the user profile and are attacker-writable; cap the read so a
                // crafted multi-hundred-MB file cannot OOM the collection. Real jump lists are far smaller.
                const long MaxJumpListBytes = 16L * 1024 * 1024;
                byte[] data;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    long len = fs.Length;
                    if (len <= 0) return;
                    if (len > MaxJumpListBytes)
                    {
                        Logger.Warning("ParseJumpListFile: skipping oversized jump list (" + (len / 1024 / 1024) + " MB): " + filePath);
                        return;
                    }
                    data = new byte[(int)len];
                    // FileStream.Read may return fewer bytes than requested; loop until full or EOF so the
                    // tail is never left as stale zeros that get mis-parsed as shell-item / LNK data.
                    int total = 0;
                    int read;
                    while (total < data.Length && (read = fs.Read(data, total, data.Length - total)) > 0)
                        total += read;
                    if (total < data.Length)
                        Array.Resize(ref data, total);
                }
                string content = Encoding.Unicode.GetString(data);
                string ascii = Encoding.ASCII.GetString(data);

                var paths = ExtractPathsFromLnkStructures(data);
                if (paths.Count == 0)
                    paths = ExtractPathsFromContent(content, ascii);
                else
                {
                    var contentPaths = ExtractPathsFromContent(content, ascii);
                    var seen = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
                    foreach (var p in contentPaths)
                        if (!seen.Contains(p)) { seen.Add(p); paths.Add(p); }
                }

                if (paths.Count > 0)
                    {
                        foreach (var path in paths.Take(10)) // Limit to 10 per file
                        {
                            entries.Add(new JumpListEntry
                            {
                                Time = File.GetLastWriteTime(filePath),
                                Source = "JumpList_" + type,
                                AppId = appId,
                                Path = path,
                                User = user,
                                Details = "File: " + Path.GetFileName(filePath),
                                FilePath = filePath
                            });
                        }
                    }
                    else
                    {
                        // At least record the file exists
                        entries.Add(new JumpListEntry
                        {
                            Time = File.GetLastWriteTime(filePath),
                            Source = "JumpList_" + type,
                            AppId = appId,
                            Path = "",
                            User = user,
                            Details = "File: " + Path.GetFileName(filePath),
                            FilePath = filePath
                        });
                    }
            }
            catch (Exception ex) { errorCount++; Logger.Warning("ParseJumpListFile: " + ex.Message); }
        }

        /// <summary>Scan for LNK structures (header 0x4C) and extract LocalBasePath from LinkInfo, or fallback to UTF-16 path scan.</summary>
        private static List<string> ExtractPathsFromLnkStructures(byte[] data)
        {
            var paths = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (data == null || data.Length < 80) return paths;

            int pos = 0;
            while (pos <= data.Length - 4)
            {
                if (data[pos] == 0x4C && data[pos + 1] == 0 && data[pos + 2] == 0 && data[pos + 3] == 0)
                {
                    int skipBytes;
                    string path = TryParseLnkLocalPath(data, pos, out skipBytes);
                    if (!string.IsNullOrEmpty(path) && path.Length > 3 && path.Contains("\\") && !seen.Contains(path))
                    {
                        seen.Add(path);
                        paths.Add(path);
                    }
                    if (string.IsNullOrEmpty(path))
                    {
                        int scanEnd = Math.Min(pos + 2048, data.Length - 6);
                        for (int i = pos + 20; i < scanEnd; i += 2)
                        {
                            if (i + 6 <= data.Length && data[i] == 'C' && data[i + 1] == 0 && data[i + 2] == ':' && data[i + 3] == 0 && data[i + 4] == '\\' && data[i + 5] == 0)
                            {
                                path = ReadUtf16NullTerminated(data, i);
                                if (!string.IsNullOrEmpty(path) && path.Length > 3 && path.Length < 260 && path.Contains("\\") && !seen.Contains(path))
                                {
                                    seen.Add(path);
                                    paths.Add(path);
                                }
                                break;
                            }
                            if (i + 6 <= data.Length && data[i] == 'D' && data[i + 1] == 0 && data[i + 2] == ':' && data[i + 3] == 0 && data[i + 4] == '\\' && data[i + 5] == 0)
                            {
                                path = ReadUtf16NullTerminated(data, i);
                                if (!string.IsNullOrEmpty(path) && path.Length > 3 && path.Length < 260 && path.Contains("\\") && !seen.Contains(path))
                                {
                                    seen.Add(path);
                                    paths.Add(path);
                                }
                                break;
                            }
                        }
                        skipBytes = 76;
                    }
                    pos += Math.Max(76, skipBytes);
                }
                else
                    pos++;
            }
            return paths;
        }

        internal static string TryParseLnkLocalPath(byte[] data, int lnkStart, out int bytesConsumed)
        {
            bytesConsumed = 76;
            const int headerSize = 76;
            if (data == null || lnkStart < 0 || lnkStart + headerSize > data.Length) return null;

            // MS-SHLLINK ShellLinkHeader: LinkFlags at offset 0x14. bit0=HasLinkTargetIDList,
            // bit1=HasLinkInfo. The previous code ignored these and always read the ANSI
            // LocalBasePathOffset (0x10), mis-reading modern Unicode jump-list LNKs.
            uint linkFlags = (uint)BitConverter.ToInt32(data, lnkStart + 0x14);
            bool hasIdList = (linkFlags & 0x00000001u) != 0;
            bool hasLinkInfo = (linkFlags & 0x00000002u) != 0;

            int off = lnkStart + headerSize;
            if (hasIdList)
            {
                if (off + 2 > data.Length) return null;
                int idListSize = BitConverter.ToUInt16(data, off);
                off += 2 + idListSize;
            }
            if (!hasLinkInfo) return null;                 // no LinkInfo => no LocalBasePath here
            if (off < 0 || off + 0x14 > data.Length) return null; // need through LocalBasePathOffset (0x10..0x13)

            int linkInfoStart = off;
            int linkInfoSize = BitConverter.ToInt32(data, linkInfoStart + 0x00);
            int linkInfoHeaderSize = BitConverter.ToInt32(data, linkInfoStart + 0x04);
            uint linkInfoFlags = (uint)BitConverter.ToInt32(data, linkInfoStart + 0x08);
            if (linkInfoSize < 0x1C || linkInfoSize > 8192) { bytesConsumed = off + 4; return null; }
            bytesConsumed = linkInfoStart + linkInfoSize;
            if ((linkInfoFlags & 0x00000001u) == 0) return null; // VolumeIDAndLocalBasePath not present

            // Prefer the Unicode local base path (LocalBasePathOffsetUnicode at 0x1C) when the optional
            // offsets are present (LinkInfoHeaderSize >= 0x24); else use the ANSI offset (0x10).
            int pathOffset = 0;
            bool unicode = false;
            if (linkInfoHeaderSize >= 0x24 && linkInfoStart + 0x20 <= data.Length)
            {
                pathOffset = BitConverter.ToInt32(data, linkInfoStart + 0x1C);
                unicode = true;
            }
            if (pathOffset <= 0 || pathOffset >= linkInfoSize)
            {
                pathOffset = BitConverter.ToInt32(data, linkInfoStart + 0x10);
                unicode = false;
            }
            if (pathOffset <= 0 || pathOffset >= linkInfoSize) return null;

            int pathStart = linkInfoStart + pathOffset;
            if (pathStart < 0 || pathStart + 1 > data.Length) return null;

            string path = unicode ? ReadUtf16NullTerminated(data, pathStart) : ReadAnsiNullTerminated(data, pathStart);
            if (!string.IsNullOrEmpty(path) && path.Length > 2 && path.Length < 260) return path;
            // Last resort: try the other encoding in case LinkInfoHeaderSize was misleading.
            path = unicode ? ReadAnsiNullTerminated(data, pathStart) : ReadUtf16NullTerminated(data, pathStart);
            if (!string.IsNullOrEmpty(path) && path.Length > 2 && path.Length < 260) return path;
            return null;
        }

        private static string ReadUtf16NullTerminated(byte[] data, int start)
        {
            var sb = new StringBuilder();
            for (int i = start; i + 1 < data.Length; i += 2)
            {
                char c = (char)BitConverter.ToInt16(data, i);
                if (c == '\0') break;
                if (char.IsControl(c) && c != '\t') break;
                sb.Append(c);
                if (sb.Length >= 259) break;
            }
            return sb.ToString().Trim();
        }

        private static string ReadAnsiNullTerminated(byte[] data, int start)
        {
            var sb = new StringBuilder();
            for (int i = start; i < data.Length && i < start + 260; i++)
            {
                if (data[i] == 0) break;
                if (data[i] < 32 && data[i] != '\t') break;
                sb.Append((char)data[i]);
            }
            return sb.ToString().Trim();
        }

        private static List<string> ExtractPathsFromContent(string unicode, string ascii)
        {
            var paths = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Look for common drive patterns (C:\, D:\, etc.)
            string[] drivePatterns = { "C:\\", "D:\\", "E:\\", "F:\\" };
            foreach (var pattern in drivePatterns)
            {
                int idx = 0;
                while ((idx = unicode.IndexOf(pattern, idx)) >= 0)
                {
                    int end = idx;
                    while (end < unicode.Length && unicode[end] != '\0' && unicode[end] != '\r' && unicode[end] != '\n' && end - idx < 260)
                    {
                        end++;
                    }
                    if (end > idx)
                    {
                        string candidate = unicode.Substring(idx, end - idx).Trim();
                        if (candidate.Length > 3 && candidate.Contains("\\") && !seen.Contains(candidate))
                        {
                            seen.Add(candidate);
                            paths.Add(candidate);
                        }
                    }
                    idx = end;
                }
            }

            return paths;
        }

        private class JumpListEntry
        {
            public DateTime Time { get; set; }
            public string Source { get; set; }
            public string AppId { get; set; }
            public string Path { get; set; }
            public string User { get; set; }
            public string Details { get; set; }
            public string FilePath { get; set; }
        }
    }
}
