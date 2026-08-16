using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    internal sealed class JumpListPathExtractionResult
    {
        public JumpListPathExtractionResult()
        {
            Paths = new List<string>();
            Warnings = new List<string>();
        }

        public List<string> Paths { get; private set; }
        public string ParserMode { get; set; }
        public bool FallbackUsed { get; set; }
        public List<string> Warnings { get; private set; }
    }

    public static class JumpListsCollector
    {
        private const int MaxExtractedPaths = 4096;

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
                var copiedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var e in entries)
                {
                    if (!string.IsNullOrEmpty(e.FilePath) && copiedFiles.Add(e.FilePath) && File.Exists(e.FilePath))
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
                JumpListPathExtractionResult extraction = ExtractJumpListPathsWithDiagnostics(data);
                string details = BuildCollectorDetails(Path.GetFileName(filePath), extraction);

                if (extraction.Paths.Count > 0)
                    {
                        foreach (var path in extraction.Paths)
                        {
                            entries.Add(new JumpListEntry
                            {
                                Time = File.GetLastWriteTime(filePath),
                                Source = "JumpList_" + type,
                                AppId = appId,
                                Path = path,
                                User = user,
                                Details = details,
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
                            Details = details,
                            FilePath = filePath
                        });
                    }
            }
            catch (Exception ex) { errorCount++; Logger.Warning("ParseJumpListFile: " + ex.Message); }
        }

        /// <summary>
        /// Extract target paths from a jump-list file's bytes exactly as collection does: OLE-CFB
        /// streams first when present, then a bounded raw LNK/content fallback for recovery.
        /// Shared by ParseJumpListFile and the -parse differential-validation CLI so the two never drift.
        /// </summary>
        internal static List<string> ExtractJumpListPaths(byte[] data)
        {
            return ExtractJumpListPathsWithDiagnostics(data).Paths;
        }

        internal static JumpListPathExtractionResult ExtractJumpListPathsWithDiagnostics(byte[] data)
        {
            var extraction = new JumpListPathExtractionResult();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (data == null || data.Length == 0)
            {
                extraction.ParserMode = "ByteScanFallback";
                extraction.FallbackUsed = true;
                AddExtractionWarning(extraction, "Jump List input is empty.");
                return extraction;
            }

            OleCompoundFileResult compound = OleCompoundFileReader.Read(data);
            if (compound.IsCompoundFile)
            {
                extraction.ParserMode = "OLE-CFB";
                bool streamContentFallback = false;
                for (int i = 0; i < compound.Streams.Count; i++)
                {
                    OleCompoundStream stream = compound.Streams[i];
                    if (stream == null || stream.Data == null ||
                        string.Equals(stream.Name, "DestList", StringComparison.OrdinalIgnoreCase))
                        continue;

                    MergePaths(extraction, seen, ExtractPathsFromLnkStructures(stream.Data));
                    int beforeContent = extraction.Paths.Count;
                    MergePaths(extraction, seen, ExtractPathsFromContent(stream.Data));
                    if (extraction.Paths.Count > beforeContent)
                        streamContentFallback = true;
                }

                int beforeRawFallback = extraction.Paths.Count;
                MergePaths(extraction, seen, ExtractPathsFromLnkStructures(data));
                MergePaths(extraction, seen, ExtractPathsFromContent(data));
                if (extraction.Paths.Count > beforeRawFallback)
                {
                    extraction.FallbackUsed = true;
                    AddExtractionWarning(extraction, "Raw byte scan recovered paths outside reconstructed CFB streams.");
                }
                if (streamContentFallback)
                {
                    extraction.FallbackUsed = true;
                    AddExtractionWarning(extraction, "Path-like content fallback supplemented structured LNK fields.");
                }
                if (!compound.IsComplete)
                {
                    extraction.FallbackUsed = true;
                    for (int i = 0; i < compound.Warnings.Count; i++)
                        AddExtractionWarning(extraction, compound.Warnings[i]);
                }
                if (extraction.FallbackUsed)
                    extraction.ParserMode = "OLE-CFB+Fallback";
            }
            else
            {
                extraction.ParserMode = "ByteScanFallback";
                extraction.FallbackUsed = true;
                MergePaths(extraction, seen, ExtractPathsFromLnkStructures(data));
                MergePaths(extraction, seen, ExtractPathsFromContent(data));
                AddExtractionWarning(extraction, "Input is not an OLE-CFB container; bounded LNK/content scan was used.");
            }
            return extraction;
        }

        /// <summary>Scan for complete ShellLink headers and extract LocalBasePath from LinkInfo.</summary>
        internal static List<string> ExtractPathsFromLnkStructures(byte[] data)
        {
            var paths = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (data == null || data.Length < 80) return paths;

            int pos = 0;
            while (pos <= data.Length - 4)
            {
                if (IsShellLinkHeader(data, pos))
                {
                    int skipBytes;
                    string path = TryParseLnkLocalPath(data, pos, out skipBytes);
                    if (!string.IsNullOrEmpty(path) && path.Length > 3 && path.Contains("\\") && !seen.Contains(path))
                    {
                        seen.Add(path);
                        paths.Add(path);
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
            if (!IsShellLinkHeader(data, lnkStart)) return null;

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
            if (linkInfoSize < 0x1C || linkInfoSize > 8192)
            {
                bytesConsumed = Math.Max(headerSize, (off + 4) - lnkStart);
                return null;
            }
            if (linkInfoHeaderSize < 0x1C || linkInfoHeaderSize > linkInfoSize ||
                (long)linkInfoStart + linkInfoSize > data.Length)
                return null;
            bytesConsumed = (linkInfoStart + linkInfoSize) - lnkStart;
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
            if (!string.IsNullOrEmpty(path) && path.Length > 2 && path.Length <= 1024) return path;
            // Last resort: try the other encoding in case LinkInfoHeaderSize was misleading.
            path = unicode ? ReadAnsiNullTerminated(data, pathStart) : ReadUtf16NullTerminated(data, pathStart);
            if (!string.IsNullOrEmpty(path) && path.Length > 2 && path.Length <= 1024) return path;
            return null;
        }

        private static bool IsShellLinkHeader(byte[] data, int start)
        {
            if (data == null || start < 0 || start + 20 > data.Length)
                return false;
            if (data[start] != 0x4C || data[start + 1] != 0 || data[start + 2] != 0 || data[start + 3] != 0)
                return false;
            byte[] clsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
            for (int i = 0; i < clsid.Length; i++)
                if (data[start + 4 + i] != clsid[i])
                    return false;
            return true;
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
                if (sb.Length >= 1024) break;
            }
            return sb.ToString().Trim();
        }

        private static string ReadAnsiNullTerminated(byte[] data, int start)
        {
            var sb = new StringBuilder();
            for (int i = start; i < data.Length && i < start + 1025; i++)
            {
                if (data[i] == 0) break;
                if (data[i] < 32 && data[i] != '\t') break;
                sb.Append((char)data[i]);
            }
            return sb.ToString().Trim();
        }

        private static List<string> ExtractPathsFromContent(byte[] data)
        {
            var paths = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (data == null || data.Length == 0)
                return paths;

            ExtractPathsFromText(Encoding.Unicode.GetString(data), paths, seen);
            ExtractPathsFromText(Encoding.ASCII.GetString(data), paths, seen);
            return paths;
        }

        private static void ExtractPathsFromText(string text, List<string> paths, HashSet<string> seen)
        {
            if (string.IsNullOrEmpty(text))
                return;
            for (char drive = 'A'; drive <= 'Z' && paths.Count < MaxExtractedPaths; drive++)
            {
                string pattern = drive + ":\\";
                int idx = 0;
                while (idx < text.Length && (idx = text.IndexOf(pattern, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    AddTextCandidate(text, idx, paths, seen);
                    idx += pattern.Length;
                }
            }

            string[] destinationPrefixes = { "https://", "http://", "knownfolder:" };
            for (int p = 0; p < destinationPrefixes.Length && paths.Count < MaxExtractedPaths; p++)
            {
                string prefix = destinationPrefixes[p];
                int idx = 0;
                while (idx < text.Length &&
                    (idx = text.IndexOf(prefix, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    AddTextCandidate(text, idx, paths, seen);
                    idx += prefix.Length;
                }
            }

            int unc = 0;
            while (paths.Count < MaxExtractedPaths && unc < text.Length &&
                (unc = text.IndexOf("\\\\", unc, StringComparison.Ordinal)) >= 0)
            {
                AddTextCandidate(text, unc, paths, seen);
                unc += 2;
            }
        }

        private static void AddTextCandidate(string text, int start, List<string> paths, HashSet<string> seen)
        {
            bool knownFolder = text.IndexOf("knownfolder:", start, StringComparison.OrdinalIgnoreCase) == start;
            int end = start;
            while (end < text.Length && end - start < 1024)
            {
                char c = text[end];
                if (c == '\0' || c == '\r' || c == '\n' || c == '"' || c == '<' ||
                    (c == '>' && !knownFolder) || c == '|')
                    break;
                if (char.IsControl(c))
                    break;
                end++;
            }
            if (end <= start)
                return;
            string candidate = text.Substring(start, end - start).Trim().TrimEnd('.', ',', ';');
            if (candidate.Length < 3 || !IsLikelyAbsolutePath(candidate))
                return;
            if (seen.Add(candidate))
                paths.Add(candidate);
        }

        private static bool IsLikelyAbsolutePath(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;
            if (value.Length >= 3 && char.IsLetter(value[0]) && value[1] == ':' && value[2] == '\\')
                return true;
            if (value.Length >= 5 && value[0] == '\\' && value[1] == '\\' && value.IndexOf('\\', 2) > 2)
                return true;
            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return value.IndexOf('/', value.IndexOf("://", StringComparison.Ordinal) + 3) > 0;
            return value.StartsWith("knownfolder:", StringComparison.OrdinalIgnoreCase) && value.Length > 12;
        }

        private static void MergePaths(JumpListPathExtractionResult extraction, HashSet<string> seen,
            IEnumerable<string> candidates)
        {
            if (candidates == null)
                return;
            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate) || !seen.Add(candidate))
                    continue;
                if (extraction.Paths.Count >= MaxExtractedPaths)
                {
                    AddExtractionWarning(extraction, "Jump List path output reached the supported 4096-entry limit.");
                    extraction.FallbackUsed = true;
                    return;
                }
                extraction.Paths.Add(candidate);
            }
        }

        private static void AddExtractionWarning(JumpListPathExtractionResult extraction, string warning)
        {
            const int MaxWarnings = 20;
            if (extraction == null || string.IsNullOrWhiteSpace(warning) ||
                extraction.Warnings.Count >= MaxWarnings || extraction.Warnings.Contains(warning))
                return;
            extraction.Warnings.Add(warning);
        }

        private static string BuildCollectorDetails(string fileName, JumpListPathExtractionResult extraction)
        {
            var details = new StringBuilder();
            details.Append("File: ").Append(fileName ?? "");
            details.Append("; Parser=").Append(extraction != null ? extraction.ParserMode : "Unknown");
            if (extraction != null && extraction.FallbackUsed)
                details.Append("; Fallback=true");
            if (extraction != null && extraction.Warnings.Count > 0)
            {
                details.Append("; ParserNote=");
                for (int i = 0; i < extraction.Warnings.Count; i++)
                {
                    if (i > 0) details.Append(" | ");
                    details.Append((extraction.Warnings[i] ?? "").Replace("\r", " ").Replace("\n", " ").Replace(";", ","));
                }
            }
            return details.ToString();
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
