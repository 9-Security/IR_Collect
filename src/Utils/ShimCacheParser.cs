using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace IR_Collect.Utils
{
    public sealed class ShimCacheEntryRecord
    {
        public string RegistryPath { get; set; }
        public string ValueName { get; set; }
        public int EntryIndex { get; set; }
        public string Path { get; set; }
        public string FileName { get; set; }
        public string LastModifiedTime { get; set; }
        public string DataHashPrefix { get; set; }
        public string ParserNote { get; set; }
    }

    public sealed class ShimCacheParseResult
    {
        public List<ShimCacheEntryRecord> Entries { get; private set; }
        public List<string> ParserNotes { get; private set; }
        public bool FallbackUsed { get; set; }

        public ShimCacheParseResult()
        {
            Entries = new List<ShimCacheEntryRecord>();
            ParserNotes = new List<string>();
        }
    }

    public static class ShimCacheParser
    {
        private const string RegistryPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

        public static ShimCacheParseResult ParseFromLiveRegistry()
        {
            var result = new ShimCacheParseResult();
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RegistryPath))
            {
                if (key == null)
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("ShimCache registry key not found.");
                    return result;
                }
                ParseKeyValues(key, result, @"HKLM\" + RegistryPath);
            }

            if (result.Entries.Count == 0)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("ShimCache parser produced no entry-level rows.");
            }
            return result;
        }

        /// <summary>
        /// Parse ShimCache from an offline SYSTEM hive file (e.g. a triage copy) by reg-loading it and
        /// reading the AppCompatCache value of ControlSet001. Needs admin (reg load = SeRestorePrivilege).
        /// Used by the differential-validation CLI to diff against AppCompatCacheParser on the same hive.
        /// </summary>
        public static ShimCacheParseResult ParseFromHiveFile(string systemHivePath)
        {
            var result = new ShimCacheParseResult();
            if (string.IsNullOrWhiteSpace(systemHivePath) || !File.Exists(systemHivePath))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SYSTEM hive not found.");
                return result;
            }

            string mount = "IRCOL_SHIM_" + Guid.NewGuid().ToString("N");
            string mountFull = "HKU\\" + mount;
            bool loaded = false;
            try
            {
                string loadErr;
                if (!RunReg("load \"" + mountFull + "\" \"" + systemHivePath + "\"", out loadErr))
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("reg load failed for SYSTEM hive (admin?): " + Shorten(loadErr, 200));
                    return result;
                }
                loaded = true;

                // A loaded SYSTEM hive has no CurrentControlSet link; use Select\Current to pick the set,
                // falling back to ControlSet001.
                string cs = "ControlSet001";
                using (var sel = Registry.Users.OpenSubKey(mount + "\\Select"))
                {
                    if (sel != null)
                    {
                        object cur = sel.GetValue("Current");
                        if (cur is int) cs = "ControlSet" + ((int)cur).ToString("D3");
                    }
                }

                string subPath = mount + "\\" + cs + "\\Control\\Session Manager\\AppCompatCache";
                using (var key = Registry.Users.OpenSubKey(subPath))
                {
                    if (key == null)
                    {
                        result.FallbackUsed = true;
                        result.ParserNotes.Add("AppCompatCache key not found in SYSTEM hive (" + cs + ").");
                        return result;
                    }
                    ParseKeyValues(key, result, @"HKLM\SYSTEM\" + cs + @"\Control\Session Manager\AppCompatCache");
                }
            }
            catch (Exception ex)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("ShimCache hive parse exception: " + Shorten(ex.Message, 200));
            }
            finally
            {
                if (loaded)
                {
                    string unloadErr;
                    RunReg("unload \"" + mountFull + "\"", out unloadErr);
                }
            }

            if (result.Entries.Count == 0 && !result.FallbackUsed)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("ShimCache hive parse produced no entry-level rows.");
            }
            return result;
        }

        private static void ParseKeyValues(RegistryKey key, ShimCacheParseResult result, string regPathLabel)
        {
            foreach (string valueName in key.GetValueNames())
                ParseSingleValue(valueName, key.GetValue(valueName) as byte[], regPathLabel, result);
        }

        /// <summary>
        /// Parse one AppCompatCache binary value. Prefers a structured Win8/Win10 walk (recovers each
        /// entry's LastModified FILETIME); falls back to the byte-scan heuristic for formats we do not
        /// structurally decode (Win7/XP/unknown). Exposed for unit tests via ParseValueBytesForTest.
        /// </summary>
        private static void ParseSingleValue(string valueName, byte[] data, string regPathLabel, ShimCacheParseResult result)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("ShimCache value '" + valueName + "' was not binary or empty.");
                    return;
                }

                string hashPrefix = ComputeSha256Prefix(data);

                // Preferred: structured Win8/Win10 ("00ts"/"10ts") entries, which carry a real per-entry
                // LastModified FILETIME the heuristic cannot recover.
                if (TryParseWin10Entries(data, valueName, regPathLabel, hashPrefix, result))
                    return;

                // Fallback: byte-scan heuristic (no timestamps) for other/older formats.
                var paths = ExtractLikelyPaths(data);
                if (paths.Count == 0)
                {
                    result.FallbackUsed = true;
                    result.Entries.Add(new ShimCacheEntryRecord
                    {
                        RegistryPath = regPathLabel,
                        ValueName = valueName,
                        EntryIndex = 0,
                        Path = "",
                        FileName = "",
                        LastModifiedTime = "",
                        DataHashPrefix = hashPrefix,
                        ParserNote = "Entry-level reconstruction did not find reliable executable paths in this value; keep raw ShimCache metadata for offline parsing."
                    });
                    return;
                }

                for (int i = 0; i < paths.Count; i++)
                {
                    string p = paths[i];
                    result.Entries.Add(new ShimCacheEntryRecord
                    {
                        RegistryPath = regPathLabel,
                        ValueName = valueName,
                        EntryIndex = i + 1,
                        Path = p,
                        FileName = SafeFileName(p),
                        LastModifiedTime = "",
                        DataHashPrefix = hashPrefix,
                        ParserNote = "Path reconstructed from ShimCache binary entry stream (heuristic; no structured timestamp for this Windows version)."
                    });
                }
            }
            catch (Exception ex)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("ShimCache parse failed for value '" + valueName + "': " + ex.Message);
            }
        }

        /// <summary>Test seam: structured+heuristic parse of a single AppCompatCache value's bytes.</summary>
        internal static ShimCacheParseResult ParseValueBytesForTest(string valueName, byte[] data)
        {
            var result = new ShimCacheParseResult();
            ParseSingleValue(valueName, data, "TEST", result);
            return result;
        }

        // ---- Structured Win8/Win10 AppCompatCache (the "00ts"/"10ts" entry format) ----------------
        //
        // Layout (Win10/Win11, "10ts"; Win8/8.1 is identical but "00ts"):
        //   header                : header-size bytes; the header-size DWORD at offset 0 also points
        //                           at the first entry (0x30 on early Win10, 0x34 on 1607+).
        //   per entry:
        //     0x00  signature      4   "10ts" / "00ts"
        //     0x04  unknown/seq    4
        //     0x08  entryDataSize  4   bytes that follow THIS field (path-len .. end of entry data)
        //     0x0C  pathSize       2   bytes of UTF-16LE path
        //     0x0E  path           pathSize
        //     +     lastModified   8   FILETIME (UTC)
        //     +     dataSize       4
        //     +     data           dataSize
        // We locate the first entry from the header DWORD when it is sane, else scan for the signature,
        // then walk entries by their self-describing sizes (robust to header-version drift).

        private static bool TryParseWin10Entries(byte[] data, string valueName, string regPathLabel, string hashPrefix, ShimCacheParseResult result)
        {
            if (data == null || data.Length < 16) return false;

            int start = BitConverter.ToInt32(data, 0); // header size == offset to first record on Win8/10
            if (start < 4 || start > data.Length - 12 || !IsEntrySig(data, start))
            {
                start = FindFirstSig(data);
                if (start < 0) return false;
            }

            int pos = start;
            int index = 0;
            bool any = false;
            // Bound the walk so a malformed length cannot spin; real caches are well under this.
            while (pos + 14 <= data.Length && IsEntrySig(data, pos) && index < 100000)
            {
                int p = pos + 8;                                    // skip signature + unknown/seq
                int entryDataSize = BitConverter.ToInt32(data, p); p += 4;
                if (entryDataSize < 2) break;
                long entryEndL = (long)p + entryDataSize;
                if (entryEndL <= p || entryEndL > data.Length) break;
                int entryEnd = (int)entryEndL;

                int pathSize = BitConverter.ToUInt16(data, p); p += 2;
                if (pathSize < 0 || p + pathSize > entryEnd) break;
                string path = Encoding.Unicode.GetString(data, p, pathSize).Trim('\0').Trim();
                p += pathSize;

                string lmtIso = "";
                if (p + 8 <= entryEnd)
                    lmtIso = FileTimeToIso(BitConverter.ToInt64(data, p));

                if (!string.IsNullOrEmpty(path))
                {
                    result.Entries.Add(new ShimCacheEntryRecord
                    {
                        RegistryPath = regPathLabel,
                        ValueName = valueName,
                        EntryIndex = ++index,
                        Path = path,
                        FileName = SafeFileName(path),
                        LastModifiedTime = lmtIso,
                        DataHashPrefix = hashPrefix,
                        ParserNote = "Structured Win8/Win10 AppCompatCache entry; LastModified is the file's mtime recorded at cache insertion (UTC)."
                    });
                    any = true;
                }
                pos = entryEnd;
            }
            return any;
        }

        private static bool IsEntrySig(byte[] d, int off)
        {
            if (off < 0 || off + 4 > d.Length) return false;
            // "10ts" (Win10/11) or "00ts" (Win8/8.1)
            return d[off + 1] == 0x30 && d[off + 2] == 0x74 && d[off + 3] == 0x73
                && (d[off] == 0x31 || d[off] == 0x30);
        }

        private static int FindFirstSig(byte[] d)
        {
            for (int i = 0; i + 4 <= d.Length; i++)
                if (IsEntrySig(d, i)) return i;
            return -1;
        }

        private static string FileTimeToIso(long fileTime)
        {
            if (fileTime <= 0) return "";
            try
            {
                DateTime dt = DateTime.FromFileTimeUtc(fileTime);
                if (dt.Year < 1980 || dt.Year > 2200) return "";
                return dt.ToString("yyyy-MM-ddTHH:mm:ss");
            }
            catch { return ""; }
        }

        private static bool RunReg(string command, out string stdErr)
        {
            var psi = new ProcessStartInfo("reg.exe", command)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using (var p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                stdErr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0;
            }
        }

        private static string Shorten(string text, int maxLen)
        {
            if (string.IsNullOrWhiteSpace(text) || maxLen <= 0) return "";
            return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
        }

        private static List<string> ExtractLikelyPaths(byte[] data)
        {
            var ordered = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string token in ExtractUtf16Tokens(data))
            {
                string path = NormalizeCandidatePath(token);
                if (string.IsNullOrWhiteSpace(path)) continue;
                if (seen.Add(path)) ordered.Add(path);
            }
            foreach (string token in ExtractAsciiTokens(data))
            {
                string path = NormalizeCandidatePath(token);
                if (string.IsNullOrWhiteSpace(path)) continue;
                if (seen.Add(path)) ordered.Add(path);
            }

            return ordered;
        }

        private static IEnumerable<string> ExtractUtf16Tokens(byte[] data)
        {
            if (data == null || data.Length < 4) yield break;
            string utf16 = Encoding.Unicode.GetString(data);
            foreach (string chunk in utf16.Split('\0'))
            {
                if (string.IsNullOrWhiteSpace(chunk)) continue;
                yield return chunk.Trim();
            }
        }

        private static IEnumerable<string> ExtractAsciiTokens(byte[] data)
        {
            if (data == null || data.Length == 0) yield break;
            string ascii = Encoding.ASCII.GetString(data);
            var sb = new StringBuilder();
            for (int i = 0; i < ascii.Length; i++)
            {
                char c = ascii[i];
                if (c >= 32 && c < 127)
                {
                    sb.Append(c);
                }
                else
                {
                    if (sb.Length > 6)
                        yield return sb.ToString();
                    sb.Clear();
                }
            }
            if (sb.Length > 6)
                yield return sb.ToString();
        }

        private static string NormalizeCandidatePath(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return "";
            string v = token.Trim().Trim('"');
            if (v.Length < 5)
                return "";
            if (v.IndexOf(':') != 1 && !v.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                return "";
            if (v.IndexOf('\\') < 0 && v.IndexOf('/') < 0)
                return "";

            string lower = v.ToLowerInvariant();
            bool seemsExecutable =
                lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".sys") ||
                lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".ps1") ||
                lower.Contains(@"\windows\") || lower.Contains(@"\program files\") || lower.Contains(@"\users\");
            if (!seemsExecutable)
                return "";

            return EventLogDataHelper.SanitizeSingleLine(v);
        }

        private static string SafeFileName(string path)
        {
            try { return Path.GetFileName(path ?? ""); }
            catch { return ""; }
        }

        private static string ComputeSha256Prefix(byte[] data)
        {
            if (data == null || data.Length == 0)
                return "";
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
            }
        }
    }
}
