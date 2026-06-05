using System;
using System.Collections.Generic;
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

                foreach (string valueName in key.GetValueNames())
                {
                    try
                    {
                        object raw = key.GetValue(valueName);
                        byte[] data = raw as byte[];
                        if (data == null || data.Length == 0)
                        {
                            result.FallbackUsed = true;
                            result.ParserNotes.Add("ShimCache value '" + valueName + "' was not binary or empty.");
                            continue;
                        }

                        var paths = ExtractLikelyPaths(data);
                        string hashPrefix = ComputeSha256Prefix(data);
                        if (paths.Count == 0)
                        {
                            result.FallbackUsed = true;
                            result.Entries.Add(new ShimCacheEntryRecord
                            {
                                RegistryPath = @"HKLM\" + RegistryPath,
                                ValueName = valueName,
                                EntryIndex = 0,
                                Path = "",
                                FileName = "",
                                LastModifiedTime = "",
                                DataHashPrefix = hashPrefix,
                                ParserNote = "Entry-level reconstruction did not find reliable executable paths in this value; keep raw ShimCache metadata for offline parsing."
                            });
                            continue;
                        }

                        for (int i = 0; i < paths.Count; i++)
                        {
                            string p = paths[i];
                            result.Entries.Add(new ShimCacheEntryRecord
                            {
                                RegistryPath = @"HKLM\" + RegistryPath,
                                ValueName = valueName,
                                EntryIndex = i + 1,
                                Path = p,
                                FileName = SafeFileName(p),
                                LastModifiedTime = "",
                                DataHashPrefix = hashPrefix,
                                ParserNote = "Path reconstructed from ShimCache binary entry stream; timestamp availability depends on Windows version."
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        result.FallbackUsed = true;
                        result.ParserNotes.Add("ShimCache parse failed for value '" + valueName + "': " + ex.Message);
                    }
                }
            }

            if (result.Entries.Count == 0)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("ShimCache parser produced no entry-level rows.");
            }
            return result;
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
