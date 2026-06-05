using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace IR_Collect.Utils
{
    public sealed class AmcacheProgramRecord
    {
        public string RegistryKey { get; set; }
        public string ProgramName { get; set; }
        public string Publisher { get; set; }
        public string Version { get; set; }
        public string ProductName { get; set; }
        public string InstallDate { get; set; }
        public string UninstallString { get; set; }
        public string ProgramId { get; set; }
        public string ParserNote { get; set; }
    }

    public sealed class AmcacheFileRecord
    {
        public string RegistryKey { get; set; }
        public string Path { get; set; }
        public string FileName { get; set; }
        public string Hash { get; set; }
        public string ProductName { get; set; }
        public string Publisher { get; set; }
        public string ProgramId { get; set; }
        public string FirstObservedTime { get; set; }
        public string ExecutedTime { get; set; }
        public string ParserNote { get; set; }
    }

    public sealed class AmcacheParseResult
    {
        public List<AmcacheProgramRecord> Programs { get; private set; }
        public List<AmcacheFileRecord> Files { get; private set; }
        public List<string> ParserNotes { get; private set; }
        public bool FallbackUsed { get; set; }

        public AmcacheParseResult()
        {
            Programs = new List<AmcacheProgramRecord>();
            Files = new List<AmcacheFileRecord>();
            ParserNotes = new List<string>();
        }
    }

    public static class AmcacheParser
    {
        public static AmcacheParseResult ParseHive(string hivePath)
        {
            var result = new AmcacheParseResult();
            if (string.IsNullOrWhiteSpace(hivePath) || !File.Exists(hivePath))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("Amcache hive not found; wrote header-only CSV.");
                return result;
            }

            string mountKey = "HKU\\IRCOL_AMCACHE_" + Guid.NewGuid().ToString("N");
            bool mounted = false;
            try
            {
                string loadErr;
                if (!RunRegCommand("load \"" + mountKey + "\" \"" + hivePath + "\"", out loadErr))
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("reg load failed for Amcache hive: " + Shorten(loadErr, 220));
                    return result;
                }
                mounted = true;

                ParseProgramBranch(result, mountKey + "\\Root\\Programs");
                ParseFileBranch(result, mountKey + "\\Root\\File");

                if (result.Programs.Count == 0 && result.Files.Count == 0)
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("Amcache schema variant or empty hive; no structured rows extracted.");
                }
            }
            catch (Exception ex)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("Amcache parser exception: " + Shorten(ex.Message, 220));
            }
            finally
            {
                if (mounted)
                {
                    string unloadErr;
                    if (!RunRegCommand("unload \"" + mountKey + "\"", out unloadErr))
                        Logger.Warning("AmcacheParser.reg unload: " + unloadErr);
                }
            }

            return result;
        }

        private static void ParseProgramBranch(AmcacheParseResult result, string branchKey)
        {
            string output;
            string error;
            if (!RunRegQuery(branchKey, out output, out error))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("Amcache program branch query failed: " + Shorten(error, 200));
                return;
            }

            var map = ParseRegQueryMap(output);
            foreach (var kv in map)
            {
                var values = kv.Value;
                string name = Pick(values, "Name", "DisplayName");
                string publisher = Pick(values, "Publisher");
                string version = Pick(values, "Version", "DisplayVersion");
                string product = Pick(values, "ProductName");
                string installDate = Pick(values, "InstallDate", "InstallDateFromLinkFile", "InstallDateArpLastModified");
                string uninstall = Pick(values, "UninstallString");
                string programId = Pick(values, "ProgramId");
                if (IsMostlyEmpty(name, publisher, version, product, programId))
                    continue;

                result.Programs.Add(new AmcacheProgramRecord
                {
                    RegistryKey = kv.Key,
                    ProgramName = name,
                    Publisher = publisher,
                    Version = version,
                    ProductName = product,
                    InstallDate = installDate,
                    UninstallString = uninstall,
                    ProgramId = programId,
                    ParserNote = "Program row reconstructed from Amcache program branch; fields vary by Windows build."
                });
            }
        }

        private static void ParseFileBranch(AmcacheParseResult result, string branchKey)
        {
            string output;
            string error;
            if (!RunRegQuery(branchKey, out output, out error))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("Amcache file branch query failed: " + Shorten(error, 200));
                return;
            }

            var map = ParseRegQueryMap(output);
            foreach (var kv in map)
            {
                var values = kv.Value;
                string path = Pick(values, "LowerCaseLongPath", "LongPath", "Path");
                string fileName = Pick(values, "Name", "OriginalFileName");
                if (string.IsNullOrWhiteSpace(fileName) && !string.IsNullOrWhiteSpace(path))
                    fileName = SafeFileName(path);
                string hash = NormalizeSha1(Pick(values, "Sha1", "SHA1"));
                string product = Pick(values, "ProductName");
                string publisher = Pick(values, "Publisher", "CompanyName");
                string programId = Pick(values, "ProgramId");
                string firstObserved = Pick(values, "LinkDate", "CreatedTimestamp", "CreatedTime", "Timestamp");
                string executed = Pick(values, "LastRunTime", "LastModifiedTime");

                if (IsMostlyEmpty(path, fileName, hash, programId, product, publisher))
                    continue;

                var noteParts = new List<string>();
                noteParts.Add("Amcache file row reconstructed from registry values");
                if (string.IsNullOrWhiteSpace(path))
                    noteParts.Add("path not present in this schema variant");
                if (string.IsNullOrWhiteSpace(hash))
                    noteParts.Add("sha1 missing");

                result.Files.Add(new AmcacheFileRecord
                {
                    RegistryKey = kv.Key,
                    Path = path,
                    FileName = fileName,
                    Hash = hash,
                    ProductName = product,
                    Publisher = publisher,
                    ProgramId = programId,
                    FirstObservedTime = firstObserved,
                    ExecutedTime = executed,
                    ParserNote = string.Join("; ", noteParts.ToArray())
                });
            }
        }

        private static Dictionary<string, Dictionary<string, string>> ParseRegQueryMap(string output)
        {
            var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(output))
                return result;

            string currentKey = null;
            var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (string raw in lines)
            {
                string line = raw ?? "";
                if (line.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
                {
                    currentKey = line.Trim();
                    if (!result.ContainsKey(currentKey))
                        result[currentKey] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    continue;
                }
                if (string.IsNullOrWhiteSpace(currentKey))
                    continue;

                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    continue;

                int kindIndex = IndexOfRegistryType(trimmed);
                if (kindIndex <= 0)
                    continue;

                string valueName = trimmed.Substring(0, kindIndex).Trim();
                string rest = trimmed.Substring(kindIndex).Trim();
                int dataSep = rest.IndexOf(' ');
                string valueData = dataSep >= 0 ? rest.Substring(dataSep + 1).Trim() : "";
                if (string.IsNullOrEmpty(valueName))
                    valueName = "(Default)";

                result[currentKey][valueName] = valueData;
            }
            return result;
        }

        private static int IndexOfRegistryType(string text)
        {
            string[] kinds = new[] { "REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ" };
            int min = -1;
            foreach (string kind in kinds)
            {
                int idx = text.IndexOf(kind, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;
                if (min < 0 || idx < min) min = idx;
            }
            return min;
        }

        private static bool RunRegQuery(string keyPath, out string output, out string error)
        {
            var psi = new ProcessStartInfo("reg.exe", "query \"" + keyPath + "\" /s")
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
                output = p.StandardOutput.ReadToEnd();
                error = p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0;
            }
        }

        private static bool RunRegCommand(string command, out string stdErr)
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

        private static string Pick(Dictionary<string, string> map, params string[] keys)
        {
            if (map == null || keys == null)
                return "";
            foreach (string key in keys)
            {
                string v;
                if (!string.IsNullOrWhiteSpace(key) && map.TryGetValue(key, out v) && !string.IsNullOrWhiteSpace(v))
                    return EventLogDataHelper.SanitizeSingleLine(v.Trim());
            }
            return "";
        }

        private static string NormalizeSha1(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "";
            string v = value.Trim();
            int idx = v.IndexOf(':');
            if (idx >= 0 && idx < v.Length - 1)
                v = v.Substring(idx + 1).Trim();
            return v;
        }

        private static string SafeFileName(string path)
        {
            try
            {
                return Path.GetFileName(path ?? "");
            }
            catch
            {
                return "";
            }
        }

        private static bool IsMostlyEmpty(params string[] values)
        {
            return values == null || values.All(v => string.IsNullOrWhiteSpace(v));
        }

        private static string Shorten(string text, int maxLen)
        {
            if (string.IsNullOrEmpty(text) || maxLen <= 0)
                return "";
            if (text.Length <= maxLen)
                return text;
            return text.Substring(0, maxLen - 3) + "...";
        }
    }
}
