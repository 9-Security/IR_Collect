using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    public static class UacStructuredArtifactDeriver
    {
        private const long MaxAccountFileBytes = 20L * 1024 * 1024;
        private const long MaxHistoryFileBytes = 50L * 1024 * 1024;
        private const int MaxAccountRows = 100000;
        private const int MaxShellHistoryRows = 100000;
        private const int MaxCommandLength = 65536;

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot, List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(sourceRoot) || !Directory.Exists(sourceRoot)) return;
            if (string.IsNullOrWhiteSpace(outputRoot)) return;
            Directory.CreateDirectory(outputRoot);
            try { DeriveAccounts(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "uac_accounts derive failed: " + (ex.Message ?? "")); }
            try { DeriveShellHistory(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "uac_shell_history derive failed: " + (ex.Message ?? "")); }
            try { UacPersistenceDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "uac_persistence derive failed: " + (ex.Message ?? "")); }
            try { UacJournalDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC journal derive failed: " + (ex.Message ?? "")); }
            try { UacLoginEventDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC login-event derive failed: " + (ex.Message ?? "")); }
            try { UacAuditEventDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC audit-event derive failed: " + (ex.Message ?? "")); }
            try { UacSystemLogDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC system-log derive failed: " + (ex.Message ?? "")); }
            try { UacPackageDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC package derive failed: " + (ex.Message ?? "")); }
            try { UacWebServerLogDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC web-server log derive failed: " + (ex.Message ?? "")); }
            try { UacFileHashDeriver.DeriveInto(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "UAC file-hash derive failed: " + (ex.Message ?? "")); }
        }

        private static void DeriveAccounts(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string output = Path.Combine(outputRoot, ArtifactNames.UacAccountsCsv);
            if (File.Exists(output)) return;

            List<string> files = SafeEnumerate(sourceRoot)
                .Where(IsAccountFile)
                .Where(IsInspectableAccountFile)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (files.Count == 0) return;

            var shadowStates = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string shadow in files.Where(x => string.Equals(Path.GetFileName(x), "shadow", StringComparison.OrdinalIgnoreCase)))
                ReadShadowStates(shadow, shadowStates);

            var rows = new List<UacAccountRow>();
            foreach (string file in files)
            {
                string name = Path.GetFileName(file);
                if (string.Equals(name, "passwd", StringComparison.OrdinalIgnoreCase))
                    ReadPasswdRows(sourceRoot, file, shadowStates, rows);
                else if (string.Equals(name, "group", StringComparison.OrdinalIgnoreCase))
                    ReadGroupRows(sourceRoot, file, rows);
                if (rows.Count >= MaxAccountRows) break;
            }
            if (rows.Count == 0) return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("RecordType,Name,Id,PrimaryGroupId,Home,Shell,Members,PasswordState,Description,SourcePath");
                foreach (UacAccountRow row in rows.Take(MaxAccountRows))
                {
                    sw.WriteLine(string.Join(",", new string[] {
                        CsvUtils.EscapeField(row.RecordType),
                        CsvUtils.EscapeField(row.Name),
                        CsvUtils.EscapeField(row.Id),
                        CsvUtils.EscapeField(row.PrimaryGroupId),
                        CsvUtils.EscapeField(row.Home),
                        CsvUtils.EscapeField(row.Shell),
                        CsvUtils.EscapeField(row.Members),
                        CsvUtils.EscapeField(row.PasswordState),
                        CsvUtils.EscapeField(row.Description),
                        CsvUtils.EscapeField(row.SourcePath)
                    }));
                }
            });

            if (rows.Count >= MaxAccountRows)
                Warn(warnings, "UAC account rows were capped at " + MaxAccountRows.ToString(CultureInfo.InvariantCulture) + ".");
            Logger.Info("Derived " + ArtifactNames.UacAccountsCsv + " (" + Math.Min(rows.Count, MaxAccountRows).ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        private static void DeriveShellHistory(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string output = Path.Combine(outputRoot, ArtifactNames.UacShellHistoryCsv);
            if (File.Exists(output)) return;

            List<string> files = SafeEnumerate(sourceRoot)
                .Where(IsShellHistoryFile)
                .Where(IsInspectableHistoryFile)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (files.Count == 0) return;

            int rowsWritten = 0;
            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("TimeUtc,User,Shell,CommandLine,SourcePath,LineNumber,Details");
                foreach (string file in files)
                {
                    rowsWritten += WriteHistoryRows(sourceRoot, file, sw, MaxShellHistoryRows - rowsWritten);
                    if (rowsWritten >= MaxShellHistoryRows) break;
                }
                return rowsWritten > 0;
            });

            if (rowsWritten == 0)
                return;
            if (rowsWritten >= MaxShellHistoryRows)
                Warn(warnings, "UAC shell history rows were capped at " + MaxShellHistoryRows.ToString(CultureInfo.InvariantCulture) + ".");
            Logger.Info("Derived " + ArtifactNames.UacShellHistoryCsv + " (" + rowsWritten.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        private static void ReadPasswdRows(string root, string file, Dictionary<string, string> shadowStates, List<UacAccountRow> rows)
        {
            string source = RelativePath(root, file);
            foreach (string raw in ReadLines(file))
            {
                string line = raw ?? "";
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] parts = line.Split(':');
                if (parts.Length < 7) continue;
                string user = parts[0].Trim();
                if (user.Length == 0) continue;
                string state;
                if (!shadowStates.TryGetValue(user, out state))
                    state = DescribePasswordToken(parts[1]);
                rows.Add(new UacAccountRow
                {
                    RecordType = "User",
                    Name = user,
                    Id = parts[2].Trim(),
                    PrimaryGroupId = parts[3].Trim(),
                    Description = parts[4].Trim(),
                    Home = parts[5].Trim(),
                    Shell = parts[6].Trim(),
                    PasswordState = state,
                    SourcePath = source
                });
                if (rows.Count >= MaxAccountRows) return;
            }
        }

        private static void ReadGroupRows(string root, string file, List<UacAccountRow> rows)
        {
            string source = RelativePath(root, file);
            foreach (string raw in ReadLines(file))
            {
                string line = raw ?? "";
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] parts = line.Split(':');
                if (parts.Length < 4) continue;
                string group = parts[0].Trim();
                if (group.Length == 0) continue;
                rows.Add(new UacAccountRow
                {
                    RecordType = "Group",
                    Name = group,
                    Id = parts[2].Trim(),
                    Members = parts[3].Trim(),
                    PasswordState = DescribePasswordToken(parts[1]),
                    SourcePath = source
                });
                if (rows.Count >= MaxAccountRows) return;
            }
        }

        private static void ReadShadowStates(string file, Dictionary<string, string> states)
        {
            foreach (string raw in ReadLines(file))
            {
                string line = raw ?? "";
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] parts = line.Split(':');
                if (parts.Length < 2) continue;
                string user = parts[0].Trim();
                if (user.Length > 0) states[user] = DescribePasswordToken(parts[1]);
            }
        }

        private static string DescribePasswordToken(string token)
        {
            string value = token ?? "";
            if (value.Length == 0) return "empty";
            if (value == "x") return "shadow-managed";
            if (value == "*" || value == "!" || value.StartsWith("!*", StringComparison.Ordinal) ||
                value.StartsWith("!!", StringComparison.Ordinal) || value.StartsWith("*LK*", StringComparison.Ordinal))
                return "locked";
            if (value.StartsWith("!", StringComparison.Ordinal)) return "locked-hash-present";
            return "hash-present";
        }

        private static int WriteHistoryRows(string root, string file, StreamWriter sw, int budget)
        {
            if (budget <= 0) return 0;
            string source = RelativePath(root, file);
            string user = InferUser(source);
            string shell = InferShell(file);
            string[] lines = ReadLines(file);
            int written = 0;
            long pendingEpoch = 0;
            string pendingFishCommand = null;
            int pendingFishLine = 0;

            for (int i = 0; i < lines.Length && written < budget; i++)
            {
                string line = (lines[i] ?? "").Replace("\0", "");
                if (line.Length == 0) continue;

                if (string.Equals(shell, "fish", StringComparison.Ordinal))
                {
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("- cmd:", StringComparison.Ordinal))
                    {
                        if (!string.IsNullOrEmpty(pendingFishCommand))
                            written += WriteHistoryRow(sw, "", user, shell, pendingFishCommand, source, pendingFishLine, "timestamp-unavailable");
                        pendingFishCommand = trimmed.Substring(6).Trim();
                        pendingFishLine = i + 1;
                        continue;
                    }
                    if (!string.IsNullOrEmpty(pendingFishCommand) && trimmed.StartsWith("when:", StringComparison.Ordinal))
                    {
                        long epoch;
                        long.TryParse(trimmed.Substring(5).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out epoch);
                        written += WriteHistoryRow(sw, FormatUnixTime(epoch), user, shell, pendingFishCommand, source, pendingFishLine, "");
                        pendingFishCommand = null;
                        pendingFishLine = 0;
                    }
                    continue;
                }

                if (string.Equals(shell, "zsh", StringComparison.Ordinal) && line.StartsWith(": ", StringComparison.Ordinal))
                {
                    int firstColon = line.IndexOf(':', 2);
                    int semicolon = firstColon >= 0 ? line.IndexOf(';', firstColon + 1) : -1;
                    long epoch;
                    if (firstColon > 2 && semicolon > firstColon &&
                        long.TryParse(line.Substring(2, firstColon - 2).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out epoch))
                    {
                        written += WriteHistoryRow(sw, FormatUnixTime(epoch), user, shell, line.Substring(semicolon + 1), source, i + 1, "");
                        continue;
                    }
                }

                long marker;
                if (line.Length >= 10 && line[0] == '#' &&
                    long.TryParse(line.Substring(1), NumberStyles.Integer, CultureInfo.InvariantCulture, out marker) &&
                    marker >= 315532800)
                {
                    pendingEpoch = marker;
                    continue;
                }

                written += WriteHistoryRow(sw, FormatUnixTime(pendingEpoch), user, shell, line, source, i + 1,
                    pendingEpoch > 0 ? "" : "timestamp-unavailable");
                pendingEpoch = 0;
            }

            if (written < budget && !string.IsNullOrEmpty(pendingFishCommand))
                written += WriteHistoryRow(sw, "", user, shell, pendingFishCommand, source, pendingFishLine, "timestamp-unavailable");
            return written;
        }

        private static int WriteHistoryRow(StreamWriter sw, string time, string user, string shell, string command, string source, int lineNumber, string details)
        {
            string value = command ?? "";
            if (value.Length > MaxCommandLength) value = value.Substring(0, MaxCommandLength);
            if (value.Length == 0) return 0;
            sw.WriteLine(string.Join(",", new string[] {
                CsvUtils.EscapeField(time),
                CsvUtils.EscapeField(user),
                CsvUtils.EscapeField(shell),
                CsvUtils.EscapeField(value),
                CsvUtils.EscapeField(source),
                lineNumber.ToString(CultureInfo.InvariantCulture),
                CsvUtils.EscapeField(details)
            }));
            return 1;
        }

        private static string FormatUnixTime(long epoch)
        {
            if (epoch <= 0) return "";
            try
            {
                DateTime value = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(epoch);
                if (value.Year < 1980 || value.Year > 3000) return "";
                return value.ToString("o", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        private static string InferUser(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/').Trim('/').ToLowerInvariant() + "/";
            string user = SegmentAfter(path, "/home/");
            if (user.Length == 0) user = SegmentAfter(path, "/users/");
            if (user.Length == 0 && (path.IndexOf("/root/root/", StringComparison.Ordinal) >= 0 ||
                                    path.IndexOf("/[root]/root/", StringComparison.Ordinal) >= 0 ||
                                    path.IndexOf("/var/root/", StringComparison.Ordinal) >= 0))
                user = "root";
            return user;
        }

        private static string SegmentAfter(string path, string marker)
        {
            int index = path.IndexOf(marker, StringComparison.Ordinal);
            if (index < 0) return "";
            int start = index + marker.Length;
            int end = path.IndexOf('/', start);
            return end > start ? path.Substring(start, end - start) : "";
        }

        private static string InferShell(string file)
        {
            string name = (Path.GetFileName(file) ?? "").ToLowerInvariant();
            if (name.IndexOf("zsh", StringComparison.Ordinal) >= 0) return "zsh";
            if (name.IndexOf("fish", StringComparison.Ordinal) >= 0) return "fish";
            if (name.IndexOf("ksh", StringComparison.Ordinal) >= 0) return "ksh";
            if (name.IndexOf("ash", StringComparison.Ordinal) >= 0) return "ash";
            if (name.IndexOf("powershell", StringComparison.Ordinal) >= 0 || name == "consolehost_history.txt") return "powershell";
            if (name.IndexOf("bash", StringComparison.Ordinal) >= 0) return "bash";
            return "sh";
        }

        private static bool IsAccountFile(string path)
        {
            string normalized = (path ?? "").Replace('\\', '/').ToLowerInvariant();
            return normalized.EndsWith("/etc/passwd", StringComparison.Ordinal) ||
                normalized.EndsWith("/etc/group", StringComparison.Ordinal) ||
                normalized.EndsWith("/etc/shadow", StringComparison.Ordinal);
        }

        private static bool IsShellHistoryFile(string path)
        {
            string name = (Path.GetFileName(path) ?? "").ToLowerInvariant();
            return name == ".bash_history" || name == ".zsh_history" || name == ".sh_history" ||
                name == ".ksh_history" || name == ".ash_history" || name == "fish_history" ||
                name == "consolehost_history.txt";
        }

        private static bool IsInspectableAccountFile(string path)
        {
            try { long size = new FileInfo(path).Length; return size > 0 && size <= MaxAccountFileBytes; }
            catch { return false; }
        }

        private static bool IsInspectableHistoryFile(string path)
        {
            try { long size = new FileInfo(path).Length; return size > 0 && size <= MaxHistoryFileBytes; }
            catch { return false; }
        }

        private static IEnumerable<string> SafeEnumerate(string root)
        {
            try { return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { return new string[0]; }
        }

        private static string[] ReadLines(string file)
        {
            try { return File.ReadAllLines(file, Encoding.UTF8); }
            catch
            {
                try { return File.ReadAllLines(file, Encoding.Default); }
                catch { return new string[0]; }
            }
        }

        private static string RelativePath(string root, string file)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
                string full = Path.GetFullPath(file);
                return (full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase) ? full.Substring(rootFull.Length) : Path.GetFileName(full)).Replace('\\', '/');
            }
            catch { return Path.GetFileName(file) ?? ""; }
        }

        private static void Warn(List<string> warnings, string message)
        {
            if (warnings != null) warnings.Add("UAC derive: " + message);
        }

        private sealed class UacAccountRow
        {
            public string RecordType = "";
            public string Name = "";
            public string Id = "";
            public string PrimaryGroupId = "";
            public string Home = "";
            public string Shell = "";
            public string Members = "";
            public string PasswordState = "";
            public string Description = "";
            public string SourcePath = "";
        }
    }
}
