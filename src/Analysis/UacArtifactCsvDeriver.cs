using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Best-effort intake adapter for UAC (Unix-like Artifacts Collector) output folders.
    /// It does not invent a parallel schema; instead it derives this tool's canonical
    /// artifacts so the existing Fact Store / Timeline / export pipeline can consume them.
    /// Current scope is intentionally bounded:
    /// - derive system_info.txt from UAC log files when absent
    /// - derive process_list.csv from UAC live_response/process snapshots when absent
    /// - derive activity_timeline.csv from UAC bodyfile.txt when absent
    /// - derive uac_auth_events.csv from raw auth/system logs when absent
    /// - derive uac_network_connections.csv from UAC network snapshots when absent
    /// - derive account, shell-history, persistence, journal metadata, login-event, audit-event, system-log, package, and web-server CSVs through UacStructuredArtifactDeriver
    /// Source and output roots may be separated so evidence folders remain read-only.
    /// </summary>
    public static class UacArtifactCsvDeriver
    {
        private const long MaxInspectableTextFileBytes = 20L * 1024 * 1024;
        private const int MaxDerivedActivityRows = 200000;
        private const int MaxDerivedAuthRows = 50000;
        private const int MaxDerivedNetworkRows = 50000;
        private static readonly Regex UacTimestampPrefixRegex = new Regex(@"^(?<stamp>\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?(?:\s*[+-]\d{4}|Z)?)", RegexOptions.CultureInvariant);
        private static readonly Regex SyslogPrefixRegex = new Regex(@"^(?<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<message>.+)$", RegexOptions.CultureInvariant);
        private static readonly Regex SshAcceptedRegex = new Regex(@"sshd(?:\[\d+\])?:\s+Accepted\s+\S+\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<remote>\S+)(?:\s+port\s+(?<port>\d+))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex SshFailedRegex = new Regex(@"sshd(?:\[\d+\])?:\s+Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<remote>\S+)(?:\s+port\s+(?<port>\d+))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex SshInvalidUserRegex = new Regex(@"sshd(?:\[\d+\])?:\s+Invalid user\s+(?<user>\S+)\s+from\s+(?<remote>\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex SessionRegex = new Regex(@"pam_unix\((?<service>[^:]+):session\):\s+session\s+(?<state>opened|closed)\s+for user\s+(?<user>\S+)\s+by\s+(?<actor>.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex SudoRegex = new Regex(@"sudo(?:\[\d+\])?:\s*(?<actor>[^:]+?)\s*:\s*TTY=(?<tty>[^;]+)\s*;\s*PWD=(?<pwd>[^;]+)\s*;\s*USER=(?<target>[^;]+)\s*;\s*COMMAND=(?<cmd>.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex SsProcessNameRegex = new Regex("\"(?<name>[^\"]+)\"", RegexOptions.CultureInvariant);
        private static readonly Regex SsProcessIdRegex = new Regex(@"pid=(?<pid>\d+)", RegexOptions.CultureInvariant);

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot, List<string> warnings)
        {
            if (string.IsNullOrEmpty(sourceRoot) || !Directory.Exists(sourceRoot)) return;
            if (string.IsNullOrEmpty(outputRoot)) return;
            Directory.CreateDirectory(outputRoot);
            try { DeriveSystemInfo(sourceRoot, outputRoot); } catch (Exception ex) { Warn(warnings, "system_info derive failed: " + ex.Message); }
            try { DeriveProcessList(sourceRoot, outputRoot, warnings); } catch (Exception ex) { Warn(warnings, "process_list derive failed: " + ex.Message); }
            try { DeriveActivityTimeline(sourceRoot, outputRoot, warnings); } catch (Exception ex) { Warn(warnings, "activity_timeline derive failed: " + ex.Message); }
            try { DeriveAuthEvents(sourceRoot, outputRoot, warnings); } catch (Exception ex) { Warn(warnings, "uac_auth_events derive failed: " + ex.Message); }
            try { DeriveNetworkConnections(sourceRoot, outputRoot, warnings); } catch (Exception ex) { Warn(warnings, "uac_network_connections derive failed: " + ex.Message); }
            UacStructuredArtifactDeriver.DeriveInto(sourceRoot, outputRoot, warnings);
        }

        private static void DeriveSystemInfo(string sourceRoot, string outputRoot)
        {
            string systemInfoPath = Path.Combine(outputRoot, ArtifactNames.SystemInfoTxt);
            if (File.Exists(systemInfoPath)) return;

            UacSystemInfo info = TryReadAcquisitionLog(sourceRoot);
            if (info == null || string.IsNullOrWhiteSpace(info.Hostname))
                info = TryReadUacLog(sourceRoot);
            if (info == null || string.IsNullOrWhiteSpace(info.Hostname))
                return;

            var sb = new StringBuilder();
            sb.Append("Hostname: ").Append(info.Hostname.Trim());
            if (!string.IsNullOrWhiteSpace(info.OperatingSystem))
                sb.Append("\r\nOS: ").Append(info.OperatingSystem.Trim());
            if (!string.IsNullOrWhiteSpace(info.Architecture))
                sb.Append("\r\nArchitecture: ").Append(info.Architecture.Trim());

            AtomicFile.WriteAllText(systemInfoPath, sb.ToString(), new UTF8Encoding(false));
        }

        private static void DeriveProcessList(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string outCsv = Path.Combine(outputRoot, ArtifactNames.ProcessListCsv);
            if (File.Exists(outCsv)) return;

            var candidateFiles = EnumerateUacProcessFiles(sourceRoot).ToList();
            if (candidateFiles.Count == 0) return;

            List<UacProcessRow> rows = null;
            string selectedPath = null;

            foreach (string file in candidateFiles.Where(f => Path.GetFileName(f).IndexOf("lstart", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                rows = TryParsePsWithLstart(file);
                if (rows != null && rows.Count > 0) { selectedPath = file; break; }
            }
            if (rows == null || rows.Count == 0)
            {
                foreach (string file in candidateFiles.Where(f => Path.GetFileName(f).IndexOf("etime", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                                  Path.GetFileName(f).IndexOf("elapsed", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    rows = TryParsePsWithElapsed(file);
                    if (rows != null && rows.Count > 0) { selectedPath = file; break; }
                }
            }
            if (rows == null || rows.Count == 0)
            {
                foreach (string file in candidateFiles)
                {
                    rows = TryParsePsWithLstart(file);
                    if (rows != null && rows.Count > 0) { selectedPath = file; break; }
                    rows = TryParsePsWithElapsed(file);
                    if (rows != null && rows.Count > 0) { selectedPath = file; break; }
                    rows = TryParsePsEf(file);
                    if (rows != null && rows.Count > 0) { selectedPath = file; break; }
                    rows = TryParsePsAux(file);
                    if (rows != null && rows.Count > 0) { selectedPath = file; break; }
                }
            }

            if (rows == null || rows.Count == 0)
            {
                Warn(warnings, "UAC process snapshots were present but no supported ps format could be derived.");
                return;
            }

            AtomicFile.WriteText(outCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("PID,Name,Path,CommandLine,StartTime,User,SHA256,SignatureStatus,Signer,PPID,SessionId,ThreadCount,WorkingSetSize");
                for (int i = 0; i < rows.Count; i++)
                {
                    UacProcessRow row = rows[i];
                    sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}",
                        CsvUtils.EscapeField(row.Pid),
                        CsvUtils.EscapeField(row.Name),
                        CsvUtils.EscapeField(row.Path),
                        CsvUtils.EscapeField(row.CommandLine),
                        row.StartTime.Year > 1980 ? row.StartTime.ToString("yyyy-MM-dd HH:mm:ss") : "",
                        CsvUtils.EscapeField(row.User),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""));
                }
            });

            if (!string.IsNullOrEmpty(selectedPath))
                Logger.Info("Derived process_list.csv from UAC snapshot: " + selectedPath);
        }

        private static void DeriveActivityTimeline(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string outCsv = Path.Combine(outputRoot, ArtifactNames.ActivityTimelineCsv);
            if (File.Exists(outCsv)) return;

            string bodyfilePath = FindFirst(sourceRoot, "bodyfile.txt");
            if (string.IsNullOrEmpty(bodyfilePath) || !File.Exists(bodyfilePath))
                return;

            int rowsWritten = 0;
            bool hitCap = false;
            AtomicFile.WriteText(outCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                using (var sr = OpenTextAuto(bodyfilePath))
                {
                    sw.WriteLine("Time,Source,Action,Path,User,Details");
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (rowsWritten >= MaxDerivedActivityRows)
                        {
                            hitCap = true;
                            break;
                        }

                        UacBodyfileRow row;
                        if (!TryParseBodyfileLine(line, out row))
                            continue;

                        rowsWritten += WriteBodyfileActivityRows(sw, row, MaxDerivedActivityRows - rowsWritten);
                        if (rowsWritten >= MaxDerivedActivityRows)
                        {
                            hitCap = true;
                            break;
                        }
                    }
                }
                return rowsWritten > 0;
            });

            if (rowsWritten <= 0)
                return;

            if (hitCap)
                Warn(warnings, "bodyfile.txt timeline rows were capped at " + MaxDerivedActivityRows + " entries.");
            Logger.Info("Derived activity_timeline.csv from UAC bodyfile: " + bodyfilePath + " (" + rowsWritten + " rows).");
        }

        private static void DeriveAuthEvents(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string outCsv = Path.Combine(outputRoot, ArtifactNames.UacAuthEventsCsv);
            if (File.Exists(outCsv)) return;

            List<string> candidateFiles = EnumerateUacAuthLogFiles(sourceRoot)
                .OrderBy(f => GetAuthFilePriority(f))
                .ThenBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (candidateFiles.Count == 0)
                return;

            DateTimeOffset referenceTime;
            bool hasReferenceTime = TryGetUacReferenceTimestamp(sourceRoot, out referenceTime);
            int rowsWritten = 0;
            bool hitCap = false;
            bool sawInput = false;
            var seen = new HashSet<string>(StringComparer.Ordinal);

            AtomicFile.WriteText(outCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Time,Source,Action,User,TargetUser,RemoteIP,RemoteName,Terminal,CommandLine,Details");

                for (int i = 0; i < candidateFiles.Count; i++)
                {
                    string file = candidateFiles[i];
                    using (var sr = OpenTextMaybeCompressed(file))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            sawInput = true;
                            UacAuthEventRow row;
                            if (!TryParseAuthEventLine(line, hasReferenceTime ? (DateTimeOffset?)referenceTime : null, out row))
                                continue;

                            string key = BuildAuthDedupKey(row);
                            if (!seen.Add(key))
                                continue;

                            sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}",
                                CsvUtils.EscapeField(row.TimeText),
                                CsvUtils.EscapeField(row.Source),
                                CsvUtils.EscapeField(row.Action),
                                CsvUtils.EscapeField(row.User),
                                CsvUtils.EscapeField(row.TargetUser),
                                CsvUtils.EscapeField(row.RemoteIp),
                                CsvUtils.EscapeField(row.RemoteName),
                                CsvUtils.EscapeField(row.Terminal),
                                CsvUtils.EscapeField(row.CommandLine),
                                CsvUtils.EscapeField(row.Details)));

                            rowsWritten++;
                            if (rowsWritten >= MaxDerivedAuthRows)
                            {
                                hitCap = true;
                                break;
                            }
                        }
                    }

                    if (hitCap)
                        break;
                }
                return rowsWritten > 0;
            });

            if (rowsWritten <= 0)
            {
                if (sawInput)
                    Warn(warnings, "auth log files were present but no supported authentication patterns were derived.");
                return;
            }

            if (hitCap)
                Warn(warnings, "UAC auth events were capped at " + MaxDerivedAuthRows + " entries.");
            Logger.Info("Derived uac_auth_events.csv from UAC auth logs (" + rowsWritten + " rows).");
        }

        private static void DeriveNetworkConnections(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string outCsv = Path.Combine(outputRoot, ArtifactNames.UacNetworkConnectionsCsv);
            if (File.Exists(outCsv)) return;

            List<string> candidateFiles = EnumerateUacNetworkFiles(sourceRoot)
                .OrderBy(f => GetNetworkFilePriority(f))
                .ThenBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (candidateFiles.Count == 0)
                return;

            DateTimeOffset referenceTime;
            bool hasReferenceTime = TryGetUacReferenceTimestamp(sourceRoot, out referenceTime);
            var rows = new List<UacNetworkConnectionRow>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool sawCandidate = false;
            bool hitCap = false;

            for (int i = 0; i < candidateFiles.Count; i++)
            {
                string file = candidateFiles[i];
                string[] lines = SafeReadAllLinesMaybeCompressed(file);
                if (lines == null || lines.Length == 0)
                    continue;
                sawCandidate = true;

                List<UacNetworkConnectionRow> parsed = TryParseNetworkSnapshot(file, lines, hasReferenceTime ? (DateTimeOffset?)referenceTime : null);
                if (parsed == null || parsed.Count == 0)
                    continue;

                for (int j = 0; j < parsed.Count; j++)
                {
                    UacNetworkConnectionRow row = parsed[j];
                    string key = BuildNetworkDedupKey(row);
                    if (!seen.Add(key))
                        continue;

                    rows.Add(row);
                    if (rows.Count >= MaxDerivedNetworkRows)
                    {
                        hitCap = true;
                        break;
                    }
                }

                if (hitCap)
                    break;
            }

            if (rows.Count <= 0)
            {
                if (sawCandidate)
                    Warn(warnings, "network snapshot files were present but no supported connection rows were derived.");
                return;
            }

            AtomicFile.WriteText(outCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("ObservedAtUtc,Collector,Protocol,State,LocalAddress,LocalPort,RemoteAddress,RemotePort,ProcessId,ProcessName,User,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    UacNetworkConnectionRow row = rows[i];
                    sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11}",
                        CsvUtils.EscapeField(row.ObservedAtUtc),
                        CsvUtils.EscapeField(row.Collector),
                        CsvUtils.EscapeField(row.Protocol),
                        CsvUtils.EscapeField(row.State),
                        CsvUtils.EscapeField(row.LocalAddress),
                        CsvUtils.EscapeField(row.LocalPort),
                        CsvUtils.EscapeField(row.RemoteAddress),
                        CsvUtils.EscapeField(row.RemotePort),
                        CsvUtils.EscapeField(row.ProcessId),
                        CsvUtils.EscapeField(row.ProcessName),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.Details)));
                }
            });

            if (hitCap)
                Warn(warnings, "UAC network connections were capped at " + MaxDerivedNetworkRows + " entries.");
            Logger.Info("Derived uac_network_connections.csv from UAC network snapshots (" + rows.Count + " rows).");
        }

        private static IEnumerable<string> EnumerateUacAuthLogFiles(string folder)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories);
            }
            catch
            {
                yield break;
            }

            string folderRoot = SafeGetFullPath(folder);
            foreach (string file in files)
            {
                long len = 0;
                try { len = new FileInfo(file).Length; } catch { }
                if (len <= 0 || len > MaxInspectableTextFileBytes)
                    continue;

                string rel = GetRelativeLikePath(folderRoot, file);
                string normalized = (rel ?? file).Replace('/', '\\').ToLowerInvariant();
                string name = (Path.GetFileName(file) ?? "").ToLowerInvariant();
                bool isAuthLog = normalized.IndexOf("\\var\\log\\", StringComparison.Ordinal) >= 0 &&
                    (name.StartsWith("auth.log", StringComparison.Ordinal) ||
                     name == "secure" ||
                     name.StartsWith("secure.", StringComparison.Ordinal) ||
                     name.StartsWith("secure-", StringComparison.Ordinal) ||
                     name.StartsWith("system.log", StringComparison.Ordinal));
                if (!isAuthLog)
                    continue;

                yield return file;
            }
        }

        private static IEnumerable<string> EnumerateUacNetworkFiles(string folder)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories);
            }
            catch
            {
                yield break;
            }

            string folderRoot = SafeGetFullPath(folder);
            foreach (string file in files)
            {
                long len = 0;
                try { len = new FileInfo(file).Length; } catch { }
                if (len <= 0 || len > MaxInspectableTextFileBytes)
                    continue;

                string rel = GetRelativeLikePath(folderRoot, file);
                string normalized = (rel ?? file).Replace('/', '\\').ToLowerInvariant();
                if (normalized.IndexOf("live_response\\", StringComparison.Ordinal) < 0)
                    continue;

                string name = (Path.GetFileName(file) ?? "").ToLowerInvariant();
                if (!LooksLikeNetworkCollectorFileName(name))
                    continue;

                yield return file;
            }
        }

        private static int GetAuthFilePriority(string path)
        {
            string name = (Path.GetFileName(path) ?? "").ToLowerInvariant();
            if (name.StartsWith("auth.log", StringComparison.Ordinal)) return 0;
            if (name == "secure" || name.StartsWith("secure.", StringComparison.Ordinal) || name.StartsWith("secure-", StringComparison.Ordinal)) return 1;
            if (name.StartsWith("system.log", StringComparison.Ordinal)) return 2;
            return 9;
        }

        private static int GetNetworkFilePriority(string path)
        {
            string name = (Path.GetFileName(path) ?? "").ToLowerInvariant();
            if (name.IndexOf("lsof", StringComparison.Ordinal) >= 0) return 0;
            if (name.IndexOf("ss", StringComparison.Ordinal) >= 0) return 1;
            if (name.IndexOf("netstat", StringComparison.Ordinal) >= 0) return 2;
            return 9;
        }

        private static bool TryGetUacReferenceTimestamp(string folder, out DateTimeOffset referenceTime)
        {
            referenceTime = default(DateTimeOffset);

            try
            {
                string uacLogPath = Directory.EnumerateFiles(folder, "uac.log", SearchOption.AllDirectories).FirstOrDefault();
                if (!string.IsNullOrEmpty(uacLogPath))
                {
                    if (TryReadTimestampFromTextFile(uacLogPath, out referenceTime))
                        return true;

                    try
                    {
                        referenceTime = new DateTimeOffset(File.GetLastWriteTime(uacLogPath));
                        return true;
                    }
                    catch { }
                }
            }
            catch { }

            try
            {
                foreach (string file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
                {
                    long len = 0;
                    try { len = new FileInfo(file).Length; } catch { }
                    if (len <= 0 || len > MaxInspectableTextFileBytes)
                        continue;

                    string[] lines = SafeReadAllLinesMaybeCompressed(file);
                    if (lines == null || lines.Length == 0)
                        continue;
                    if (!string.Equals((lines[0] ?? "").Trim(), "Created by UAC (Unix-like Artifacts Collector)", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (TryReadTimestampFromLines(lines, out referenceTime))
                        return true;

                    try
                    {
                        referenceTime = new DateTimeOffset(File.GetLastWriteTime(file));
                        return true;
                    }
                    catch { }
                }
            }
            catch { }

            try
            {
                referenceTime = new DateTimeOffset(Directory.GetLastWriteTime(folder));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryReadTimestampFromTextFile(string path, out DateTimeOffset timestamp)
        {
            timestamp = default(DateTimeOffset);
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return false;

            try
            {
                using (var sr = OpenTextMaybeCompressed(path))
                {
                    var sample = new List<string>();
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        sample.Add(line);
                        if (sample.Count >= 200)
                            break;
                    }
                    return TryReadTimestampFromLines(sample.ToArray(), out timestamp);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool TryReadTimestampFromLines(string[] lines, out DateTimeOffset timestamp)
        {
            timestamp = default(DateTimeOffset);
            if (lines == null || lines.Length == 0)
                return false;

            for (int i = 0; i < lines.Length; i++)
            {
                if (TryParseTimestampPrefix(lines[i], out timestamp))
                    return true;
            }
            return false;
        }

        private static bool TryParseTimestampPrefix(string line, out DateTimeOffset timestamp)
        {
            timestamp = default(DateTimeOffset);
            if (string.IsNullOrWhiteSpace(line))
                return false;

            Match m = UacTimestampPrefixRegex.Match(line.Trim());
            if (!m.Success)
                return false;

            string stamp = (m.Groups["stamp"].Value ?? "").Trim();
            if (stamp.Length == 0)
                return false;

            if (DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out timestamp))
                return true;

            DateTime dt;
            if (!DateTime.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dt) &&
                !DateTime.TryParse(stamp, out dt))
                return false;

            timestamp = new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Unspecified), TimeZoneInfo.Local.GetUtcOffset(dt));
            return true;
        }

        private static bool TryParseAuthEventLine(string line, DateTimeOffset? referenceTime, out UacAuthEventRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            Match prefix = SyslogPrefixRegex.Match(line);
            if (!prefix.Success)
                return false;

            DateTime parsedTime;
            if (!TryParseSyslogTimestamp(prefix.Groups["stamp"].Value, referenceTime, out parsedTime))
                return false;

            string message = (prefix.Groups["message"].Value ?? "").Trim();
            if (message.Length == 0)
                return false;

            Match m = SudoRegex.Match(message);
            if (m.Success)
            {
                row = new UacAuthEventRow();
                row.TimeText = parsedTime.ToString("yyyy-MM-dd HH:mm:ss");
                row.Source = "sudo";
                row.Action = "SudoCommand";
                row.User = CleanToken(m.Groups["actor"].Value);
                row.TargetUser = CleanToken(m.Groups["target"].Value);
                row.Terminal = CleanToken(m.Groups["tty"].Value);
                row.CommandLine = CleanToken(m.Groups["cmd"].Value);
                row.Details = "pwd=" + CleanToken(m.Groups["pwd"].Value);
                return true;
            }

            m = SessionRegex.Match(message);
            if (m.Success)
            {
                row = new UacAuthEventRow();
                row.TimeText = parsedTime.ToString("yyyy-MM-dd HH:mm:ss");
                row.Source = CleanToken(m.Groups["service"].Value);
                row.Action = string.Equals((m.Groups["state"].Value ?? "").Trim(), "opened", StringComparison.OrdinalIgnoreCase)
                    ? "SessionOpened"
                    : "SessionClosed";
                row.User = CleanToken(m.Groups["user"].Value);
                row.Details = "by=" + CleanToken(m.Groups["actor"].Value);
                return true;
            }

            m = SshAcceptedRegex.Match(message);
            if (m.Success)
            {
                row = CreateSshAuthRow(parsedTime, "SshLoginAccepted", m);
                return true;
            }

            m = SshFailedRegex.Match(message);
            if (m.Success)
            {
                row = CreateSshAuthRow(parsedTime, "SshLoginFailed", m);
                return true;
            }

            m = SshInvalidUserRegex.Match(message);
            if (m.Success)
            {
                row = new UacAuthEventRow();
                row.TimeText = parsedTime.ToString("yyyy-MM-dd HH:mm:ss");
                row.Source = "sshd";
                row.Action = "SshInvalidUser";
                row.TargetUser = CleanToken(m.Groups["user"].Value);
                string remoteValue = CleanToken(m.Groups["remote"].Value);
                SplitRemoteValue(remoteValue, out row.RemoteIp, out row.RemoteName);
                row.Details = "invalid-user";
                return true;
            }

            return false;
        }

        private static UacAuthEventRow CreateSshAuthRow(DateTime parsedTime, string action, Match match)
        {
            var row = new UacAuthEventRow();
            row.TimeText = parsedTime.ToString("yyyy-MM-dd HH:mm:ss");
            row.Source = "sshd";
            row.Action = action;
            row.TargetUser = CleanToken(match.Groups["user"].Value);

            string remoteValue = CleanToken(match.Groups["remote"].Value);
            SplitRemoteValue(remoteValue, out row.RemoteIp, out row.RemoteName);

            string port = CleanToken(match.Groups["port"].Value);
            if (!string.IsNullOrWhiteSpace(port))
                row.Details = "port=" + port;
            return row;
        }

        private static bool TryParseSyslogTimestamp(string stamp, DateTimeOffset? referenceTime, out DateTime parsed)
        {
            parsed = DateTime.MinValue;
            if (string.IsNullOrWhiteSpace(stamp))
                return false;

            DateTime partial;
            if (!DateTime.TryParseExact(stamp.Trim(),
                new string[] { "MMM d HH:mm:ss", "MMM dd HH:mm:ss" },
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces,
                out partial))
                return false;

            DateTime referenceLocal = referenceTime.HasValue ? referenceTime.Value.DateTime : DateTime.Now;
            try
            {
                parsed = new DateTime(referenceLocal.Year, partial.Month, partial.Day, partial.Hour, partial.Minute, partial.Second, DateTimeKind.Unspecified);
            }
            catch
            {
                return false;
            }

            if (referenceTime.HasValue)
            {
                DateTime wallClock = referenceTime.Value.DateTime;
                if (parsed > wallClock.AddDays(31))
                    parsed = parsed.AddYears(-1);
                else if (parsed < wallClock.AddDays(-335))
                    parsed = parsed.AddYears(1);
            }

            return true;
        }

        private static void SplitRemoteValue(string value, out string remoteIp, out string remoteName)
        {
            remoteIp = "";
            remoteName = "";

            string normalized = NormalizeNetworkAddress(value);
            if (normalized.Length == 0)
                return;

            IPAddress address;
            if (IPAddress.TryParse(normalized, out address))
                remoteIp = normalized;
            else
                remoteName = normalized;
        }

        private static string BuildAuthDedupKey(UacAuthEventRow row)
        {
            if (row == null) return "";
            return string.Join("|", new string[]
            {
                row.TimeText ?? "",
                row.Source ?? "",
                row.Action ?? "",
                row.User ?? "",
                row.TargetUser ?? "",
                row.RemoteIp ?? "",
                row.RemoteName ?? "",
                row.Terminal ?? "",
                row.CommandLine ?? "",
                row.Details ?? ""
            });
        }

        private static List<UacNetworkConnectionRow> TryParseNetworkSnapshot(string path, string[] lines, DateTimeOffset? referenceTime)
        {
            if (LooksLikeLsofNetwork(lines))
                return ParseLsofNetworkSnapshot(path, lines, referenceTime);
            if (LooksLikeSsNetwork(lines))
                return ParseSsNetworkSnapshot(path, lines, referenceTime);
            if (LooksLikeNetstatNetwork(lines))
                return ParseNetstatNetworkSnapshot(path, lines, referenceTime);
            return null;
        }

        private static bool LooksLikeLsofNetwork(string[] lines)
        {
            return FindHeaderIndex(lines, "COMMAND", "PID", "NAME") >= 0;
        }

        private static bool LooksLikeSsNetwork(string[] lines)
        {
            return FindHeaderIndex(lines, "Netid", "State", "Local") >= 0;
        }

        private static bool LooksLikeNetstatNetwork(string[] lines)
        {
            return FindHeaderIndex(lines, "Proto", "Local", "Foreign") >= 0;
        }

        private static List<UacNetworkConnectionRow> ParseLsofNetworkSnapshot(string path, string[] lines, DateTimeOffset? referenceTime)
        {
            int headerIndex = FindHeaderIndex(lines, "COMMAND", "PID", "NAME");
            if (headerIndex < 0)
                return null;

            string observedAt = ResolveObservedAtUtc(TryFindSnapshotTime(lines, headerIndex), path, referenceTime);
            var rows = new List<UacNetworkConnectionRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                string[] parts = SplitWhitespace(line, 9);
                if (parts.Length < 9)
                    continue;

                string protocol;
                string state;
                string localAddress;
                string localPort;
                string remoteAddress;
                string remotePort;
                if (!TryParseLsofName(parts[8], out protocol, out state, out localAddress, out localPort, out remoteAddress, out remotePort))
                    continue;

                var row = new UacNetworkConnectionRow();
                row.ObservedAtUtc = observedAt;
                row.Collector = "lsof";
                row.Protocol = protocol;
                row.State = state;
                row.LocalAddress = localAddress;
                row.LocalPort = localPort;
                row.RemoteAddress = remoteAddress;
                row.RemotePort = remotePort;
                row.ProcessId = CleanToken(parts[1]);
                row.ProcessName = CleanToken(parts[0]);
                row.User = CleanToken(parts[2]);
                row.Details = "fd=" + CleanToken(parts[3]) + "; type=" + CleanToken(parts[4]);
                rows.Add(row);
            }

            return rows;
        }

        private static List<UacNetworkConnectionRow> ParseSsNetworkSnapshot(string path, string[] lines, DateTimeOffset? referenceTime)
        {
            int headerIndex = FindHeaderIndex(lines, "Netid", "State", "Local");
            if (headerIndex < 0)
                return null;

            string observedAt = ResolveObservedAtUtc(TryFindSnapshotTime(lines, headerIndex), path, referenceTime);
            var rows = new List<UacNetworkConnectionRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                string[] parts = SplitWhitespace(line, 7);
                if (parts.Length < 6)
                    continue;

                string localAddress;
                string localPort;
                if (!TrySplitEndpoint(parts[4], out localAddress, out localPort))
                    continue;

                string remoteAddress;
                string remotePort;
                if (!TrySplitEndpoint(parts[5], out remoteAddress, out remotePort))
                    continue;

                string processName = "";
                string processId = "";
                string details = parts.Length >= 7 ? CleanToken(parts[6]) : "";
                TryParseSsProcessDetails(details, out processName, out processId);

                var row = new UacNetworkConnectionRow();
                row.ObservedAtUtc = observedAt;
                row.Collector = "ss";
                row.Protocol = CleanToken(parts[0]);
                row.State = CleanToken(parts[1]);
                row.LocalAddress = localAddress;
                row.LocalPort = localPort;
                row.RemoteAddress = remoteAddress;
                row.RemotePort = remotePort;
                row.ProcessId = processId;
                row.ProcessName = processName;
                row.User = "";
                row.Details = details;
                rows.Add(row);
            }

            return rows;
        }

        private static List<UacNetworkConnectionRow> ParseNetstatNetworkSnapshot(string path, string[] lines, DateTimeOffset? referenceTime)
        {
            int headerIndex = FindHeaderIndex(lines, "Proto", "Local", "Foreign");
            if (headerIndex < 0)
                return null;

            string observedAt = ResolveObservedAtUtc(TryFindSnapshotTime(lines, headerIndex), path, referenceTime);
            var rows = new List<UacNetworkConnectionRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                string[] parts = SplitWhitespace(line, 7);
                if (parts.Length < 5)
                    continue;

                string localAddress;
                string localPort;
                if (!TrySplitEndpoint(parts[3], out localAddress, out localPort))
                    continue;

                string remoteAddress;
                string remotePort;
                if (!TrySplitEndpoint(parts[4], out remoteAddress, out remotePort))
                    continue;

                string state = "";
                string processId = "";
                string processName = "";
                string trailing = "";

                if (parts.Length >= 7)
                {
                    state = CleanToken(parts[5]);
                    trailing = CleanToken(parts[6]);
                }
                else if (parts.Length == 6)
                {
                    trailing = CleanToken(parts[5]);
                    if (LooksLikePidProgram(trailing))
                    {
                        state = "";
                    }
                    else
                    {
                        state = trailing;
                        trailing = "";
                    }
                }

                TryParsePidProgram(trailing, out processId, out processName);

                var row = new UacNetworkConnectionRow();
                row.ObservedAtUtc = observedAt;
                row.Collector = "netstat";
                row.Protocol = CleanToken(parts[0]);
                row.State = state;
                row.LocalAddress = localAddress;
                row.LocalPort = localPort;
                row.RemoteAddress = remoteAddress;
                row.RemotePort = remotePort;
                row.ProcessId = processId;
                row.ProcessName = processName;
                row.User = "";
                row.Details = trailing;
                rows.Add(row);
            }

            return rows;
        }

        private static bool TryParseLsofName(string value, out string protocol, out string state, out string localAddress, out string localPort, out string remoteAddress, out string remotePort)
        {
            protocol = "";
            state = "";
            localAddress = "";
            localPort = "";
            remoteAddress = "";
            remotePort = "";

            string text = CleanToken(value);
            if (text.Length == 0)
                return false;

            Match m = Regex.Match(text, @"^(?<proto>[A-Za-z0-9]+)\s+(?<rest>.+?)(?:\s+\((?<state>[^)]+)\))?$", RegexOptions.CultureInvariant);
            if (!m.Success)
                return false;

            protocol = CleanToken(m.Groups["proto"].Value);
            state = CleanToken(m.Groups["state"].Value);

            string localPart;
            string remotePart;
            SplitEndpointPair(CleanToken(m.Groups["rest"].Value), out localPart, out remotePart);

            if (!TrySplitEndpoint(localPart, out localAddress, out localPort))
                return false;
            if (!TrySplitEndpoint(remotePart, out remoteAddress, out remotePort))
                return false;

            return true;
        }

        private static void SplitEndpointPair(string value, out string localPart, out string remotePart)
        {
            localPart = CleanToken(value);
            remotePart = "*:*";
            int arrow = localPart.IndexOf("->", StringComparison.Ordinal);
            if (arrow < 0)
                return;

            remotePart = localPart.Substring(arrow + 2).Trim();
            localPart = localPart.Substring(0, arrow).Trim();
        }

        private static bool TrySplitEndpoint(string endpoint, out string address, out string port)
        {
            address = "";
            port = "";

            string text = CleanToken(endpoint);
            if (text.Length == 0 || text == "*" || text == "*:*" || text == "*.*")
            {
                address = "*";
                port = "*";
                return true;
            }

            if (text.StartsWith("[", StringComparison.Ordinal))
            {
                int bracket = text.IndexOf(']');
                if (bracket > 0)
                {
                    string inner = text.Substring(1, bracket - 1);
                    string tail = text.Substring(bracket + 1).Trim();
                    if (tail.StartsWith(":", StringComparison.Ordinal) || tail.StartsWith(".", StringComparison.Ordinal))
                        tail = tail.Substring(1);
                    address = NormalizeNetworkAddress(inner);
                    port = NormalizePort(tail);
                    return true;
                }
            }

            int colon = text.LastIndexOf(':');
            if (colon > 0)
            {
                string tail = text.Substring(colon + 1);
                if (IsPortToken(tail))
                {
                    address = NormalizeNetworkAddress(text.Substring(0, colon));
                    port = NormalizePort(tail);
                    return true;
                }
            }

            int dot = text.LastIndexOf('.');
            if (dot > 0)
            {
                string tail = text.Substring(dot + 1);
                if (IsPortToken(tail) && LooksLikeDotSeparatedEndpoint(text.Substring(0, dot)))
                {
                    address = NormalizeNetworkAddress(text.Substring(0, dot));
                    port = NormalizePort(tail);
                    return true;
                }
            }

            address = NormalizeNetworkAddress(text);
            port = "";
            return true;
        }

        private static bool LooksLikeDotSeparatedEndpoint(string address)
        {
            string text = CleanToken(address);
            if (text == "*")
                return true;
            return Regex.IsMatch(text, @"^[0-9.*]+$", RegexOptions.CultureInvariant);
        }

        private static bool IsPortToken(string value)
        {
            string text = CleanToken(value);
            if (text == "*")
                return true;
            int portValue;
            return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out portValue);
        }

        private static string NormalizePort(string value)
        {
            string text = CleanToken(value);
            return text.Length == 0 ? "*" : text;
        }

        private static string NormalizeNetworkAddress(string value)
        {
            string text = CleanToken(value).Trim('[', ']');
            if (text == "*.*")
                return "*";

            int zone = text.IndexOf('%');
            if (zone > 0)
                text = text.Substring(0, zone);

            return text;
        }

        private static void TryParseSsProcessDetails(string details, out string processName, out string processId)
        {
            processName = "";
            processId = "";

            if (string.IsNullOrWhiteSpace(details))
                return;

            Match m = SsProcessNameRegex.Match(details);
            if (m.Success)
                processName = CleanToken(m.Groups["name"].Value);

            m = SsProcessIdRegex.Match(details);
            if (m.Success)
                processId = CleanToken(m.Groups["pid"].Value);
        }

        private static bool LooksLikePidProgram(string value)
        {
            string text = CleanToken(value);
            return Regex.IsMatch(text, @"^\d+\/", RegexOptions.CultureInvariant) ||
                string.Equals(text, "-", StringComparison.Ordinal);
        }

        private static void TryParsePidProgram(string value, out string processId, out string processName)
        {
            processId = "";
            processName = "";

            string text = CleanToken(value);
            if (text.Length == 0 || text == "-")
                return;

            int slash = text.IndexOf('/');
            if (slash <= 0)
                return;

            processId = CleanToken(text.Substring(0, slash));
            processName = CleanToken(text.Substring(slash + 1));
        }

        private static string ResolveObservedAtUtc(DateTime snapshotTime, string filePath, DateTimeOffset? referenceTime)
        {
            DateTime utc = DateTime.MinValue;
            if (snapshotTime.Year > 1980)
            {
                if (snapshotTime.Kind == DateTimeKind.Utc)
                {
                    utc = snapshotTime;
                }
                else if (snapshotTime.Kind == DateTimeKind.Local)
                {
                    utc = snapshotTime.ToUniversalTime();
                }
                else if (referenceTime.HasValue)
                {
                    utc = new DateTimeOffset(DateTime.SpecifyKind(snapshotTime, DateTimeKind.Unspecified), referenceTime.Value.Offset).UtcDateTime;
                }
                else
                {
                    utc = DateTime.SpecifyKind(snapshotTime, DateTimeKind.Utc);
                }
            }

            if (utc.Year <= 1980)
            {
                try { utc = File.GetLastWriteTimeUtc(filePath); }
                catch { utc = DateTime.MinValue; }
            }

            return utc.Year > 1980 ? utc.ToString("yyyy-MM-ddTHH:mm:ssZ") : "";
        }

        private static string BuildNetworkDedupKey(UacNetworkConnectionRow row)
        {
            if (row == null) return "";
            return string.Join("|", new string[]
            {
                row.Protocol ?? "",
                row.State ?? "",
                row.LocalAddress ?? "",
                row.LocalPort ?? "",
                row.RemoteAddress ?? "",
                row.RemotePort ?? "",
                row.ProcessId ?? "",
                row.ProcessName ?? "",
                row.User ?? ""
            });
        }

        private static string SafeGetFullPath(string path)
        {
            try { return Path.GetFullPath(path ?? ""); }
            catch { return path ?? ""; }
        }

        private static string GetRelativeLikePath(string root, string path)
        {
            try
            {
                string fullRoot = SafeGetFullPath(root);
                string fullPath = SafeGetFullPath(path);
                if (!string.IsNullOrEmpty(fullRoot) && fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                    return fullPath.Substring(fullRoot.Length).TrimStart(Path.DirectorySeparatorChar, '/', '\\');
            }
            catch { }
            return path;
        }

        private static bool LooksLikeNetworkCollectorFileName(string name)
        {
            string value = (name ?? "").ToLowerInvariant();
            return value.IndexOf("lsof", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("netstat", StringComparison.Ordinal) >= 0 ||
                value.StartsWith("ss", StringComparison.Ordinal) ||
                value.IndexOf("_ss", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("-ss", StringComparison.Ordinal) >= 0;
        }

        private static IEnumerable<string> EnumerateUacProcessFiles(string folder)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(folder, "*.txt", SearchOption.AllDirectories);
            }
            catch
            {
                yield break;
            }

            foreach (string file in files)
            {
                string rel;
                try { rel = file.Substring(Path.GetFullPath(folder).Length).TrimStart(Path.DirectorySeparatorChar, '/', '\\'); }
                catch { rel = file; }

                string normalized = (rel ?? file).Replace('/', '\\');
                if (normalized.IndexOf("live_response\\process\\", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                long len = 0;
                try { len = new FileInfo(file).Length; } catch { }
                if (MaxInspectableTextFileBytes > 0 && len > MaxInspectableTextFileBytes)
                    continue;

                yield return file;
            }
        }

        private static List<UacProcessRow> TryParsePsWithLstart(string path)
        {
            string[] lines = SafeReadAllLines(path);
            if (lines == null || lines.Length == 0) return null;

            int headerIndex = FindHeaderIndex(lines, "PID", "USER", "STARTED");
            if (headerIndex < 0) return null;

            var rows = new List<UacProcessRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = SplitWhitespace(line, 8);
                if (parts.Length < 8) continue;

                DateTime startTime;
                string startValue = string.Join(" ", new string[] { parts[2], parts[3], parts[4], parts[5], parts[6] });
                if (!TryParseUnixDate(startValue, out startTime))
                    startTime = DateTime.MinValue;

                UacProcessRow row = CreateProcessRow(parts[0], parts[1], parts[7], startTime);
                if (row != null) rows.Add(row);
            }

            return rows;
        }

        private static List<UacProcessRow> TryParsePsWithElapsed(string path)
        {
            string[] lines = SafeReadAllLines(path);
            if (lines == null || lines.Length == 0) return null;

            int headerIndex = FindHeaderIndex(lines, "PID", "USER", "ELAPSED");
            if (headerIndex < 0)
                headerIndex = FindHeaderIndex(lines, "PID", "USER", "ETIME");
            if (headerIndex < 0) return null;

            DateTime snapshotTime = TryFindSnapshotTime(lines, headerIndex);
            var rows = new List<UacProcessRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = SplitWhitespace(line, 4);
                if (parts.Length < 4) continue;

                TimeSpan elapsed;
                DateTime startTime = DateTime.MinValue;
                if (snapshotTime.Year > 1980 && TryParseElapsed(parts[2], out elapsed))
                    startTime = snapshotTime.Subtract(elapsed);

                UacProcessRow row = CreateProcessRow(parts[0], parts[1], parts[3], startTime);
                if (row != null) rows.Add(row);
            }

            return rows;
        }

        private static List<UacProcessRow> TryParsePsEf(string path)
        {
            string[] lines = SafeReadAllLines(path);
            if (lines == null || lines.Length == 0) return null;

            int headerIndex = FindHeaderIndex(lines, "UID", "PID", "CMD");
            if (headerIndex < 0) return null;

            var rows = new List<UacProcessRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = SplitWhitespace(line, 8);
                if (parts.Length < 8) continue;

                UacProcessRow row = CreateProcessRow(parts[1], parts[0], parts[7], DateTime.MinValue);
                if (row != null) rows.Add(row);
            }

            return rows;
        }

        private static List<UacProcessRow> TryParsePsAux(string path)
        {
            string[] lines = SafeReadAllLines(path);
            if (lines == null || lines.Length == 0) return null;

            int headerIndex = FindHeaderIndex(lines, "USER", "PID", "COMMAND");
            if (headerIndex < 0) return null;

            var rows = new List<UacProcessRow>();
            for (int i = headerIndex + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] parts = SplitWhitespace(line, 11);
                if (parts.Length < 11) continue;

                UacProcessRow row = CreateProcessRow(parts[1], parts[0], parts[10], DateTime.MinValue);
                if (row != null) rows.Add(row);
            }

            return rows;
        }

        private static UacProcessRow CreateProcessRow(string pid, string user, string commandLine, DateTime startTime)
        {
            if (string.IsNullOrWhiteSpace(pid) || string.IsNullOrWhiteSpace(commandLine))
                return null;

            string path = ExtractExecutablePath(commandLine);
            string name = ExtractProcessName(path, commandLine);
            return new UacProcessRow
            {
                Pid = pid.Trim(),
                User = (user ?? "").Trim(),
                CommandLine = (commandLine ?? "").Trim(),
                Path = path,
                Name = name,
                StartTime = startTime
            };
        }

        private static string ExtractExecutablePath(string commandLine)
        {
            string cmd = (commandLine ?? "").Trim();
            if (string.IsNullOrEmpty(cmd) || cmd.StartsWith("[", StringComparison.Ordinal))
                return "";

            string token = FirstCommandToken(cmd);
            if (string.IsNullOrWhiteSpace(token))
                return "";

            token = token.Trim().Trim('"');
            if (token.StartsWith("-", StringComparison.Ordinal))
                return "";

            return token;
        }

        private static string ExtractProcessName(string path, string commandLine)
        {
            string candidate = path;
            if (string.IsNullOrWhiteSpace(candidate))
                candidate = FirstCommandToken(commandLine ?? "").Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(candidate))
                return "";
            try
            {
                return Path.GetFileName(candidate);
            }
            catch
            {
                return candidate;
            }
        }

        private static string FirstCommandToken(string commandLine)
        {
            string cmd = (commandLine ?? "").Trim();
            if (string.IsNullOrEmpty(cmd)) return "";
            if (cmd.StartsWith("\"", StringComparison.Ordinal))
            {
                int endQuote = cmd.IndexOf('"', 1);
                if (endQuote > 1)
                    return cmd.Substring(1, endQuote - 1);
            }

            int space = cmd.IndexOfAny(new char[] { ' ', '\t' });
            return space > 0 ? cmd.Substring(0, space) : cmd;
        }

        private static int FindHeaderIndex(string[] lines, string requiredA, string requiredB, string requiredC)
        {
            for (int i = 0; i < lines.Length; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0) continue;
                if (line.IndexOf(requiredA, StringComparison.OrdinalIgnoreCase) >= 0 &&
                    line.IndexOf(requiredB, StringComparison.OrdinalIgnoreCase) >= 0 &&
                    line.IndexOf(requiredC, StringComparison.OrdinalIgnoreCase) >= 0)
                    return i;
            }
            return -1;
        }

        private static DateTime TryFindSnapshotTime(string[] lines, int headerIndex)
        {
            for (int i = headerIndex - 1; i >= 0; i--)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0) continue;
                DateTime parsed;
                if (TryParseUnixDate(line, out parsed) || DateTime.TryParse(line, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed) || DateTime.TryParse(line, out parsed))
                    return parsed;
            }
            return DateTime.MinValue;
        }

        private static bool TryParseUnixDate(string value, out DateTime parsed)
        {
            parsed = DateTime.MinValue;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            string[] formats = new string[]
            {
                "ddd MMM d HH:mm:ss yyyy",
                "ddd MMM dd HH:mm:ss yyyy",
                "ddd MMM d HH:mm:ss 'UTC' yyyy",
                "ddd MMM dd HH:mm:ss 'UTC' yyyy",
                "yyyy-MM-dd HH:mm:ss",
                "yyyy-MM-ddTHH:mm:ss",
                "yyyy-MM-ddTHH:mm:ssZ"
            };

            return DateTime.TryParseExact(value.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed) ||
                   DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed) ||
                   DateTime.TryParse(value, out parsed);
        }

        private static bool TryParseElapsed(string value, out TimeSpan elapsed)
        {
            elapsed = TimeSpan.Zero;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            string text = value.Trim();
            int days = 0;
            int dash = text.IndexOf('-');
            if (dash > 0)
            {
                int parsedDays;
                if (!int.TryParse(text.Substring(0, dash), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedDays))
                    return false;
                days = parsedDays;
                text = text.Substring(dash + 1);
            }

            string[] parts = text.Split(':');
            int hours = 0, minutes = 0, seconds = 0;
            if (parts.Length == 2)
            {
                if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out minutes)) return false;
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds)) return false;
            }
            else if (parts.Length == 3)
            {
                if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out hours)) return false;
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out minutes)) return false;
                if (!int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds)) return false;
            }
            else
            {
                return false;
            }

            elapsed = new TimeSpan(days, hours, minutes, seconds);
            return true;
        }

        private static string[] SplitWhitespace(string line, int count)
        {
            return (line ?? "").Trim().Split(new char[] { ' ', '\t' }, count, StringSplitOptions.RemoveEmptyEntries);
        }

        private static string[] SafeReadAllLines(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            try
            {
                return File.ReadAllLines(path, Encoding.UTF8);
            }
            catch
            {
                try { return File.ReadAllLines(path); }
                catch { return null; }
            }
        }

        private static string[] SafeReadAllLinesMaybeCompressed(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            try
            {
                var lines = new List<string>();
                using (var sr = OpenTextMaybeCompressed(path))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                        lines.Add(line);
                }
                return lines.ToArray();
            }
            catch
            {
                return SafeReadAllLines(path);
            }
        }

        private static StreamReader OpenTextAuto(string path)
        {
            try
            {
                return new StreamReader(path, Encoding.UTF8);
            }
            catch
            {
                return new StreamReader(path);
            }
        }

        private static StreamReader OpenTextMaybeCompressed(string path)
        {
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                    return new StreamReader(new GZipStream(fs, CompressionMode.Decompress), Encoding.UTF8);
                return new StreamReader(fs, Encoding.UTF8, true);
            }
            catch
            {
                try { fs.Dispose(); } catch { }
                return OpenTextAuto(path);
            }
        }

        private static string FindFirst(string root, string fileName)
        {
            try
            {
                foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    if (string.Equals(Path.GetFileName(f), fileName, StringComparison.OrdinalIgnoreCase))
                        return f;
            }
            catch { }
            return null;
        }

        private static bool TryParseBodyfileLine(string line, out UacBodyfileRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            string[] parts = (line ?? "").Split('|');
            if (parts.Length < 11)
                return false;

            string path = parts[1] ?? "";
            if (string.IsNullOrWhiteSpace(path))
                return false;

            long inode, size, atime, mtime, ctime, crtime;
            if (!TryParseLong(parts[2], out inode)) inode = 0;
            string mode = parts[3] ?? "";
            string uid = parts[4] ?? "";
            string gid = parts[5] ?? "";
            if (!TryParseLong(parts[6], out size)) size = 0;
            if (!TryParseLong(parts[7], out atime)) atime = 0;
            if (!TryParseLong(parts[8], out mtime)) mtime = 0;
            if (!TryParseLong(parts[9], out ctime)) ctime = 0;
            if (!TryParseLong(parts[10], out crtime)) crtime = 0;

            row = new UacBodyfileRow
            {
                Path = path.Trim(),
                Inode = inode,
                Mode = mode.Trim(),
                UserId = uid.Trim(),
                GroupId = gid.Trim(),
                Size = size,
                AccessTime = atime,
                ModifiedTime = mtime,
                MetadataChangeTime = ctime,
                CreatedTime = crtime
            };
            return true;
        }

        private static int WriteBodyfileActivityRows(StreamWriter sw, UacBodyfileRow row, int remainingBudget)
        {
            if (sw == null || row == null || remainingBudget <= 0)
                return 0;

            int written = 0;
            string details = BuildBodyfileDetails(row);

            written += TryWriteBodyfileActivityRow(sw, row.CreatedTime, "Created", row.Path, details, remainingBudget - written);
            written += TryWriteBodyfileActivityRow(sw, row.ModifiedTime, "Modified", row.Path, details, remainingBudget - written);
            written += TryWriteBodyfileActivityRow(sw, row.MetadataChangeTime, "MetadataChanged", row.Path, details, remainingBudget - written);
            written += TryWriteBodyfileActivityRow(sw, row.AccessTime, "Accessed", row.Path, details, remainingBudget - written);
            return written;
        }

        private static int TryWriteBodyfileActivityRow(StreamWriter sw, long unixSeconds, string action, string path, string details, int remainingBudget)
        {
            if (sw == null || remainingBudget <= 0 || unixSeconds <= 0)
                return 0;

            DateTime time;
            if (!TryUnixSecondsToUtc(unixSeconds, out time))
                return 0;

            sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5}",
                time.ToString("yyyy-MM-dd HH:mm:ss"),
                CsvUtils.EscapeField("Bodyfile"),
                CsvUtils.EscapeField(action),
                CsvUtils.EscapeField(path ?? ""),
                "",
                CsvUtils.EscapeField(details ?? "")));
            return 1;
        }

        private static string BuildBodyfileDetails(UacBodyfileRow row)
        {
            return string.Format(CultureInfo.InvariantCulture,
                "inode={0} mode={1} uid={2} gid={3} size={4}",
                row.Inode,
                row.Mode ?? "",
                row.UserId ?? "",
                row.GroupId ?? "",
                row.Size);
        }

        private static bool TryParseLong(string value, out long parsed)
        {
            return long.TryParse((value ?? "").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
        }

        private static bool TryUnixSecondsToUtc(long unixSeconds, out DateTime value)
        {
            value = DateTime.MinValue;
            if (unixSeconds <= 0)
                return false;

            try
            {
                value = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixSeconds);
                if (value.Year < 1970 || value.Year > 2100)
                    return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static UacSystemInfo TryReadAcquisitionLog(string folder)
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
                {
                    string ext = Path.GetExtension(file);
                    if (!string.Equals(ext, ".log", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(ext, ".txt", StringComparison.OrdinalIgnoreCase))
                        continue;

                    long len = 0;
                    try { len = new FileInfo(file).Length; } catch { }
                    if (len <= 0 || len > MaxInspectableTextFileBytes)
                        continue;

                    string[] lines = SafeReadAllLines(file);
                    if (lines == null || lines.Length == 0)
                        continue;
                    if (!string.Equals((lines[0] ?? "").Trim(), "Created by UAC (Unix-like Artifacts Collector)", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var info = new UacSystemInfo();
                    bool inSystemInfo = false;
                    for (int i = 0; i < lines.Length; i++)
                    {
                        string line = (lines[i] ?? "").Trim();
                        if (line.Length == 0) continue;
                        if (line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal))
                        {
                            inSystemInfo = string.Equals(line, "[System Information]", StringComparison.OrdinalIgnoreCase);
                            continue;
                        }
                        if (!inSystemInfo) continue;
                        if (line.StartsWith("Operating System:", StringComparison.OrdinalIgnoreCase))
                            info.OperatingSystem = AfterColon(line);
                        else if (line.StartsWith("System Architecture:", StringComparison.OrdinalIgnoreCase))
                            info.Architecture = AfterColon(line);
                        else if (line.StartsWith("Hostname:", StringComparison.OrdinalIgnoreCase))
                            info.Hostname = AfterColon(line);
                    }

                    if (!string.IsNullOrWhiteSpace(info.Hostname))
                        return info;
                }
            }
            catch { }
            return null;
        }

        private static UacSystemInfo TryReadUacLog(string folder)
        {
            string path = null;
            try
            {
                path = Directory.EnumerateFiles(folder, "uac.log", SearchOption.AllDirectories).FirstOrDefault();
            }
            catch { }
            if (string.IsNullOrEmpty(path)) return null;

            string[] lines = SafeReadAllLines(path);
            if (lines == null || lines.Length == 0) return null;

            var info = new UacSystemInfo();
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i] ?? "";
                if (line.IndexOf("Hostname:", StringComparison.OrdinalIgnoreCase) >= 0)
                    info.Hostname = ExtractInfValue(line, "Hostname:");
                else if (line.IndexOf("Operating system:", StringComparison.OrdinalIgnoreCase) >= 0)
                    info.OperatingSystem = ExtractInfValue(line, "Operating system:");
                else if (line.IndexOf("System architecture:", StringComparison.OrdinalIgnoreCase) >= 0)
                    info.Architecture = ExtractInfValue(line, "System architecture:");
            }

            return string.IsNullOrWhiteSpace(info.Hostname) ? null : info;
        }

        private static string ExtractInfValue(string line, string label)
        {
            int idx = line.IndexOf(label, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            return line.Substring(idx + label.Length).Trim();
        }

        private static string AfterColon(string line)
        {
            if (string.IsNullOrEmpty(line)) return "";
            int idx = line.IndexOf(':');
            return idx < 0 ? "" : line.Substring(idx + 1).Trim();
        }

        private static string CleanToken(string value)
        {
            return (value ?? "").Trim().Trim('"').Trim();
        }

        private static void Warn(List<string> warnings, string msg)
        {
            if (warnings != null) warnings.Add("UAC derive: " + msg);
        }

        private sealed class UacSystemInfo
        {
            public string Hostname;
            public string OperatingSystem;
            public string Architecture;
        }

        private sealed class UacProcessRow
        {
            public string Pid;
            public string Name;
            public string Path;
            public string CommandLine;
            public DateTime StartTime;
            public string User;
        }

        private sealed class UacBodyfileRow
        {
            public string Path;
            public long Inode;
            public string Mode;
            public string UserId;
            public string GroupId;
            public long Size;
            public long AccessTime;
            public long ModifiedTime;
            public long MetadataChangeTime;
            public long CreatedTime;
        }

        private sealed class UacAuthEventRow
        {
            public string TimeText;
            public string Source;
            public string Action;
            public string User;
            public string TargetUser;
            public string RemoteIp;
            public string RemoteName;
            public string Terminal;
            public string CommandLine;
            public string Details;
        }

        private sealed class UacNetworkConnectionRow
        {
            public string ObservedAtUtc;
            public string Collector;
            public string Protocol;
            public string State;
            public string LocalAddress;
            public string LocalPort;
            public string RemoteAddress;
            public string RemotePort;
            public string ProcessId;
            public string ProcessName;
            public string User;
            public string Details;
        }
    }
}
