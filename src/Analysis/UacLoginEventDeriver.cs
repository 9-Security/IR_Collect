using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Derives facts-only login records from UAC live-response text output.
    /// Local timestamps without a reliable numeric offset remain raw and do not
    /// receive an invented UTC value.
    /// </summary>
    public static class UacLoginEventDeriver
    {
        private const long MaxSourceBytes = 20L * 1024 * 1024;
        private const int MaxRows = 100000;
        private static readonly Regex BracketFieldRegex = new Regex(@"\[(?<value>[^\]]*)\]",
            RegexOptions.CultureInvariant);
        private static readonly Regex LastDateRegex = new Regex(
            @"(?<stamp>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}(?::\d{2})?(?:\s+\d{4})?)",
            RegexOptions.CultureInvariant);
        private static readonly Regex LastlogDateRegex = new Regex(
            @"(?<stamp>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\s+\d{4})\s*$",
            RegexOptions.CultureInvariant);
        private static readonly Regex DurationRegex = new Regex(@"\((?<duration>[^)]*)\)",
            RegexOptions.CultureInvariant);

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot, List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(sourceRoot) || !Directory.Exists(sourceRoot))
                return;
            if (string.IsNullOrWhiteSpace(outputRoot))
                return;
            Directory.CreateDirectory(outputRoot);

            string output = Path.Combine(outputRoot, ArtifactNames.UacLoginEventsCsv);
            if (File.Exists(output))
                return;

            List<string> candidates = EnumerateCandidateFiles(sourceRoot).ToList();
            if (candidates.Count == 0)
                return;

            var rows = new List<LoginEventRow>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            bool hitCap = false;

            List<string> lastFull = candidates.Where(IsFullLastFile).ToList();
            List<string> lastBasic = candidates.Where(IsBasicLastFile).ToList();
            List<string> lastbFull = candidates.Where(IsFullLastbFile).ToList();
            List<string> lastbBasic = candidates.Where(IsBasicLastbFile).ToList();

            hitCap = ParseLastFiles(sourceRoot, lastFull.Count > 0 ? lastFull : lastBasic,
                false, rows, seen, MaxRows);
            if (!hitCap)
                hitCap = ParseLastFiles(sourceRoot, lastbFull.Count > 0 ? lastbFull : lastbBasic,
                    true, rows, seen, MaxRows);

            if (!hitCap)
            {
                foreach (string file in candidates.Where(IsLastlogFile))
                {
                    if (ParseLastlogFile(sourceRoot, file, rows, seen, MaxRows))
                    {
                        hitCap = true;
                        break;
                    }
                }
            }

            if (!hitCap)
            {
                foreach (string file in candidates.Where(IsUtmpdumpFile))
                {
                    if (ParseUtmpdumpFile(sourceRoot, file, rows, seen, MaxRows))
                    {
                        hitCap = true;
                        break;
                    }
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Time,TimeUtc,EndTime,EndTimeUtc,TimeParseStatus,Action,User,Terminal,RemoteHost,RemoteAddress,ProcessId,RecordId,Duration,SourceType,SourcePath,LineNumber,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    LoginEventRow row = rows[i];
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.Time),
                        CsvUtils.EscapeField(row.TimeUtc),
                        CsvUtils.EscapeField(row.EndTime),
                        CsvUtils.EscapeField(row.EndTimeUtc),
                        CsvUtils.EscapeField(row.TimeParseStatus),
                        CsvUtils.EscapeField(row.Action),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.Terminal),
                        CsvUtils.EscapeField(row.RemoteHost),
                        CsvUtils.EscapeField(row.RemoteAddress),
                        CsvUtils.EscapeField(row.ProcessId),
                        CsvUtils.EscapeField(row.RecordId),
                        CsvUtils.EscapeField(row.Duration),
                        CsvUtils.EscapeField(row.SourceType),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (hitCap && warnings != null)
                warnings.Add("UAC derive: login events were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) + " rows.");
            Logger.Info("Derived " + ArtifactNames.UacLoginEventsCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string normalized = "/" + (relativePath ?? "").Replace('\\', '/').TrimStart('/').ToLowerInvariant();
            if (normalized.IndexOf("/live_response/system/", StringComparison.Ordinal) < 0)
                return false;

            string name = Path.GetFileName(normalized) ?? "";
            return IsFullLastName(name) ||
                IsFullLastbName(name) ||
                string.Equals(name, "last.txt", StringComparison.Ordinal) ||
                string.Equals(name, "lastb.txt", StringComparison.Ordinal) ||
                string.Equals(name, "lastlog.txt", StringComparison.Ordinal) ||
                IsUtmpdumpName(name);
        }

        private static IEnumerable<string> EnumerateCandidateFiles(string folder)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories); }
            catch { yield break; }

            foreach (string file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                string relative = ToRelativeSourcePath(folder, file);
                if (!IsSupportedSourceRelativePath(relative))
                    continue;

                long size;
                try { size = new FileInfo(file).Length; }
                catch { continue; }
                if (size <= 0 || size > MaxSourceBytes)
                    continue;
                yield return file;
            }
        }

        private static bool ParseLastFiles(string root, IEnumerable<string> files, bool failure,
            List<LoginEventRow> rows, HashSet<string> seen, int limit)
        {
            foreach (string file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                string source = ToRelativeSourcePath(root, file);
                string name = (Path.GetFileName(file) ?? "").ToLowerInvariant();
                bool fullFormat = failure ? IsFullLastbName(name) : IsFullLastName(name);
                int lineNumber = 0;
                using (var sr = OpenText(file))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        lineNumber++;
                        LoginEventRow row;
                        if (!TryParseLastLine(line, failure, fullFormat, source, lineNumber, out row))
                            continue;
                        if (!seen.Add(BuildDedupKey(row)))
                            continue;
                        rows.Add(row);
                        if (rows.Count >= limit)
                            return true;
                    }
                }
            }
            return false;
        }

        private static bool TryParseLastLine(string line, bool failure, bool fullFormat,
            string source, int lineNumber, out LoginEventRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            string trimmed = line.Trim();
            string lower = trimmed.ToLowerInvariant();
            if (lower.StartsWith("wtmp begins", StringComparison.Ordinal) ||
                lower.StartsWith("btmp begins", StringComparison.Ordinal))
                return false;

            MatchCollection dates = LastDateRegex.Matches(trimmed);
            if (dates.Count == 0)
                return false;

            string prefix = trimmed.Substring(0, dates[0].Index).Trim();
            string[] parts = SplitFields(prefix);
            if (parts.Length < 2)
                return false;

            row = new LoginEventRow();
            row.Time = dates[0].Groups["stamp"].Value.Trim();
            row.TimeParseStatus = HasFourDigitYear(row.Time)
                ? "local-time-no-offset"
                : "local-time-year-unavailable";
            row.User = parts[0];
            row.Terminal = parts[1];
            row.SourceType = failure ? "lastb" : "last";
            row.SourcePath = source;
            row.LineNumber = lineNumber;

            if (dates.Count > 1)
                row.EndTime = dates[1].Groups["stamp"].Value.Trim();

            Match duration = DurationRegex.Match(trimmed);
            if (duration.Success)
                row.Duration = duration.Groups["duration"].Value.Trim();

            string userLower = row.User.ToLowerInvariant();
            if (failure)
                row.Action = "LoginFailureObserved";
            else if (userLower == "reboot")
                row.Action = "SystemBootObserved";
            else if (userLower == "shutdown")
                row.Action = "SystemShutdownObserved";
            else if (userLower == "runlevel")
                row.Action = "RunLevelChanged";
            else
                row.Action = "LoginSessionObserved";

            string remote = "";
            string extraPrefix = "";
            if (!fullFormat && parts.Length >= 3 && !IsSystemPseudoUser(userLower))
            {
                remote = parts[2];
                if (parts.Length > 3)
                    extraPrefix = string.Join(" ", parts.Skip(3).ToArray());
            }
            else if (parts.Length > 2)
            {
                extraPrefix = string.Join(" ", parts.Skip(2).ToArray());
            }

            string tail = trimmed.Substring(dates[dates.Count - 1].Index +
                dates[dates.Count - 1].Length).Trim();
            string state = ExtractSessionState(trimmed);
            if (fullFormat)
            {
                string remoteFromTail = ExtractRemoteFromTail(tail, state, row.Duration);
                if (!string.IsNullOrEmpty(remoteFromTail))
                    remote = remoteFromTail;
            }
            SetRemote(row, remote);

            var details = new List<string>();
            if (!string.IsNullOrEmpty(state)) details.Add("session_state=" + state);
            if (!string.IsNullOrEmpty(extraPrefix)) details.Add("source_fields=" + extraPrefix);
            row.Details = string.Join("; ", details.ToArray());
            return true;
        }

        private static bool ParseLastlogFile(string root, string file, List<LoginEventRow> rows,
            HashSet<string> seen, int limit)
        {
            string source = ToRelativeSourcePath(root, file);
            int lineNumber = 0;
            using (var sr = OpenText(file))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    lineNumber++;
                    if (string.IsNullOrWhiteSpace(line) ||
                        line.IndexOf("Never logged in", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        line.TrimStart().StartsWith("Username", StringComparison.OrdinalIgnoreCase))
                        continue;

                    Match date = LastlogDateRegex.Match(line);
                    if (!date.Success)
                        continue;
                    string prefix = line.Substring(0, date.Index).Trim();
                    string[] parts = SplitFields(prefix);
                    if (parts.Length < 2)
                        continue;

                    var row = new LoginEventRow();
                    row.Time = date.Groups["stamp"].Value.Trim();
                    row.Action = "LastLoginObserved";
                    row.User = parts[0];
                    row.Terminal = parts[1];
                    if (parts.Length > 2) SetRemote(row, parts[2]);
                    row.SourceType = "lastlog";
                    row.SourcePath = source;
                    row.LineNumber = lineNumber;
                    DateTimeOffset parsed;
                    if (TryParseOffsetTimestamp(row.Time, out parsed))
                    {
                        row.TimeUtc = parsed.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);
                        row.TimeParseStatus = "offset-parsed";
                    }
                    else
                    {
                        row.TimeParseStatus = "local-time-no-offset";
                    }

                    if (!seen.Add(BuildDedupKey(row)))
                        continue;
                    rows.Add(row);
                    if (rows.Count >= limit)
                        return true;
                }
            }
            return false;
        }

        private static bool ParseUtmpdumpFile(string root, string file, List<LoginEventRow> rows,
            HashSet<string> seen, int limit)
        {
            string source = ToRelativeSourcePath(root, file);
            int lineNumber = 0;
            using (var sr = OpenText(file))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    lineNumber++;
                    MatchCollection fields = BracketFieldRegex.Matches(line ?? "");
                    if (fields.Count < 8)
                        continue;

                    int recordType;
                    if (!int.TryParse(Field(fields, 0), NumberStyles.Integer,
                        CultureInfo.InvariantCulture, out recordType))
                        continue;

                    string action = MapUtmpAction(recordType);
                    if (string.IsNullOrEmpty(action))
                        continue;

                    var row = new LoginEventRow();
                    row.Time = Field(fields, 7);
                    row.Action = action;
                    row.User = Field(fields, 3);
                    row.Terminal = Field(fields, 4);
                    row.ProcessId = Field(fields, 1);
                    row.RecordId = Field(fields, 2);
                    row.SourceType = "utmpdump";
                    row.SourcePath = source;
                    row.LineNumber = lineNumber;
                    row.Details = "ut_type=" + recordType.ToString(CultureInfo.InvariantCulture);
                    SetRemote(row, Field(fields, 5));
                    string address = Field(fields, 6);
                    if (!string.IsNullOrWhiteSpace(address) &&
                        !string.Equals(address, "0.0.0.0", StringComparison.Ordinal) &&
                        !string.Equals(address, "::", StringComparison.Ordinal))
                        row.RemoteAddress = address;

                    DateTimeOffset parsed;
                    if (TryParseOffsetTimestamp(row.Time, out parsed))
                    {
                        row.TimeUtc = parsed.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);
                        row.TimeParseStatus = "offset-parsed";
                    }
                    else
                    {
                        row.TimeParseStatus = "timestamp-unparsed";
                    }

                    if (!seen.Add(BuildDedupKey(row)))
                        continue;
                    rows.Add(row);
                    if (rows.Count >= limit)
                        return true;
                }
            }
            return false;
        }

        private static string MapUtmpAction(int type)
        {
            switch (type)
            {
                case 1: return "RunLevelChanged";
                case 2: return "SystemBootObserved";
                case 3: return "ClockNewTimeObserved";
                case 4: return "ClockOldTimeObserved";
                case 5: return "InitProcessObserved";
                case 6: return "LoginProcessObserved";
                case 7: return "LoginSessionStarted";
                case 8: return "LoginSessionEnded";
                case 9: return "AccountingObserved";
                default: return "";
            }
        }

        private static string Field(MatchCollection fields, int index)
        {
            if (fields == null || index < 0 || index >= fields.Count)
                return "";
            return (fields[index].Groups["value"].Value ?? "").Trim();
        }

        private static bool TryParseOffsetTimestamp(string value, out DateTimeOffset parsed)
        {
            parsed = DateTimeOffset.MinValue;
            string normalized = (value ?? "").Trim();
            if (normalized.Length == 0)
                return false;

            normalized = Regex.Replace(normalized, @"([+-]\d{2})(\d{2})(?=\s+\d{4}$)", "$1:$2");
            string[] formats = new string[]
            {
                "yyyy-MM-dd'T'HH:mm:ss','FFFFFFFzzz",
                "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz",
                "ddd MMM d HH:mm:ss zzz yyyy",
                "ddd MMM dd HH:mm:ss zzz yyyy"
            };
            return DateTimeOffset.TryParseExact(normalized, formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out parsed);
        }

        private static string ExtractSessionState(string line)
        {
            string lower = (line ?? "").ToLowerInvariant();
            if (lower.IndexOf("still logged in", StringComparison.Ordinal) >= 0) return "still-logged-in";
            if (lower.IndexOf("gone - no logout", StringComparison.Ordinal) >= 0) return "no-logout";
            if (lower.IndexOf("- crash", StringComparison.Ordinal) >= 0) return "crash";
            if (lower.IndexOf("- down", StringComparison.Ordinal) >= 0) return "down";
            return "";
        }

        private static string ExtractRemoteFromTail(string tail, string state, string duration)
        {
            string value = tail ?? "";
            if (!string.IsNullOrEmpty(duration))
                value = value.Replace("(" + duration + ")", " ");
            value = value.Replace("-", " ");
            if (string.Equals(state, "still-logged-in", StringComparison.Ordinal))
                value = Regex.Replace(value, @"\bstill\s+logged\s+in\b", " ", RegexOptions.IgnoreCase);
            else if (string.Equals(state, "no-logout", StringComparison.Ordinal))
                value = Regex.Replace(value, @"\bgone\s+no\s+logout\b", " ", RegexOptions.IgnoreCase);
            else if (string.Equals(state, "crash", StringComparison.Ordinal))
                value = Regex.Replace(value, @"\bcrash\b", " ", RegexOptions.IgnoreCase);
            else if (string.Equals(state, "down", StringComparison.Ordinal))
                value = Regex.Replace(value, @"\bdown\b", " ", RegexOptions.IgnoreCase);

            string[] parts = SplitFields(value);
            if (parts.Length != 1)
                return "";
            return parts[0];
        }

        private static void SetRemote(LoginEventRow row, string value)
        {
            if (row == null || string.IsNullOrWhiteSpace(value))
                return;
            string candidate = value.Trim();
            IPAddress address;
            if (IPAddress.TryParse(candidate, out address))
                row.RemoteAddress = candidate;
            else
                row.RemoteHost = candidate;
        }

        private static string BuildDedupKey(LoginEventRow row)
        {
            return string.Join("|", new string[]
            {
                row.SourcePath ?? "",
                row.SourceType ?? "",
                row.Action ?? "",
                row.Time ?? "",
                row.EndTime ?? "",
                row.User ?? "",
                row.Terminal ?? "",
                row.RemoteHost ?? "",
                row.RemoteAddress ?? "",
                row.ProcessId ?? "",
                row.RecordId ?? ""
            });
        }

        private static string[] SplitFields(string value)
        {
            return Regex.Split((value ?? "").Trim(), @"\s+")
                .Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
        }

        private static bool HasFourDigitYear(string value)
        {
            return Regex.IsMatch(value ?? "", @"\b\d{4}\s*$", RegexOptions.CultureInvariant);
        }

        private static bool IsSystemPseudoUser(string value)
        {
            return value == "reboot" || value == "shutdown" || value == "runlevel";
        }

        private static bool IsFullLastFile(string file)
        {
            return IsFullLastName((Path.GetFileName(file) ?? "").ToLowerInvariant());
        }

        private static bool IsFullLastbFile(string file)
        {
            return IsFullLastbName((Path.GetFileName(file) ?? "").ToLowerInvariant());
        }

        private static bool IsBasicLastFile(string file)
        {
            return string.Equals(Path.GetFileName(file), "last.txt", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsBasicLastbFile(string file)
        {
            return string.Equals(Path.GetFileName(file), "lastb.txt", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsLastlogFile(string file)
        {
            return string.Equals(Path.GetFileName(file), "lastlog.txt", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsUtmpdumpFile(string file)
        {
            return IsUtmpdumpName((Path.GetFileName(file) ?? "").ToLowerInvariant());
        }

        private static bool IsFullLastName(string name)
        {
            return (name ?? "").StartsWith("last_-a_-f", StringComparison.Ordinal) &&
                (name ?? "").EndsWith(".txt", StringComparison.Ordinal) &&
                !(name ?? "").StartsWith("lastb_", StringComparison.Ordinal);
        }

        private static bool IsFullLastbName(string name)
        {
            return (name ?? "").StartsWith("lastb_-a_-f", StringComparison.Ordinal) &&
                (name ?? "").EndsWith(".txt", StringComparison.Ordinal);
        }

        private static bool IsUtmpdumpName(string name)
        {
            string value = name ?? "";
            return value.StartsWith("utmpdump_", StringComparison.Ordinal) &&
                value.EndsWith(".txt", StringComparison.Ordinal) &&
                value.IndexOf("_files.txt", StringComparison.Ordinal) < 0;
        }

        private static StreamReader OpenText(string file)
        {
            return new StreamReader(file, Encoding.UTF8, true);
        }

        private static string ToRelativeSourcePath(string root, string file)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                string fileFull = Path.GetFullPath(file);
                if (fileFull.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
                    return fileFull.Substring(rootFull.Length).Replace('\\', '/');
            }
            catch { }
            return (file ?? "").Replace('\\', '/');
        }

        private sealed class LoginEventRow
        {
            public string Time = "";
            public string TimeUtc = "";
            public string EndTime = "";
            public string EndTimeUtc = "";
            public string TimeParseStatus = "";
            public string Action = "";
            public string User = "";
            public string Terminal = "";
            public string RemoteHost = "";
            public string RemoteAddress = "";
            public string ProcessId = "";
            public string RecordId = "";
            public string Duration = "";
            public string SourceType = "";
            public string SourcePath = "";
            public int LineNumber;
            public string Details = "";
        }
    }
}
