using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Bounded RFC 3164 / RFC 5424 / ISO-style text system-log intake.
    /// Yearless or offset-less timestamps remain raw and never receive an
    /// inferred UTC value.
    /// </summary>
    public static class UacSystemLogDeriver
    {
        private const long MaxSourceFileBytes = 1024L * 1024 * 1024;
        private const long MaxExpandedCharactersPerFile = 256L * 1024 * 1024;
        private const int MaxLineCharacters = 1024 * 1024;
        private const int MaxMessageCharacters = 4096;
        private const int MaxRows = 50000;
        private static readonly Regex Rfc5424Regex = new Regex(
            @"^<(?<pri>\d{1,3})>(?<version>\d{1,3})\s+(?<stamp>\S+)\s+(?<host>\S+)\s+(?<app>\S+)\s+(?<proc>\S+)\s+(?<msgid>\S+)\s*(?<rest>.*)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex IsoRegex = new Regex(
            @"^(?:<(?<pri>\d{1,3})>)?(?<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?<host>\S+)\s+(?<payload>.+)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex Rfc3164Regex = new Regex(
            @"^(?:<(?<pri>\d{1,3})>)?(?<stamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<payload>.+)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex TagRegex = new Regex(
            @"^(?<program>[A-Za-z0-9_.@/+\-]+)(?:\[(?<pid>\d+)\])?(?:\s+<(?<level>[^>]+)>)?:\s*(?<message>.*)$",
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

            string output = Path.Combine(outputRoot, ArtifactNames.UacSystemLogEventsCsv);
            if (File.Exists(output))
                return;

            List<string> files = EnumerateSystemLogFiles(sourceRoot).ToList();
            if (files.Count == 0)
                return;

            var rows = new List<SystemLogRow>();
            bool hitCap = false;
            for (int i = 0; i < files.Count && !hitCap; i++)
            {
                try
                {
                    bool expandedCap;
                    int oversizedLines;
                    hitCap = ParseFile(sourceRoot, files[i], rows, MaxRows,
                        out expandedCap, out oversizedLines);
                    if (expandedCap)
                        Warn(warnings, "system-log expanded-text limit was reached: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    if (oversizedLines > 0)
                        Warn(warnings, "system-log source contained " +
                            oversizedLines.ToString(CultureInfo.InvariantCulture) +
                            " oversized line(s) that remained raw: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                }
                catch (Exception ex)
                {
                    Warn(warnings, "system-log source could not be parsed: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + " (" + (ex.Message ?? "") + ")");
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Time,TimeUtc,TimeParseStatus,Host,Facility,Severity,Program,ProcessId,MessageId,Message,SourcePath,LineNumber,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    SystemLogRow row = rows[i];
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.Time),
                        CsvUtils.EscapeField(row.TimeUtc),
                        CsvUtils.EscapeField(row.TimeParseStatus),
                        CsvUtils.EscapeField(row.Host),
                        CsvUtils.EscapeField(row.Facility),
                        CsvUtils.EscapeField(row.Severity),
                        CsvUtils.EscapeField(row.Program),
                        CsvUtils.EscapeField(row.ProcessId),
                        CsvUtils.EscapeField(row.MessageId),
                        CsvUtils.EscapeField(row.Message),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (hitCap)
                Warn(warnings, "system-log events were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) + " rows.");
            Logger.Info("Derived " + ArtifactNames.UacSystemLogEventsCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            bool underLinuxLog = path.IndexOf("/root/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/[root]/var/log/", StringComparison.Ordinal) >= 0;
            bool underMacLog = path.IndexOf("/root/private/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/[root]/private/var/log/", StringComparison.Ordinal) >= 0;
            if (!underLinuxLog && !underMacLog)
                return false;
            if (UacAuditEventDeriver.IsSupportedSourceRelativePath(path))
                return false;

            string name = Path.GetFileName(path) ?? "";
            return MatchesLogFamily(name, "syslog") ||
                MatchesLogFamily(name, "messages") ||
                MatchesLogFamily(name, "kern.log") ||
                MatchesLogFamily(name, "daemon.log") ||
                MatchesLogFamily(name, "user.log") ||
                MatchesLogFamily(name, "debug") ||
                MatchesLogFamily(name, "system.log");
        }

        private static bool MatchesLogFamily(string name, string baseName)
        {
            return string.Equals(name, baseName, StringComparison.Ordinal) ||
                name.StartsWith(baseName + ".", StringComparison.Ordinal) ||
                name.StartsWith(baseName + "-", StringComparison.Ordinal);
        }

        private static IEnumerable<string> EnumerateSystemLogFiles(string folder)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories); }
            catch { yield break; }

            foreach (string file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                if (!IsSupportedSourceRelativePath(ToRelativeSourcePath(folder, file)))
                    continue;
                long size;
                try { size = new FileInfo(file).Length; }
                catch { continue; }
                if (size <= 0 || size > MaxSourceFileBytes)
                    continue;
                yield return file;
            }
        }

        private static bool ParseFile(string root, string file,
            List<SystemLogRow> rows, int limit, out bool expandedCap,
            out int oversizedLines)
        {
            expandedCap = false;
            oversizedLines = 0;
            string source = ToRelativeSourcePath(root, file);
            using (var reader = OpenText(file))
            using (var bounded = new BoundedLineReader(reader, MaxLineCharacters,
                MaxExpandedCharactersPerFile))
            {
                string line;
                bool oversized;
                int lineNumber = 0;
                while ((line = bounded.ReadLine(out oversized)) != null)
                {
                    lineNumber++;
                    if (oversized)
                    {
                        oversizedLines++;
                        continue;
                    }

                    SystemLogRow row;
                    if (!TryParseLine(line, source, lineNumber, out row))
                        continue;
                    rows.Add(row);
                    if (rows.Count >= limit)
                        return true;
                }
                expandedCap = bounded.TotalLimitReached;
            }
            return false;
        }

        private static bool TryParseLine(string line, string source,
            int lineNumber, out SystemLogRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            Match rfc5424 = Rfc5424Regex.Match(line);
            if (rfc5424.Success)
            {
                row = NewRow(source, lineNumber);
                row.Time = CleanNil(rfc5424.Groups["stamp"].Value);
                ApplyTimestamp(row);
                row.Host = CleanNil(rfc5424.Groups["host"].Value);
                row.Program = CleanNil(rfc5424.Groups["app"].Value);
                row.ProcessId = CleanNil(rfc5424.Groups["proc"].Value);
                row.MessageId = CleanNil(rfc5424.Groups["msgid"].Value);
                ApplyPriority(row, rfc5424.Groups["pri"].Value);
                string structuredData;
                row.Message = ExtractRfc5424Message(rfc5424.Groups["rest"].Value,
                    out structuredData);
                if (!string.IsNullOrWhiteSpace(structuredData))
                    row.Details = "structured_data=" + LimitText(structuredData, 4096);
                LimitMessage(row);
                return true;
            }

            Match iso = IsoRegex.Match(line);
            if (iso.Success)
            {
                row = NewRow(source, lineNumber);
                row.Time = iso.Groups["stamp"].Value.Trim();
                ApplyTimestamp(row);
                row.Host = iso.Groups["host"].Value.Trim();
                ApplyPriority(row, iso.Groups["pri"].Value);
                ApplyTag(row, iso.Groups["payload"].Value);
                LimitMessage(row);
                return true;
            }

            Match rfc3164 = Rfc3164Regex.Match(line);
            if (rfc3164.Success)
            {
                row = NewRow(source, lineNumber);
                row.Time = rfc3164.Groups["stamp"].Value.Trim();
                row.TimeParseStatus = "local-time-year-and-offset-unavailable";
                row.Host = rfc3164.Groups["host"].Value.Trim();
                ApplyPriority(row, rfc3164.Groups["pri"].Value);
                ApplyTag(row, rfc3164.Groups["payload"].Value);
                LimitMessage(row);
                return true;
            }

            return false;
        }

        private static SystemLogRow NewRow(string source, int lineNumber)
        {
            var row = new SystemLogRow();
            row.SourcePath = source ?? "";
            row.LineNumber = lineNumber;
            return row;
        }

        private static void ApplyTimestamp(SystemLogRow row)
        {
            if (row == null || string.IsNullOrWhiteSpace(row.Time))
            {
                if (row != null) row.TimeParseStatus = "timestamp-missing";
                return;
            }

            string value = row.Time.Trim();
            if (value.IndexOf(',') >= 0)
                value = value.Replace(',', '.');
            value = Regex.Replace(value, @"([+-]\d{2})(\d{2})$", "$1:$2");
            bool hasOffset = value.EndsWith("Z", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(value, @"[+-]\d{2}:\d{2}$", RegexOptions.CultureInvariant);
            if (!hasOffset)
            {
                row.TimeParseStatus = "local-time-no-offset";
                return;
            }

            DateTimeOffset parsed;
            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out parsed))
            {
                row.TimeUtc = parsed.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);
                row.TimeParseStatus = "offset-parsed";
            }
            else
            {
                row.TimeParseStatus = "timestamp-unparsed";
            }
        }

        private static void ApplyTag(SystemLogRow row, string payload)
        {
            string text = (payload ?? "").Trim();
            Match tag = TagRegex.Match(text);
            if (!tag.Success)
            {
                row.Message = text;
                return;
            }

            row.Program = tag.Groups["program"].Value.Trim();
            row.ProcessId = tag.Groups["pid"].Value.Trim();
            row.Message = tag.Groups["message"].Value;
            if (string.IsNullOrWhiteSpace(row.Severity) &&
                !string.IsNullOrWhiteSpace(tag.Groups["level"].Value))
                row.Severity = tag.Groups["level"].Value.Trim().ToLowerInvariant();
        }

        private static void ApplyPriority(SystemLogRow row, string priorityText)
        {
            int priority;
            if (row == null || !int.TryParse(priorityText, NumberStyles.None,
                CultureInfo.InvariantCulture, out priority) ||
                priority < 0 || priority > 191)
                return;

            int facility = priority / 8;
            int severity = priority % 8;
            row.Facility = FacilityName(facility);
            row.Severity = SeverityName(severity);
            row.Details = AppendDetail(row.Details, "pri=" +
                priority.ToString(CultureInfo.InvariantCulture));
        }

        private static string FacilityName(int value)
        {
            string[] names = new string[]
            {
                "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
                "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
                "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"
            };
            return value >= 0 && value < names.Length ? names[value] : value.ToString(CultureInfo.InvariantCulture);
        }

        private static string SeverityName(int value)
        {
            string[] names = new string[]
            {
                "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
            };
            return value >= 0 && value < names.Length ? names[value] : value.ToString(CultureInfo.InvariantCulture);
        }

        private static string ExtractRfc5424Message(string rest,
            out string structuredData)
        {
            structuredData = "";
            string value = (rest ?? "").TrimStart();
            if (value.Length == 0)
                return "";
            if (value[0] == '-')
                return value.Length > 1 ? value.Substring(1).TrimStart() : "";
            if (value[0] != '[')
                return value;

            int index = 0;
            bool quoted = false;
            bool escaped = false;
            int lastClose = -1;
            while (index < value.Length)
            {
                char c = value[index];
                if (escaped)
                {
                    escaped = false;
                }
                else if (c == '\\' && quoted)
                {
                    escaped = true;
                }
                else if (c == '"')
                {
                    quoted = !quoted;
                }
                else if (c == ']' && !quoted)
                {
                    lastClose = index;
                    int next = index + 1;
                    while (next < value.Length && char.IsWhiteSpace(value[next])) next++;
                    if (next >= value.Length || value[next] != '[')
                        break;
                    index = next;
                    continue;
                }
                index++;
            }

            if (lastClose < 0)
                return value;
            structuredData = value.Substring(0, lastClose + 1);
            return value.Substring(lastClose + 1).TrimStart();
        }

        private static void LimitMessage(SystemLogRow row)
        {
            if (row == null)
                return;
            string message = row.Message ?? "";
            if (message.Length <= MaxMessageCharacters)
                return;
            row.Message = message.Substring(0, MaxMessageCharacters);
            row.Details = AppendDetail(row.Details, "message_truncated=true");
        }

        private static string LimitText(string value, int limit)
        {
            string text = value ?? "";
            return text.Length <= limit ? text : text.Substring(0, limit);
        }

        private static string CleanNil(string value)
        {
            string text = (value ?? "").Trim();
            return text == "-" ? "" : text;
        }

        private static string AppendDetail(string existing, string detail)
        {
            if (string.IsNullOrWhiteSpace(detail))
                return existing ?? "";
            if (string.IsNullOrWhiteSpace(existing))
                return detail;
            return existing + "; " + detail;
        }

        private static StreamReader OpenText(string file)
        {
            FileStream input = new FileStream(file, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (file.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return new StreamReader(new GZipStream(input, CompressionMode.Decompress),
                        Encoding.UTF8, true);
                }
                catch
                {
                    input.Dispose();
                    throw;
                }
            }
            return new StreamReader(input, Encoding.UTF8, true);
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

        private static void Warn(List<string> warnings, string message)
        {
            if (warnings != null)
                warnings.Add("UAC derive: " + (message ?? ""));
        }

        private sealed class BoundedLineReader : IDisposable
        {
            private readonly TextReader _reader;
            private readonly int _maxLineCharacters;
            private readonly long _maxTotalCharacters;
            private long _totalCharacters;

            public bool TotalLimitReached { get; private set; }

            public BoundedLineReader(TextReader reader, int maxLineCharacters,
                long maxTotalCharacters)
            {
                _reader = reader;
                _maxLineCharacters = maxLineCharacters;
                _maxTotalCharacters = maxTotalCharacters;
            }

            public string ReadLine(out bool oversized)
            {
                oversized = false;
                if (TotalLimitReached)
                    return null;

                var sb = new StringBuilder();
                bool sawCharacter = false;
                while (true)
                {
                    if (_totalCharacters >= _maxTotalCharacters)
                    {
                        TotalLimitReached = true;
                        oversized = true;
                        return sawCharacter ? sb.ToString() : null;
                    }

                    int value = _reader.Read();
                    if (value < 0)
                        return sawCharacter ? sb.ToString() : null;

                    _totalCharacters++;
                    sawCharacter = true;
                    char c = (char)value;
                    if (c == '\n')
                        return sb.ToString();
                    if (c == '\r')
                        continue;
                    if (sb.Length < _maxLineCharacters)
                        sb.Append(c);
                    else
                        oversized = true;
                }
            }

            public void Dispose()
            {
            }
        }

        private sealed class SystemLogRow
        {
            public string Time = "";
            public string TimeUtc = "";
            public string TimeParseStatus = "";
            public string Host = "";
            public string Facility = "";
            public string Severity = "";
            public string Program = "";
            public string ProcessId = "";
            public string MessageId = "";
            public string Message = "";
            public string SourcePath = "";
            public int LineNumber;
            public string Details = "";
        }
    }
}
