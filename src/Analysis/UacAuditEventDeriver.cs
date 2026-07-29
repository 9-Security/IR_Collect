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
    /// Bounded Linux auditd raw-log normalizer. Records sharing the same
    /// audit(epoch:serial) identifier are grouped into one facts-only event.
    /// </summary>
    public static class UacAuditEventDeriver
    {
        private const long MaxSourceFileBytes = 1024L * 1024 * 1024;
        private const long MaxExpandedTextBytesPerFile = 256L * 1024 * 1024;
        private const int MaxRows = 100000;
        private const int MaxPendingEvents = 2048;
        private const int MaxArguments = 256;
        private const int MaxPaths = 64;
        private static readonly Regex RecordRegex = new Regex(
            @"^(?:node=(?<node>\S+)\s+)?type=(?<type>\S+)\s+msg=audit\((?<epoch>\d+(?:\.\d+)?):(?<serial>\d+)\):?\s*(?<body>.*)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex FieldRegex = new Regex(
            @"(?<key>[A-Za-z0-9_.-]+)=(?:""(?<double>(?:\\.|[^""])*)""|'(?<single>(?:\\.|[^'])*)'|(?<bare>[^\s]+))",
            RegexOptions.CultureInvariant);
        private static readonly Regex ArgumentNameRegex = new Regex(@"^a(?<index>\d+)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex AvcRegex = new Regex(
            @"\bavc:\s*(?<decision>[A-Za-z_]+)\s*\{(?<permissions>[^}]*)\}",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex HexRegex = new Regex(@"^[0-9A-Fa-f]+$",
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

            string output = Path.Combine(outputRoot, ArtifactNames.UacAuditEventsCsv);
            if (File.Exists(output))
                return;

            List<string> files = EnumerateAuditFiles(sourceRoot).ToList();
            if (files.Count == 0)
                return;

            var rows = new List<AuditEventRow>();
            bool hitCap = false;
            for (int i = 0; i < files.Count && !hitCap; i++)
            {
                try
                {
                    bool expandedTextCapped;
                    int pendingEvictions;
                    hitCap = ParseAuditFile(sourceRoot, files[i], rows, MaxRows,
                        out expandedTextCapped, out pendingEvictions);
                    if (expandedTextCapped)
                        Warn(warnings, "audit source expanded-text limit was reached: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    if (pendingEvictions > 0)
                        Warn(warnings, "audit source exceeded the pending-event grouping limit; " +
                            pendingEvictions.ToString(CultureInfo.InvariantCulture) +
                            " event(s) were emitted with grouping_boundary=pending-cap: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                }
                catch (Exception ex)
                {
                    Warn(warnings, "audit source could not be parsed: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + " (" + (ex.Message ?? "") + ")");
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("TimeUtc,AuditEventId,RecordTypes,Action,Success,Syscall,Executable,CommandLine,WorkingDirectory,User,AuditUserId,RealUserId,EffectiveUserId,SessionId,ProcessId,ParentProcessId,Terminal,RemoteAddress,RemoteHost,TargetPaths,SELinuxDecision,SourcePath,LineNumbers,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    AuditEventRow row = rows[i];
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.TimeUtc),
                        CsvUtils.EscapeField(row.AuditEventId),
                        CsvUtils.EscapeField(row.RecordTypes),
                        CsvUtils.EscapeField(row.Action),
                        CsvUtils.EscapeField(row.Success),
                        CsvUtils.EscapeField(row.Syscall),
                        CsvUtils.EscapeField(row.Executable),
                        CsvUtils.EscapeField(row.CommandLine),
                        CsvUtils.EscapeField(row.WorkingDirectory),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.AuditUserId),
                        CsvUtils.EscapeField(row.RealUserId),
                        CsvUtils.EscapeField(row.EffectiveUserId),
                        CsvUtils.EscapeField(row.SessionId),
                        CsvUtils.EscapeField(row.ProcessId),
                        CsvUtils.EscapeField(row.ParentProcessId),
                        CsvUtils.EscapeField(row.Terminal),
                        CsvUtils.EscapeField(row.RemoteAddress),
                        CsvUtils.EscapeField(row.RemoteHost),
                        CsvUtils.EscapeField(row.TargetPaths),
                        CsvUtils.EscapeField(row.SelinuxDecision),
                        CsvUtils.EscapeField(row.SourcePath),
                        CsvUtils.EscapeField(row.LineNumbers),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (hitCap)
                Warn(warnings, "audit events were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) + " rows.");
            Logger.Info("Derived " + ArtifactNames.UacAuditEventsCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            if (path.IndexOf("/root/var/log/audit/", StringComparison.Ordinal) < 0 &&
                path.IndexOf("/[root]/var/log/audit/", StringComparison.Ordinal) < 0)
                return false;

            string name = Path.GetFileName(path) ?? "";
            return name == "audit.log" ||
                name.StartsWith("audit.log.", StringComparison.Ordinal);
        }

        private static IEnumerable<string> EnumerateAuditFiles(string folder)
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

        private static bool ParseAuditFile(string root, string file,
            List<AuditEventRow> rows, int limit, out bool expandedTextCapped,
            out int pendingEvictions)
        {
            expandedTextCapped = false;
            pendingEvictions = 0;
            string source = ToRelativeSourcePath(root, file);
            var pending = new Dictionary<string, AuditEventBuilder>(StringComparer.Ordinal);
            var order = new Queue<string>();
            long expandedBytes = 0;
            int lineNumber = 0;

            using (var reader = OpenAuditText(file))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;
                    expandedBytes += Encoding.UTF8.GetByteCount(line) + 1;
                    if (expandedBytes > MaxExpandedTextBytesPerFile)
                    {
                        expandedTextCapped = true;
                        break;
                    }

                    Match match = RecordRegex.Match(line);
                    if (!match.Success)
                        continue;

                    string eventId = match.Groups["epoch"].Value + ":" +
                        match.Groups["serial"].Value;
                    AuditEventBuilder builder;
                    if (!pending.TryGetValue(eventId, out builder))
                    {
                        while (pending.Count >= MaxPendingEvents)
                        {
                            AuditEventBuilder evicted = RemoveOldestPending(pending, order);
                            if (evicted == null)
                                break;
                            evicted.MarkGroupingBoundary("pending-cap");
                            pendingEvictions++;
                            rows.Add(evicted.ToRow());
                            if (rows.Count >= limit)
                                return true;
                        }

                        builder = new AuditEventBuilder(eventId,
                            match.Groups["epoch"].Value, source, lineNumber);
                        pending[eventId] = builder;
                        order.Enqueue(eventId);
                    }

                    builder.AddRecord(match.Groups["type"].Value,
                        match.Groups["node"].Value, match.Groups["body"].Value, lineNumber);

                    if (string.Equals(match.Groups["type"].Value, "EOE",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        builder.MarkGroupingBoundary("eoe");
                        pending.Remove(eventId);
                        rows.Add(builder.ToRow());
                        if (rows.Count >= limit)
                            return true;
                    }
                }
            }

            while (pending.Count > 0)
            {
                AuditEventBuilder builder = RemoveOldestPending(pending, order);
                if (builder == null)
                    break;
                builder.MarkGroupingBoundary("source-end");
                rows.Add(builder.ToRow());
                if (rows.Count >= limit)
                    return true;
            }
            return false;
        }

        private static AuditEventBuilder RemoveOldestPending(
            Dictionary<string, AuditEventBuilder> pending, Queue<string> order)
        {
            while (order.Count > 0)
            {
                string id = order.Dequeue();
                AuditEventBuilder builder;
                if (pending.TryGetValue(id, out builder))
                {
                    pending.Remove(id);
                    return builder;
                }
            }
            return null;
        }

        private static StreamReader OpenAuditText(string file)
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

        private static Dictionary<string, string> ParseFields(string body)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            MatchCollection matches = FieldRegex.Matches(body ?? "");
            for (int i = 0; i < matches.Count; i++)
            {
                Match match = matches[i];
                string key = match.Groups["key"].Value;
                string value;
                if (match.Groups["double"].Success)
                    value = UnescapeQuoted(match.Groups["double"].Value);
                else if (match.Groups["single"].Success)
                    value = UnescapeQuoted(match.Groups["single"].Value);
                else
                    value = match.Groups["bare"].Value;
                if (!result.ContainsKey(key))
                    result[key] = value ?? "";
            }

            string nested;
            if (result.TryGetValue("msg", out nested) && !string.IsNullOrWhiteSpace(nested))
            {
                MatchCollection nestedMatches = FieldRegex.Matches(nested);
                for (int i = 0; i < nestedMatches.Count; i++)
                {
                    Match match = nestedMatches[i];
                    string key = match.Groups["key"].Value;
                    if (result.ContainsKey(key))
                        continue;
                    string value;
                    if (match.Groups["double"].Success)
                        value = UnescapeQuoted(match.Groups["double"].Value);
                    else if (match.Groups["single"].Success)
                        value = UnescapeQuoted(match.Groups["single"].Value);
                    else
                        value = match.Groups["bare"].Value;
                    result[key] = value ?? "";
                }
            }
            return result;
        }

        private static string UnescapeQuoted(string value)
        {
            return (value ?? "").Replace("\\\"", "\"").Replace("\\\\", "\\");
        }

        private static bool TryFormatEpochUtc(string epoch, out string utc)
        {
            utc = "";
            string value = (epoch ?? "").Trim();
            int dot = value.IndexOf('.');
            string secondsText = dot >= 0 ? value.Substring(0, dot) : value;
            string fractionText = dot >= 0 ? value.Substring(dot + 1) : "";
            long seconds;
            if (!long.TryParse(secondsText, NumberStyles.None,
                CultureInfo.InvariantCulture, out seconds) || seconds < 0)
                return false;

            long ticks = 0;
            if (fractionText.Length > 0)
            {
                string fraction = fractionText.Length > 7
                    ? fractionText.Substring(0, 7)
                    : fractionText.PadRight(7, '0');
                if (!long.TryParse(fraction, NumberStyles.None,
                    CultureInfo.InvariantCulture, out ticks))
                    return false;
            }

            try
            {
                DateTime time = new DateTime(1970, 1, 1, 0, 0, 0,
                    DateTimeKind.Utc).AddSeconds(seconds).AddTicks(ticks);
                utc = time.ToString("o", CultureInfo.InvariantCulture);
                return true;
            }
            catch { return false; }
        }

        private static string DecodeAuditString(string value, bool allowHex)
        {
            string text = (value ?? "").Trim();
            if (text.Length == 0 || string.Equals(text, "(null)",
                StringComparison.OrdinalIgnoreCase))
                return "";
            if (!allowHex || text.Length < 2 || (text.Length % 2) != 0 ||
                !HexRegex.IsMatch(text))
                return text;

            try
            {
                byte[] bytes = new byte[text.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                    bytes[i] = byte.Parse(text.Substring(i * 2, 2),
                        NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                string decoded = new UTF8Encoding(false, true).GetString(bytes);
                for (int i = 0; i < decoded.Length; i++)
                {
                    char c = decoded[i];
                    if (c == '\0' || c == '\t' || c == '\r' || c == '\n')
                        continue;
                    if (char.IsControl(c))
                        return text;
                }
                return decoded;
            }
            catch { return text; }
        }

        private static string QuoteArgument(string value)
        {
            string text = value ?? "";
            if (text.Length == 0)
                return "\"\"";
            if (text.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0)
                return text;
            return "\"" + text.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        private static string EncodePathList(IEnumerable<string> paths)
        {
            var encoded = new List<string>();
            if (paths == null)
                return "";
            foreach (string path in paths)
            {
                var sb = new StringBuilder();
                string value = path ?? "";
                for (int i = 0; i < value.Length; i++)
                {
                    char c = value[i];
                    if (c == '\\' || c == '|')
                        sb.Append('\\');
                    sb.Append(c);
                }
                encoded.Add(sb.ToString());
            }
            return string.Join("|", encoded.ToArray());
        }

        private static string NormalizeSuccess(Dictionary<string, string> values)
        {
            string value = GetFirst(values, "success", "res", "result");
            string lower = (value ?? "").Trim().ToLowerInvariant();
            if (lower == "yes" || lower == "success" || lower == "succeeded" ||
                lower == "granted")
                return "success";
            if (lower == "no" || lower == "failed" || lower == "failure" ||
                lower == "denied")
                return "failure";
            return value ?? "";
        }

        private static string DetermineAction(HashSet<string> types, string success)
        {
            if (HasType(types, "AVC")) return "AccessControlDecisionObserved";
            if (HasType(types, "USER_AUTH"))
                return success == "success" ? "AuthenticationSucceeded" :
                    success == "failure" ? "AuthenticationFailed" : "AuthenticationObserved";
            if (HasType(types, "USER_LOGIN"))
                return success == "success" ? "LoginSucceeded" :
                    success == "failure" ? "LoginFailed" : "LoginObserved";
            if (HasType(types, "USER_CMD")) return "UserCommandObserved";
            if (HasType(types, "ADD_USER")) return "AccountCreated";
            if (HasType(types, "DEL_USER")) return "AccountDeleted";
            if (HasType(types, "ADD_GROUP")) return "GroupCreated";
            if (HasType(types, "DEL_GROUP")) return "GroupDeleted";
            if (HasType(types, "USER_MGMT")) return "AccountManagementObserved";
            if (HasType(types, "SERVICE_START")) return "ServiceStarted";
            if (HasType(types, "SERVICE_STOP")) return "ServiceStopped";
            if (HasType(types, "CONFIG_CHANGE")) return "AuditConfigurationChanged";
            if (types.Any(x => x.StartsWith("ANOM_", StringComparison.OrdinalIgnoreCase)))
                return "AuditAnomalyObserved";
            if (HasType(types, "EXECVE") || HasType(types, "PROCTITLE"))
                return "ProcessExecutionObserved";
            return "AuditEventObserved";
        }

        private static bool HasType(HashSet<string> types, string type)
        {
            return types != null && types.Contains(type);
        }

        private static string GetFirst(Dictionary<string, string> values,
            params string[] names)
        {
            if (values == null || names == null)
                return "";
            for (int i = 0; i < names.Length; i++)
            {
                string value;
                if (values.TryGetValue(names[i], out value) &&
                    !string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }
            return "";
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

        private sealed class AuditEventBuilder
        {
            private readonly string _eventId;
            private readonly string _epoch;
            private readonly string _sourcePath;
            private readonly HashSet<string> _types =
                new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            private readonly Dictionary<string, string> _values =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            private readonly SortedDictionary<int, string> _arguments =
                new SortedDictionary<int, string>();
            private readonly List<string> _paths = new List<string>();
            private int _firstLine;
            private int _lastLine;
            private int _recordCount;
            private string _node = "";
            private string _avcDecision = "";
            private string _avcPermissions = "";
            private string _groupingBoundary = "";

            public AuditEventBuilder(string eventId, string epoch,
                string sourcePath, int lineNumber)
            {
                _eventId = eventId ?? "";
                _epoch = epoch ?? "";
                _sourcePath = sourcePath ?? "";
                _firstLine = lineNumber;
                _lastLine = lineNumber;
            }

            public void AddRecord(string recordType, string node,
                string body, int lineNumber)
            {
                string type = (recordType ?? "").Trim().ToUpperInvariant();
                if (type.Length > 0)
                    _types.Add(type);
                if (_node.Length == 0 && !string.IsNullOrWhiteSpace(node))
                    _node = node.Trim();
                _lastLine = lineNumber;
                _recordCount++;

                Dictionary<string, string> fields = ParseFields(body);
                foreach (KeyValuePair<string, string> pair in fields)
                {
                    if (!_values.ContainsKey(pair.Key) &&
                        !string.IsNullOrWhiteSpace(pair.Value))
                        _values[pair.Key] = pair.Value.Trim();
                }

                if (type == "EXECVE")
                {
                    foreach (KeyValuePair<string, string> pair in fields)
                    {
                        Match argument = ArgumentNameRegex.Match(pair.Key);
                        int index;
                        if (argument.Success &&
                            int.TryParse(argument.Groups["index"].Value,
                                NumberStyles.None, CultureInfo.InvariantCulture, out index) &&
                            index >= 0 && index < MaxArguments)
                            _arguments[index] = DecodeAuditString(pair.Value, true);
                    }
                }

                if (type == "PATH" && _paths.Count < MaxPaths)
                {
                    string path = GetFirst(fields, "name", "path");
                    path = DecodeAuditString(path, true);
                    if (!string.IsNullOrWhiteSpace(path) &&
                        !_paths.Contains(path, StringComparer.Ordinal))
                        _paths.Add(path);
                }

                if (type == "AVC")
                {
                    Match avc = AvcRegex.Match(body ?? "");
                    if (avc.Success)
                    {
                        _avcDecision = avc.Groups["decision"].Value.Trim().ToLowerInvariant();
                        _avcPermissions = Regex.Replace(
                            avc.Groups["permissions"].Value.Trim(), @"\s+", " ");
                    }
                    string avcPath = GetFirst(fields, "path", "name");
                    avcPath = DecodeAuditString(avcPath, true);
                    if (!string.IsNullOrWhiteSpace(avcPath) &&
                        _paths.Count < MaxPaths &&
                        !_paths.Contains(avcPath, StringComparer.Ordinal))
                        _paths.Add(avcPath);
                }
            }

            public void MarkGroupingBoundary(string boundary)
            {
                if (string.Equals(boundary, "eoe", StringComparison.Ordinal))
                    _groupingBoundary = boundary;
                else if (_groupingBoundary.Length == 0)
                    _groupingBoundary = boundary ?? "";
            }

            public AuditEventRow ToRow()
            {
                var row = new AuditEventRow();
                TryFormatEpochUtc(_epoch, out row.TimeUtc);
                row.AuditEventId = _eventId;
                row.RecordTypes = string.Join("|",
                    _types.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
                row.Success = NormalizeSuccess(_values);
                row.Action = DetermineAction(_types, row.Success);
                row.Syscall = GetFirst(_values, "syscall");
                row.Executable = DecodeAuditString(GetFirst(_values, "exe"), true);
                row.WorkingDirectory = DecodeAuditString(GetFirst(_values, "cwd"), true);
                row.User = GetFirst(_values, "acct", "user");
                row.AuditUserId = GetFirst(_values, "auid", "loginuid");
                row.RealUserId = GetFirst(_values, "uid");
                row.EffectiveUserId = GetFirst(_values, "euid");
                row.SessionId = GetFirst(_values, "ses");
                row.ProcessId = GetFirst(_values, "pid");
                row.ParentProcessId = GetFirst(_values, "ppid");
                row.Terminal = GetFirst(_values, "terminal", "tty");
                row.RemoteAddress = GetFirst(_values, "addr");
                row.RemoteHost = GetFirst(_values, "hostname", "host");
                row.TargetPaths = EncodePathList(_paths);
                row.SelinuxDecision = _avcDecision;
                row.SourcePath = _sourcePath;
                row.LineNumbers = _firstLine == _lastLine
                    ? _firstLine.ToString(CultureInfo.InvariantCulture)
                    : _firstLine.ToString(CultureInfo.InvariantCulture) + "-" +
                        _lastLine.ToString(CultureInfo.InvariantCulture);
                row.CommandLine = BuildCommandLine();
                row.Details = BuildDetails();
                return row;
            }

            private string BuildCommandLine()
            {
                if (_arguments.Count > 0)
                    return string.Join(" ", _arguments.Values.Select(QuoteArgument).ToArray());

                string proctitle = GetFirst(_values, "proctitle");
                if (!string.IsNullOrWhiteSpace(proctitle))
                {
                    string decoded = DecodeAuditString(proctitle, true)
                        .Replace('\0', ' ').Trim();
                    if (decoded.Length > 0)
                        return Regex.Replace(decoded, @"\s+", " ");
                }

                string command = GetFirst(_values, "cmd");
                if (!string.IsNullOrWhiteSpace(command))
                    return DecodeAuditString(command, true).Replace('\0', ' ').Trim();
                return "";
            }

            private string BuildDetails()
            {
                var parts = new List<string>();
                parts.Add("record_count=" + _recordCount.ToString(CultureInfo.InvariantCulture));
                AddDetail(parts, "grouping_boundary", _groupingBoundary);
                AddDetail(parts, "node", _node);
                AddDetail(parts, "comm", DecodeAuditString(GetFirst(_values, "comm"), true));
                AddDetail(parts, "audit_key", DecodeAuditString(GetFirst(_values, "key"), true));
                AddDetail(parts, "operation", DecodeAuditString(GetFirst(_values, "op"), true));
                AddDetail(parts, "avc_permissions", _avcPermissions);
                AddDetail(parts, "scontext", GetFirst(_values, "scontext", "subj"));
                AddDetail(parts, "tcontext", GetFirst(_values, "tcontext", "obj"));
                AddDetail(parts, "tclass", GetFirst(_values, "tclass"));
                return string.Join("; ", parts.ToArray());
            }

            private static void AddDetail(List<string> parts, string name, string value)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    parts.Add(name + "=" + value.Trim());
            }
        }

        private sealed class AuditEventRow
        {
            public string TimeUtc = "";
            public string AuditEventId = "";
            public string RecordTypes = "";
            public string Action = "";
            public string Success = "";
            public string Syscall = "";
            public string Executable = "";
            public string CommandLine = "";
            public string WorkingDirectory = "";
            public string User = "";
            public string AuditUserId = "";
            public string RealUserId = "";
            public string EffectiveUserId = "";
            public string SessionId = "";
            public string ProcessId = "";
            public string ParentProcessId = "";
            public string Terminal = "";
            public string RemoteAddress = "";
            public string RemoteHost = "";
            public string TargetPaths = "";
            public string SelinuxDecision = "";
            public string SourcePath = "";
            public string LineNumbers = "";
            public string Details = "";
        }
    }
}
