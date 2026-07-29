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
    /// Bounded Apache/nginx Common/Combined access-log and default error-log
    /// intake. Custom formats remain raw evidence unless they match one of the
    /// explicitly supported envelopes.
    /// </summary>
    public static class UacWebServerLogDeriver
    {
        private const long MaxSourceFileBytes = 1024L * 1024 * 1024;
        private const long MaxExpandedCharactersPerFile = 256L * 1024 * 1024;
        private const int MaxLineCharacters = 1024 * 1024;
        private const int MaxRows = 50000;
        private const int MaxRequestTargetCharacters = 4096;
        private const int MaxHeaderCharacters = 4096;
        private const int MaxMessageCharacters = 8192;
        private const int MaxDetailsCharacters = 4096;

        private static readonly Regex AccessRegex = new Regex(
            @"^(?<remote>\S+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<stamp>[^\]]{1,128})\]\s+""(?<request>(?:\\.|[^""])*)""\s+(?<status>\d{3}|-)\s+(?<bytes>\d+|-)(?:\s+""(?<referrer>(?:\\.|[^""])*)""\s+""(?<agent>(?:\\.|[^""])*)"")?(?:\s+(?<extra>.*))?$",
            RegexOptions.CultureInvariant);
        private static readonly Regex VhostAccessRegex = new Regex(
            @"^(?<vhost>\S+)\s+(?<remote>\S+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<stamp>[^\]]{1,128})\]\s+""(?<request>(?:\\.|[^""])*)""\s+(?<status>\d{3}|-)\s+(?<bytes>\d+|-)(?:\s+""(?<referrer>(?:\\.|[^""])*)""\s+""(?<agent>(?:\\.|[^""])*)"")?(?:\s+(?<extra>.*))?$",
            RegexOptions.CultureInvariant);
        private static readonly Regex NginxErrorRegex = new Regex(
            @"^(?<stamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<severity>[^\]]+)\]\s+(?<pid>\d+)#\d+:\s*(?:\*\d+\s+)?(?<message>.*)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex ApacheErrorRegex = new Regex(
            @"^\[(?<stamp>[^\]]+)\]\s+\[(?<module>[^\]]+)\](?:\s+\[pid\s+(?<pid>\d+)(?::tid\s+[^\]]+)?\])?(?:\s+\[client\s+(?<client>[^\]]+)\])?\s*(?<message>.*)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex NginxClientRegex = new Regex(
            @"(?:^|,\s*)client:\s*(?<value>[^,\s]+)",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex NginxServerRegex = new Regex(
            @"(?:^|,\s*)server:\s*(?<value>[^,]*)",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex NginxRequestRegex = new Regex(
            @"(?:^|,\s*)request:\s*""(?<value>(?:\\.|[^""])*)""",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex NginxHostRegex = new Regex(
            @"(?:^|,\s*)host:\s*""(?<value>(?:\\.|[^""])*)""",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

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

            string output = Path.Combine(outputRoot, ArtifactNames.UacWebServerEventsCsv);
            if (File.Exists(output))
                return;

            List<string> files = EnumerateWebLogFiles(sourceRoot).ToList();
            if (files.Count == 0)
                return;

            var rows = new List<WebEventRow>();
            bool hitCap = false;
            for (int i = 0; i < files.Count && !hitCap; i++)
            {
                try
                {
                    bool expandedCap;
                    int oversizedLines;
                    hitCap = ParseFile(sourceRoot, files[i], rows, out expandedCap,
                        out oversizedLines);
                    if (expandedCap)
                    {
                        Warn(warnings, "web-log expanded-text limit was reached: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    }
                    if (oversizedLines > 0)
                    {
                        Warn(warnings, "web-log source contained " +
                            oversizedLines.ToString(CultureInfo.InvariantCulture) +
                            " oversized line(s) that remained raw: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    }
                }
                catch (Exception ex)
                {
                    Warn(warnings, "web-log source could not be parsed: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + " (" +
                        (ex.Message ?? "") + ")");
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Time,TimeUtc,TimeParseStatus,ServerType,EventType,RemoteAddress,RemotePort,User,VirtualHost,Method,RequestTarget,Protocol,StatusCode,ResponseBytes,Referrer,UserAgent,Severity,ProcessId,Message,SourcePath,LineNumber,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    WebEventRow row = rows[i];
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.Time),
                        CsvUtils.EscapeField(row.TimeUtc),
                        CsvUtils.EscapeField(row.TimeParseStatus),
                        CsvUtils.EscapeField(row.ServerType),
                        CsvUtils.EscapeField(row.EventType),
                        CsvUtils.EscapeField(row.RemoteAddress),
                        CsvUtils.EscapeField(row.RemotePort),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.VirtualHost),
                        CsvUtils.EscapeField(row.Method),
                        CsvUtils.EscapeField(row.RequestTarget),
                        CsvUtils.EscapeField(row.Protocol),
                        CsvUtils.EscapeField(row.StatusCode),
                        CsvUtils.EscapeField(row.ResponseBytes),
                        CsvUtils.EscapeField(row.Referrer),
                        CsvUtils.EscapeField(row.UserAgent),
                        CsvUtils.EscapeField(row.Severity),
                        CsvUtils.EscapeField(row.ProcessId),
                        CsvUtils.EscapeField(row.Message),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (hitCap)
            {
                Warn(warnings, "web-server events were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) + " rows.");
            }
            Logger.Info("Derived " + ArtifactNames.UacWebServerEventsCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            bool underVarLog =
                path.IndexOf("/root/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/[root]/var/log/", StringComparison.Ordinal) >= 0;
            if (!underVarLog)
                return false;

            string name = Path.GetFileName(path) ?? "";
            if (name.EndsWith(".gz", StringComparison.Ordinal))
                name = name.Substring(0, name.Length - 3);
            return IsAccessLogName(name) || IsErrorLogName(name);
        }

        private static bool IsAccessLogName(string name)
        {
            string value = (name ?? "").ToLowerInvariant();
            return value.IndexOf("access.log", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("access_log", StringComparison.Ordinal) >= 0;
        }

        private static bool IsErrorLogName(string name)
        {
            string value = (name ?? "").ToLowerInvariant();
            return value.IndexOf("error.log", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("error_log", StringComparison.Ordinal) >= 0;
        }

        private static IEnumerable<string> EnumerateWebLogFiles(string folder)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories); }
            catch { yield break; }

            foreach (string file in files.OrderBy(f => f,
                StringComparer.OrdinalIgnoreCase))
            {
                if (!IsSupportedSourceRelativePath(
                    ToRelativeSourcePath(folder, file)))
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
            List<WebEventRow> rows, out bool expandedCap, out int oversizedLines)
        {
            expandedCap = false;
            oversizedLines = 0;
            string source = ToRelativeSourcePath(root, file);
            string inferredServer = InferServerType(source);
            bool accessSource = IsAccessLogName(Path.GetFileName(
                file.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ?
                file.Substring(0, file.Length - 3) : file));

            using (var reader = OpenText(file))
            using (var bounded = new BoundedLineReader(reader,
                MaxLineCharacters, MaxExpandedCharactersPerFile))
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

                    WebEventRow row;
                    bool parsed = accessSource ?
                        TryParseAccessLine(line, inferredServer, out row) :
                        TryParseErrorLine(line, inferredServer, out row);
                    if (!parsed || row == null)
                        continue;

                    row.SourcePath = source;
                    row.LineNumber = lineNumber;
                    BoundCanonicalFields(row);
                    rows.Add(row);
                    if (rows.Count >= MaxRows)
                        return true;
                }
                expandedCap = bounded.TotalLimitReached;
            }
            return false;
        }

        private static bool TryParseAccessLine(string line, string inferredServer,
            out WebEventRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            Match match = AccessRegex.Match(line);
            string format = "common";
            if (!match.Success)
            {
                match = VhostAccessRegex.Match(line);
                format = "vhost-common";
            }
            if (!match.Success)
                return false;

            row = new WebEventRow();
            row.ServerType = inferredServer;
            row.EventType = "Access";
            row.Time = match.Groups["stamp"].Value.Trim();
            ApplyAccessTimestamp(row);
            SplitEndpoint(CleanNil(match.Groups["remote"].Value),
                out row.RemoteAddress, out row.RemotePort);
            row.User = CleanNil(match.Groups["user"].Value);
            row.VirtualHost = CleanNil(match.Groups["vhost"].Value);
            row.StatusCode = CleanNil(match.Groups["status"].Value);
            row.ResponseBytes = CleanNil(match.Groups["bytes"].Value);
            row.Referrer = CleanNil(match.Groups["referrer"].Value);
            row.UserAgent = CleanNil(match.Groups["agent"].Value);
            ApplyRequest(row, CleanNil(match.Groups["request"].Value));

            if (match.Groups["agent"].Success)
                format = format.Replace("common", "combined");
            row.Details = "format=" + format;
            string ident = CleanNil(match.Groups["ident"].Value);
            if (!string.IsNullOrWhiteSpace(ident))
                row.Details += "; ident=" + ident;
            string extra = match.Groups["extra"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(extra))
                row.Details += "; extra=" + extra;
            return true;
        }

        private static bool TryParseErrorLine(string line, string inferredServer,
            out WebEventRow row)
        {
            row = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            Match nginx = NginxErrorRegex.Match(line);
            if (nginx.Success)
            {
                row = new WebEventRow();
                row.ServerType = "nginx";
                row.EventType = "Error";
                row.Time = nginx.Groups["stamp"].Value.Trim();
                row.TimeParseStatus = "local-time-no-offset";
                row.Severity = nginx.Groups["severity"].Value.Trim();
                row.ProcessId = nginx.Groups["pid"].Value.Trim();
                row.Message = nginx.Groups["message"].Value;
                ApplyNginxErrorFields(row);
                return true;
            }

            Match apache = ApacheErrorRegex.Match(line);
            if (!apache.Success)
                return false;

            row = new WebEventRow();
            row.ServerType = string.Equals(inferredServer, "nginx",
                StringComparison.OrdinalIgnoreCase) ? "web" : "apache";
            row.EventType = "Error";
            row.Time = apache.Groups["stamp"].Value.Trim();
            ApplyOffsetTimestampOnly(row);
            row.ProcessId = apache.Groups["pid"].Value.Trim();
            row.Message = apache.Groups["message"].Value;

            string module = apache.Groups["module"].Value.Trim();
            int colon = module.LastIndexOf(':');
            row.Severity = colon >= 0 && colon < module.Length - 1 ?
                module.Substring(colon + 1) : module;
            if (!string.IsNullOrWhiteSpace(module))
                row.Details = "module=" + module;

            string client = CleanNil(apache.Groups["client"].Value);
            if (!string.IsNullOrWhiteSpace(client))
            {
                SplitEndpoint(client, out row.RemoteAddress,
                    out row.RemotePort);
            }
            return true;
        }

        private static void ApplyNginxErrorFields(WebEventRow row)
        {
            string message = row != null ? (row.Message ?? "") : "";
            Match client = NginxClientRegex.Match(message);
            if (client.Success)
            {
                SplitEndpoint(client.Groups["value"].Value.Trim(),
                    out row.RemoteAddress, out row.RemotePort);
            }

            Match request = NginxRequestRegex.Match(message);
            if (request.Success)
                ApplyRequest(row, request.Groups["value"].Value);

            Match host = NginxHostRegex.Match(message);
            Match server = NginxServerRegex.Match(message);
            if (host.Success)
                row.VirtualHost = host.Groups["value"].Value.Trim();
            else if (server.Success)
                row.VirtualHost = server.Groups["value"].Value.Trim();
        }

        private static void ApplyRequest(WebEventRow row, string request)
        {
            if (row == null || string.IsNullOrWhiteSpace(request) ||
                string.Equals(request, "-", StringComparison.Ordinal))
                return;

            string value = request.Trim();
            int first = value.IndexOf(' ');
            int last = value.LastIndexOf(' ');
            if (first <= 0)
            {
                row.RequestTarget = value;
                return;
            }

            row.Method = value.Substring(0, first).Trim();
            if (last > first)
            {
                row.RequestTarget = value.Substring(first + 1,
                    last - first - 1).Trim();
                string protocol = value.Substring(last + 1).Trim();
                if (protocol.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                    row.Protocol = protocol;
                else
                {
                    row.RequestTarget = value.Substring(first + 1).Trim();
                }
            }
            else
            {
                row.RequestTarget = value.Substring(first + 1).Trim();
            }
        }

        private static void ApplyAccessTimestamp(WebEventRow row)
        {
            DateTimeOffset parsed;
            if (DateTimeOffset.TryParseExact(row.Time,
                "dd/MMM/yyyy:HH:mm:ss zzz", CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out parsed))
            {
                row.TimeUtc = parsed.UtcDateTime.ToString("o",
                    CultureInfo.InvariantCulture);
                row.TimeParseStatus = "offset-parsed";
            }
            else
            {
                ApplyOffsetTimestampOnly(row);
            }
        }

        private static void ApplyOffsetTimestampOnly(WebEventRow row)
        {
            if (row == null || string.IsNullOrWhiteSpace(row.Time))
                return;
            string value = row.Time.Trim().Replace(',', '.');
            value = Regex.Replace(value, @"([+-]\d{2})(\d{2})$", "$1:$2");
            bool hasOffset = value.EndsWith("Z",
                StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(value, @"[+-]\d{2}:\d{2}$",
                    RegexOptions.CultureInvariant);
            if (!hasOffset)
            {
                row.TimeParseStatus = "local-time-no-offset";
                return;
            }

            DateTimeOffset parsed;
            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out parsed))
            {
                row.TimeUtc = parsed.UtcDateTime.ToString("o",
                    CultureInfo.InvariantCulture);
                row.TimeParseStatus = "offset-parsed";
            }
            else
            {
                row.TimeParseStatus = "timestamp-unparsed";
            }
        }

        private static void SplitEndpoint(string value, out string address,
            out string port)
        {
            address = (value ?? "").Trim();
            port = "";
            if (address.Length == 0)
                return;

            if (address[0] == '[')
            {
                int close = address.IndexOf(']');
                if (close > 1)
                {
                    string candidate = address.Substring(1, close - 1);
                    string suffix = close + 1 < address.Length ?
                        address.Substring(close + 1) : "";
                    if (suffix.StartsWith(":", StringComparison.Ordinal) &&
                        IsPort(suffix.Substring(1)))
                    {
                        address = candidate;
                        port = suffix.Substring(1);
                        return;
                    }
                    if (suffix.Length == 0)
                    {
                        address = candidate;
                        return;
                    }
                }
            }

            IPAddress parsed;
            if (IPAddress.TryParse(address, out parsed))
                return;

            int colon = address.LastIndexOf(':');
            if (colon > 0 && colon < address.Length - 1)
            {
                string candidateAddress = address.Substring(0, colon);
                string candidatePort = address.Substring(colon + 1);
                if (IsPort(candidatePort) &&
                    (IPAddress.TryParse(candidateAddress, out parsed) ||
                    candidateAddress.IndexOf(':') < 0))
                {
                    address = candidateAddress;
                    port = candidatePort;
                }
            }
        }

        private static bool IsPort(string value)
        {
            int port;
            return int.TryParse(value, NumberStyles.None,
                CultureInfo.InvariantCulture, out port) &&
                port >= 0 && port <= 65535;
        }

        private static string InferServerType(string sourcePath)
        {
            string path = "/" + (sourcePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            if (path.IndexOf("/nginx/", StringComparison.Ordinal) >= 0)
                return "nginx";
            if (path.IndexOf("/apache/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/apache2/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/httpd/", StringComparison.Ordinal) >= 0)
                return "apache";
            return "web";
        }

        private static void BoundCanonicalFields(WebEventRow row)
        {
            if (row == null)
                return;

            bool truncated = false;
            row.Time = LimitText(row.Time, 256, ref truncated);
            row.ServerType = LimitText(row.ServerType, 64, ref truncated);
            row.EventType = LimitText(row.EventType, 32, ref truncated);
            row.RemoteAddress = LimitText(row.RemoteAddress, 1024, ref truncated);
            row.RemotePort = LimitText(row.RemotePort, 16, ref truncated);
            row.User = LimitText(row.User, 1024, ref truncated);
            row.VirtualHost = LimitText(row.VirtualHost, 2048, ref truncated);
            row.Method = LimitText(row.Method, 64, ref truncated);
            row.RequestTarget = LimitText(row.RequestTarget,
                MaxRequestTargetCharacters, ref truncated);
            row.Protocol = LimitText(row.Protocol, 64, ref truncated);
            row.StatusCode = LimitText(row.StatusCode, 16, ref truncated);
            row.ResponseBytes = LimitText(row.ResponseBytes, 32, ref truncated);
            row.Referrer = LimitText(row.Referrer, MaxHeaderCharacters,
                ref truncated);
            row.UserAgent = LimitText(row.UserAgent, MaxHeaderCharacters,
                ref truncated);
            row.Severity = LimitText(row.Severity, 128, ref truncated);
            row.ProcessId = LimitText(row.ProcessId, 32, ref truncated);
            row.Message = LimitText(row.Message, MaxMessageCharacters,
                ref truncated);
            row.Details = LimitText(row.Details, MaxDetailsCharacters,
                ref truncated);
            if (truncated)
                row.Details = AppendBoundedMarker(row.Details,
                    "canonical_field_truncated=true", MaxDetailsCharacters);
        }

        private static string LimitText(string value, int limit,
            ref bool truncated)
        {
            string text = value ?? "";
            if (text.Length <= limit)
                return text;
            truncated = true;
            return text.Substring(0, limit);
        }

        private static string AppendBoundedMarker(string value, string marker,
            int limit)
        {
            string text = value ?? "";
            string suffix = string.IsNullOrWhiteSpace(text) ? marker :
                "; " + marker;
            if (text.Length + suffix.Length <= limit)
                return text + suffix;
            int keep = Math.Max(0, limit - suffix.Length);
            return text.Substring(0, Math.Min(text.Length, keep)) + suffix;
        }

        private static string CleanNil(string value)
        {
            string text = (value ?? "").Trim();
            return string.Equals(text, "-", StringComparison.Ordinal) ? "" : text;
        }

        private static StreamReader OpenText(string file)
        {
            FileStream input = new FileStream(file, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (file.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return new StreamReader(new GZipStream(input,
                        CompressionMode.Decompress), Encoding.UTF8, true);
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
                string rootFull = Path.GetFullPath(root).TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;
                string fileFull = Path.GetFullPath(file);
                if (fileFull.StartsWith(rootFull,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return fileFull.Substring(rootFull.Length).Replace('\\', '/');
                }
            }
            catch
            {
            }
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

        private sealed class WebEventRow
        {
            public string Time = "";
            public string TimeUtc = "";
            public string TimeParseStatus = "";
            public string ServerType = "";
            public string EventType = "";
            public string RemoteAddress = "";
            public string RemotePort = "";
            public string User = "";
            public string VirtualHost = "";
            public string Method = "";
            public string RequestTarget = "";
            public string Protocol = "";
            public string StatusCode = "";
            public string ResponseBytes = "";
            public string Referrer = "";
            public string UserAgent = "";
            public string Severity = "";
            public string ProcessId = "";
            public string Message = "";
            public string SourcePath = "";
            public int LineNumber;
            public string Details = "";
        }
    }
}
