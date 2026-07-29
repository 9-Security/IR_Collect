using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Derives facts-only persistence configuration rows from UAC-collected Unix files.
    /// A row records configuration presence; it is not an execution or maliciousness verdict.
    /// </summary>
    public static class UacPersistenceDeriver
    {
        private const long MaxInspectableFileBytes = 20L * 1024 * 1024;
        private const int MaxRows = 100000;
        private const int MaxFieldLength = 65536;

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot, List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(sourceRoot) || !Directory.Exists(sourceRoot)) return;
            if (string.IsNullOrWhiteSpace(outputRoot)) return;
            Directory.CreateDirectory(outputRoot);
            string output = Path.Combine(outputRoot, ArtifactNames.UacPersistenceCsv);
            if (File.Exists(output)) return;

            var rows = new List<UacPersistenceRow>();
            foreach (string file in SafeEnumerate(sourceRoot)
                .Where(IsInspectable)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                string relativePath = RelativePath(sourceRoot, file);
                if (!IsSupportedSourceRelativePath(relativePath)) continue;
                try
                {
                    if (IsSystemdPath(relativePath))
                        ParseSystemd(file, relativePath, rows);
                    else if (IsLaunchdPath(relativePath))
                        ParseLaunchd(file, relativePath, rows);
                    else if (IsAuthorizedKeysPath(relativePath))
                        ParseAuthorizedKeys(file, relativePath, rows);
                    else if (IsLdPreloadPath(relativePath))
                        ParseLdPreload(file, relativePath, rows);
                    else if (IsRcLocalPath(relativePath))
                        ParseStartupScript(file, relativePath, rows);
                    else if (IsCronPath(relativePath))
                        ParseCron(file, relativePath, rows);
                }
                catch (Exception ex)
                {
                    Warn(warnings, "persistence source could not be parsed: " + relativePath + ": " + (ex.Message ?? ""));
                }
                if (rows.Count >= MaxRows) break;
            }

            if (rows.Count == 0) return;
            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("ModifiedTimeUtc,Platform,Mechanism,Scope,Name,User,Executable,Arguments,Trigger,EnabledState,KeyFingerprintSha256,SourcePath,LineNumber,Details");
                foreach (UacPersistenceRow row in rows
                    .Take(MaxRows)
                    .OrderBy(x => x.SourcePath, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(x => x.LineNumber)
                    .ThenBy(x => x.Mechanism, StringComparer.OrdinalIgnoreCase))
                {
                    sw.WriteLine(string.Join(",", new string[] {
                        CsvUtils.EscapeField(row.ModifiedTimeUtc),
                        CsvUtils.EscapeField(row.Platform),
                        CsvUtils.EscapeField(row.Mechanism),
                        CsvUtils.EscapeField(row.Scope),
                        CsvUtils.EscapeField(row.Name),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(Limit(row.Executable)),
                        CsvUtils.EscapeField(Limit(row.Arguments)),
                        CsvUtils.EscapeField(Limit(row.Trigger)),
                        CsvUtils.EscapeField(row.EnabledState),
                        CsvUtils.EscapeField(row.KeyFingerprintSha256),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(Limit(row.Details))
                    }));
                }
            });

            if (rows.Count >= MaxRows)
                Warn(warnings, "persistence rows were capped at " + MaxRows.ToString(CultureInfo.InvariantCulture) + ".");
            Logger.Info("Derived " + ArtifactNames.UacPersistenceCsv + " (" +
                Math.Min(rows.Count, MaxRows).ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            return IsSystemdPath(relativePath) ||
                IsLaunchdPath(relativePath) ||
                IsAuthorizedKeysPath(relativePath) ||
                IsCronPath(relativePath) ||
                IsRcLocalPath(relativePath) ||
                IsLdPreloadPath(relativePath);
        }

        private static void ParseSystemd(string file, string source, List<UacPersistenceRow> rows)
        {
            var directives = new List<SystemdDirective>();
            string section = "";
            List<LogicalLine> lines = ReadLogicalLines(file);
            for (int i = 0; i < lines.Count; i++)
            {
                LogicalLine logicalLine = lines[i];
                string line = (logicalLine.Text ?? "").Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal) ||
                    line.StartsWith(";", StringComparison.Ordinal)) continue;
                if (line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal))
                {
                    section = line.Substring(1, line.Length - 2).Trim();
                    continue;
                }
                int equals = line.IndexOf('=');
                if (equals <= 0) continue;
                directives.Add(new SystemdDirective
                {
                    Section = section,
                    Key = line.Substring(0, equals).Trim(),
                    Value = line.Substring(equals + 1).Trim(),
                    LineNumber = logicalLine.LineNumber
                });
            }

            bool isTimer = SourcePathLower(source).IndexOf(".timer", StringComparison.Ordinal) >= 0;
            string name = InferSystemdUnitName(source);
            string scope = IsUserScopedSystemd(source) ? "User" : "System";
            string user = FirstDirective(directives, "Service", "User");
            if (string.IsNullOrEmpty(user) && scope == "User") user = InferUser(source);
            string description = FirstDirective(directives, "Unit", "Description");
            string enabled = "definition-present";
            string modified = FormatModifiedTime(file);

            if (isTimer)
            {
                string trigger = JoinDirectives(directives, "Timer", new string[] {
                    "OnCalendar", "OnActiveSec", "OnBootSec", "OnStartupSec",
                    "OnUnitActiveSec", "OnUnitInactiveSec", "Unit"
                });
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = modified,
                    Platform = "Linux",
                    Mechanism = "systemd-timer",
                    Scope = scope,
                    Name = name,
                    User = user,
                    Trigger = trigger,
                    EnabledState = enabled,
                    SourcePath = source,
                    LineNumber = FirstDirectiveLine(directives, "Timer"),
                    Details = Detail("description", description)
                });
                return;
            }

            List<SystemdDirective> commands = directives
                .Where(x => string.Equals(x.Section, "Service", StringComparison.OrdinalIgnoreCase) &&
                    (string.Equals(x.Key, "ExecStart", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(x.Key, "ExecStartPre", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(x.Key, "ExecStartPost", StringComparison.OrdinalIgnoreCase)))
                .ToList();
            string installTrigger = JoinDirectives(directives, "Install", new string[] { "WantedBy", "RequiredBy", "Alias" });
            string workingDirectory = FirstDirective(directives, "Service", "WorkingDirectory");
            if (commands.Count == 0)
            {
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = modified,
                    Platform = "Linux",
                    Mechanism = "systemd-service",
                    Scope = scope,
                    Name = name,
                    User = user,
                    Trigger = installTrigger,
                    EnabledState = enabled,
                    SourcePath = source,
                    Details = JoinDetails(Detail("description", description), Detail("working_directory", workingDirectory))
                });
                return;
            }

            foreach (SystemdDirective command in commands)
            {
                string executable;
                string arguments;
                SplitSystemdCommand(command.Value, out executable, out arguments);
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = modified,
                    Platform = "Linux",
                    Mechanism = "systemd-service",
                    Scope = scope,
                    Name = name,
                    User = user,
                    Executable = executable,
                    Arguments = arguments,
                    Trigger = installTrigger,
                    EnabledState = enabled,
                    SourcePath = source,
                    LineNumber = command.LineNumber,
                    Details = JoinDetails(
                        Detail("directive", command.Key),
                        Detail("description", description),
                        Detail("working_directory", workingDirectory))
                });
                if (rows.Count >= MaxRows) return;
            }
        }

        private static void ParseLaunchd(string file, string source, List<UacPersistenceRow> rows)
        {
            Dictionary<string, object> values = LoadPlistDictionary(file);
            if (values == null) return;
            string label = PlistString(values, "Label");
            if (string.IsNullOrEmpty(label)) label = Path.GetFileNameWithoutExtension(source) ?? "";
            List<string> programArguments = PlistArray(values, "ProgramArguments");
            string executable = PlistString(values, "Program");
            if (string.IsNullOrEmpty(executable) && programArguments.Count > 0)
                executable = programArguments[0];
            string arguments = programArguments.Count > 1 ? string.Join(" ", programArguments.Skip(1).ToArray()) : "";
            string user = PlistString(values, "UserName");
            if (string.IsNullOrEmpty(user)) user = InferUser(source);
            bool daemon = SourcePathLower(source).IndexOf("/launchdaemons/", StringComparison.Ordinal) >= 0;
            string trigger = BuildLaunchdTrigger(values);
            string disabledText = PlistScalar(values, "Disabled");
            string enabled = string.Equals(disabledText, "true", StringComparison.OrdinalIgnoreCase)
                ? "disabled-in-definition"
                : "definition-present";
            string details = JoinDetails(
                Detail("working_directory", PlistString(values, "WorkingDirectory")),
                Detail("stdout", PlistString(values, "StandardOutPath")),
                Detail("stderr", PlistString(values, "StandardErrorPath")));

            rows.Add(new UacPersistenceRow
            {
                ModifiedTimeUtc = FormatModifiedTime(file),
                Platform = "macOS",
                Mechanism = daemon ? "launchd-daemon" : "launchd-agent",
                Scope = daemon ? "System" : "User",
                Name = label,
                User = user,
                Executable = executable,
                Arguments = arguments,
                Trigger = trigger,
                EnabledState = enabled,
                SourcePath = source,
                Details = details
            });
        }

        private static void ParseAuthorizedKeys(string file, string source, List<UacPersistenceRow> rows)
        {
            string[] lines = ReadLines(file);
            string user = InferUser(source);
            for (int i = 0; i < lines.Length && rows.Count < MaxRows; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                List<AuthorizedKeyToken> tokens = TokenizeAuthorizedKeyLine(line);
                int keyIndex = -1;
                for (int t = 0; t + 1 < tokens.Count; t++)
                {
                    if (LooksLikeSshKeyType(tokens[t].Value))
                    {
                        keyIndex = t;
                        break;
                    }
                }
                if (keyIndex < 0) continue;
                string keyType = tokens[keyIndex].Value;
                string keyMaterial = tokens[keyIndex + 1].Value;
                string comment = tokens[keyIndex + 1].EndIndex < line.Length
                    ? line.Substring(tokens[keyIndex + 1].EndIndex).Trim()
                    : "";
                string options = tokens[keyIndex].StartIndex > 0
                    ? line.Substring(0, tokens[keyIndex].StartIndex).Trim()
                    : "";
                string fingerprint = ComputeSshFingerprint(keyMaterial);
                if (string.IsNullOrEmpty(fingerprint)) continue;
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = FormatModifiedTime(file),
                    Platform = "Unix",
                    Mechanism = "ssh-authorized-key",
                    Scope = "User",
                    Name = keyType,
                    User = user,
                    Trigger = "ssh-public-key-authentication",
                    EnabledState = "configured",
                    KeyFingerprintSha256 = fingerprint,
                    SourcePath = source,
                    LineNumber = i + 1,
                    Details = JoinDetails(Detail("comment", comment), Detail("options", options))
                });
            }
        }

        private static void ParseCron(string file, string source, List<UacPersistenceRow> rows)
        {
            if (IsPeriodicCronScript(source))
            {
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = FormatModifiedTime(file),
                    Platform = "Unix",
                    Mechanism = "cron-periodic-script",
                    Scope = "System",
                    Name = Path.GetFileName(source) ?? "",
                    Executable = ToUnixCollectedPath(source),
                    Trigger = InferPeriodicCronTrigger(source),
                    EnabledState = "definition-present",
                    SourcePath = source
                });
                return;
            }

            bool anacron = SourcePathLower(source).EndsWith("/etc/anacrontab", StringComparison.Ordinal);
            bool systemCron = IsSystemCron(source);
            string inferredUser = systemCron ? "" : InferCronUser(source);
            string[] lines = ReadLines(file);
            for (int i = 0; i < lines.Length && rows.Count < MaxRows; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal) ||
                    LooksLikeEnvironmentAssignment(line)) continue;

                string trigger;
                string user = inferredUser;
                string command;
                if (anacron)
                {
                    List<string> fields = TakeFields(line, 3);
                    if (fields.Count < 4) continue;
                    trigger = "period_days=" + fields[0] + "; delay_minutes=" + fields[1] + "; job=" + fields[2];
                    command = fields[3];
                }
                else if (line.StartsWith("@", StringComparison.Ordinal))
                {
                    List<string> fields = TakeFields(line, systemCron ? 2 : 1);
                    if (fields.Count < (systemCron ? 3 : 2)) continue;
                    trigger = fields[0];
                    if (systemCron) user = fields[1];
                    command = fields[systemCron ? 2 : 1];
                }
                else
                {
                    List<string> fields = TakeFields(line, systemCron ? 6 : 5);
                    if (fields.Count < (systemCron ? 7 : 6)) continue;
                    trigger = string.Join(" ", fields.Take(5).ToArray());
                    if (systemCron) user = fields[5];
                    command = fields[systemCron ? 6 : 5];
                }

                string executable;
                string arguments;
                SplitCommand(command, out executable, out arguments);
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = FormatModifiedTime(file),
                    Platform = "Unix",
                    Mechanism = anacron ? "anacron" : "cron",
                    Scope = systemCron || anacron ? "System" : "User",
                    Name = anacron ? ExtractAnacronName(trigger) : Path.GetFileName(source) ?? "crontab",
                    User = user,
                    Executable = executable,
                    Arguments = arguments,
                    Trigger = trigger,
                    EnabledState = "configured",
                    SourcePath = source,
                    LineNumber = i + 1
                });
            }
        }

        private static void ParseStartupScript(string file, string source, List<UacPersistenceRow> rows)
        {
            string[] lines = ReadLines(file);
            for (int i = 0; i < lines.Length && rows.Count < MaxRows; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal) ||
                    string.Equals(line, "exit 0", StringComparison.Ordinal)) continue;
                string executable;
                string arguments;
                SplitCommand(line, out executable, out arguments);
                rows.Add(new UacPersistenceRow
                {
                    ModifiedTimeUtc = FormatModifiedTime(file),
                    Platform = "Linux",
                    Mechanism = "rc-local",
                    Scope = "System",
                    Name = "rc.local",
                    Executable = executable,
                    Arguments = arguments,
                    Trigger = "system-startup",
                    EnabledState = "definition-present",
                    SourcePath = source,
                    LineNumber = i + 1
                });
            }
        }

        private static void ParseLdPreload(string file, string source, List<UacPersistenceRow> rows)
        {
            string[] lines = ReadLines(file);
            for (int i = 0; i < lines.Length && rows.Count < MaxRows; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                foreach (string path in Regex.Split(line, @"\s+").Where(x => !string.IsNullOrWhiteSpace(x)))
                {
                    rows.Add(new UacPersistenceRow
                    {
                        ModifiedTimeUtc = FormatModifiedTime(file),
                        Platform = "Linux",
                        Mechanism = "ld-so-preload",
                        Scope = "System",
                        Name = "ld.so.preload",
                        Executable = path,
                        Trigger = "dynamic-loader",
                        EnabledState = "configured",
                        SourcePath = source,
                        LineNumber = i + 1,
                        Details = "Configured library path; presence does not establish library provenance or execution."
                    });
                    if (rows.Count >= MaxRows) return;
                }
            }
        }

        private static Dictionary<string, object> LoadPlistDictionary(string file)
        {
            if (BinaryPlistReader.HasSignature(file))
            {
                Dictionary<string, object> binaryValues;
                string error;
                return BinaryPlistReader.TryReadDictionary(file, out binaryValues, out error)
                    ? binaryValues
                    : null;
            }

            XmlDocument document = LoadPlistXml(file);
            if (document == null) return null;
            XmlNode dict = document.SelectSingleNode("/plist/dict");
            return dict == null ? null : ReadXmlPlistDictionary(dict);
        }

        private static XmlDocument LoadPlistXml(string file)
        {
            try
            {
                using (FileStream stream = File.OpenRead(file))
                {
                    var settings = new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Ignore,
                        XmlResolver = null,
                        MaxCharactersInDocument = MaxInspectableFileBytes
                    };
                    using (XmlReader reader = XmlReader.Create(stream, settings))
                    {
                        var document = new XmlDocument();
                        document.XmlResolver = null;
                        document.Load(reader);
                        return document;
                    }
                }
            }
            catch { return null; }
        }

        private static Dictionary<string, object> ReadXmlPlistDictionary(XmlNode dict)
        {
            var values = new Dictionary<string, object>(StringComparer.Ordinal);
            if (dict == null) return values;
            string pendingKey = null;
            foreach (XmlNode child in dict.ChildNodes)
            {
                if (child.NodeType != XmlNodeType.Element) continue;
                if (string.Equals(child.LocalName, "key", StringComparison.Ordinal))
                {
                    pendingKey = child.InnerText ?? "";
                    continue;
                }
                if (!string.IsNullOrEmpty(pendingKey))
                {
                    values[pendingKey] = ReadXmlPlistValue(child);
                    pendingKey = null;
                }
            }
            return values;
        }

        private static object ReadXmlPlistValue(XmlNode node)
        {
            if (node == null) return null;
            if (string.Equals(node.LocalName, "true", StringComparison.Ordinal)) return true;
            if (string.Equals(node.LocalName, "false", StringComparison.Ordinal)) return false;
            if (string.Equals(node.LocalName, "dict", StringComparison.Ordinal))
                return ReadXmlPlistDictionary(node);
            if (string.Equals(node.LocalName, "array", StringComparison.Ordinal))
            {
                var list = new List<object>();
                foreach (XmlNode child in node.ChildNodes)
                {
                    if (child.NodeType == XmlNodeType.Element && list.Count < 100000)
                        list.Add(ReadXmlPlistValue(child));
                }
                return list;
            }
            return node.InnerText ?? "";
        }

        private static string PlistString(Dictionary<string, object> values, string key)
        {
            object value;
            if (values == null || !values.TryGetValue(key, out value) || value == null) return "";
            return FormatPlistValue(value, 0);
        }

        private static string PlistScalar(Dictionary<string, object> values, string key)
        {
            return PlistString(values, key);
        }

        private static List<string> PlistArray(Dictionary<string, object> values, string key)
        {
            var result = new List<string>();
            object value;
            if (values == null || !values.TryGetValue(key, out value) || value == null) return result;
            var list = value as List<object>;
            if (list == null) return result;
            foreach (object item in list)
            {
                if (result.Count >= 100) break;
                result.Add(FormatPlistValue(item, 0));
            }
            return result;
        }

        private static string BuildLaunchdTrigger(Dictionary<string, object> values)
        {
            var triggers = new List<string>();
            AddPlistTrigger(values, triggers, "RunAtLoad");
            AddPlistTrigger(values, triggers, "KeepAlive");
            AddPlistTrigger(values, triggers, "StartInterval");
            AddPlistTrigger(values, triggers, "StartCalendarInterval");
            AddPlistTrigger(values, triggers, "StartOnMount");
            AddPlistTrigger(values, triggers, "WatchPaths");
            AddPlistTrigger(values, triggers, "QueueDirectories");
            return string.Join("; ", triggers.ToArray());
        }

        private static void AddPlistTrigger(Dictionary<string, object> values, List<string> triggers, string key)
        {
            object value;
            if (!values.TryGetValue(key, out value) || value == null) return;
            triggers.Add(key + "=" + Limit(FormatPlistValue(value, 0)));
        }

        private static string FormatPlistValue(object value, int depth)
        {
            if (value == null) return "";
            if (depth > 8) return "(nested)";
            if (value is bool) return (bool)value ? "true" : "false";
            if (value is DateTime)
                return ((DateTime)value).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            byte[] data = value as byte[];
            if (data != null) return "(data:" + data.Length.ToString(CultureInfo.InvariantCulture) + " bytes)";
            var list = value as List<object>;
            if (list != null)
                return string.Join("|", list.Take(20).Select(x => FormatPlistValue(x, depth + 1)).ToArray());
            var dictionary = value as Dictionary<string, object>;
            if (dictionary != null)
                return string.Join(",", dictionary.Take(20)
                    .Select(x => x.Key + ":" + FormatPlistValue(x.Value, depth + 1))
                    .ToArray());
            return Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
        }

        private static string FirstDirective(List<SystemdDirective> directives, string section, string key)
        {
            SystemdDirective item = directives.FirstOrDefault(x =>
                string.Equals(x.Section, section, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.Key, key, StringComparison.OrdinalIgnoreCase));
            return item == null ? "" : item.Value;
        }

        private static int FirstDirectiveLine(List<SystemdDirective> directives, string section)
        {
            SystemdDirective item = directives.FirstOrDefault(x =>
                string.Equals(x.Section, section, StringComparison.OrdinalIgnoreCase));
            return item == null ? 0 : item.LineNumber;
        }

        private static string JoinDirectives(List<SystemdDirective> directives, string section, string[] keys)
        {
            var wanted = new HashSet<string>(keys ?? new string[0], StringComparer.OrdinalIgnoreCase);
            return string.Join("; ", directives
                .Where(x => string.Equals(x.Section, section, StringComparison.OrdinalIgnoreCase) && wanted.Contains(x.Key))
                .Select(x => x.Key + "=" + x.Value)
                .ToArray());
        }

        private static List<LogicalLine> ReadLogicalLines(string file)
        {
            string[] physical = ReadLines(file);
            var logical = new List<LogicalLine>();
            var current = new StringBuilder();
            int startLine = 0;
            for (int i = 0; i < physical.Length; i++)
            {
                string raw = physical[i];
                string line = raw ?? "";
                bool continued = line.TrimEnd().EndsWith("\\", StringComparison.Ordinal);
                string segment = continued ? line.TrimEnd().Substring(0, line.TrimEnd().Length - 1) : line;
                if (current.Length == 0) startLine = i + 1;
                if (current.Length > 0) current.Append(" ");
                current.Append(segment);
                if (!continued)
                {
                    logical.Add(new LogicalLine { Text = current.ToString(), LineNumber = startLine });
                    current.Length = 0;
                }
            }
            if (current.Length > 0)
                logical.Add(new LogicalLine { Text = current.ToString(), LineNumber = startLine });
            return logical;
        }

        private static List<AuthorizedKeyToken> TokenizeAuthorizedKeyLine(string line)
        {
            var tokens = new List<AuthorizedKeyToken>();
            string text = line ?? "";
            int index = 0;
            while (index < text.Length)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
                if (index >= text.Length) break;
                int start = index;
                char quote = '\0';
                bool escaped = false;
                var value = new StringBuilder();
                while (index < text.Length)
                {
                    char c = text[index];
                    if (escaped)
                    {
                        value.Append(c);
                        escaped = false;
                        index++;
                        continue;
                    }
                    if (c == '\\')
                    {
                        escaped = true;
                        value.Append(c);
                        index++;
                        continue;
                    }
                    if (quote != '\0')
                    {
                        value.Append(c);
                        if (c == quote) quote = '\0';
                        index++;
                        continue;
                    }
                    if (c == '"' || c == '\'')
                    {
                        quote = c;
                        value.Append(c);
                        index++;
                        continue;
                    }
                    if (char.IsWhiteSpace(c)) break;
                    value.Append(c);
                    index++;
                }
                tokens.Add(new AuthorizedKeyToken
                {
                    Value = value.ToString(),
                    StartIndex = start,
                    EndIndex = index
                });
            }
            return tokens;
        }

        private static bool LooksLikeSshKeyType(string value)
        {
            string keyType = (value ?? "").ToLowerInvariant();
            return keyType == "ssh-rsa" ||
                keyType == "ssh-dss" ||
                keyType == "ssh-ed25519" ||
                keyType.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) ||
                keyType.StartsWith("sk-ssh-", StringComparison.Ordinal) ||
                keyType.StartsWith("sk-ecdsa-", StringComparison.Ordinal) ||
                keyType.StartsWith("rsa-sha2-", StringComparison.Ordinal) ||
                keyType.EndsWith("-cert-v01@openssh.com", StringComparison.Ordinal);
        }

        private static void SplitSystemdCommand(string value, out string executable, out string arguments)
        {
            string command = (value ?? "").TrimStart();
            while (command.Length > 0 && "-@:+!".IndexOf(command[0]) >= 0)
                command = command.Substring(1).TrimStart();
            SplitCommand(command, out executable, out arguments);
        }

        private static void SplitCommand(string value, out string executable, out string arguments)
        {
            executable = "";
            arguments = "";
            string text = (value ?? "").Trim();
            if (text.Length == 0) return;
            int index = 0;
            char quote = '\0';
            if (text[0] == '"' || text[0] == '\'')
            {
                quote = text[0];
                index = 1;
                int end = text.IndexOf(quote, index);
                if (end < 0)
                {
                    executable = text.Substring(index);
                    return;
                }
                executable = text.Substring(index, end - index);
                arguments = text.Substring(end + 1).Trim();
                return;
            }
            while (index < text.Length && !char.IsWhiteSpace(text[index])) index++;
            executable = text.Substring(0, index);
            arguments = index < text.Length ? text.Substring(index).Trim() : "";
        }

        private static List<string> TakeFields(string line, int fixedFieldCount)
        {
            var result = new List<string>();
            string text = line ?? "";
            int index = 0;
            for (int i = 0; i < fixedFieldCount; i++)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
                if (index >= text.Length) return result;
                int start = index;
                while (index < text.Length && !char.IsWhiteSpace(text[index])) index++;
                result.Add(text.Substring(start, index - start));
            }
            while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
            if (index < text.Length) result.Add(text.Substring(index));
            return result;
        }

        private static bool LooksLikeEnvironmentAssignment(string line)
        {
            int equals = (line ?? "").IndexOf('=');
            if (equals <= 0) return false;
            string key = line.Substring(0, equals).Trim();
            return Regex.IsMatch(key, @"^[A-Za-z_][A-Za-z0-9_]*$");
        }

        private static string ComputeSshFingerprint(string keyMaterial)
        {
            try
            {
                byte[] key = Convert.FromBase64String(keyMaterial ?? "");
                using (SHA256 sha = SHA256.Create())
                    return "SHA256:" + Convert.ToBase64String(sha.ComputeHash(key)).TrimEnd('=');
            }
            catch { return ""; }
        }

        private static bool IsSystemdPath(string path)
        {
            string value = SourcePathLower(path);
            if (value.IndexOf("/systemd/", StringComparison.Ordinal) < 0) return false;
            return value.EndsWith(".service", StringComparison.Ordinal) ||
                value.EndsWith(".timer", StringComparison.Ordinal) ||
                value.IndexOf(".service.d/", StringComparison.Ordinal) >= 0 && value.EndsWith(".conf", StringComparison.Ordinal) ||
                value.IndexOf(".timer.d/", StringComparison.Ordinal) >= 0 && value.EndsWith(".conf", StringComparison.Ordinal);
        }

        private static bool IsLaunchdPath(string path)
        {
            string value = SourcePathLower(path);
            return value.EndsWith(".plist", StringComparison.Ordinal) &&
                (value.IndexOf("/launchagents/", StringComparison.Ordinal) >= 0 ||
                 value.IndexOf("/launchdaemons/", StringComparison.Ordinal) >= 0);
        }

        private static bool IsAuthorizedKeysPath(string path)
        {
            string value = SourcePathLower(path);
            return value.EndsWith("/authorized_keys", StringComparison.Ordinal) ||
                value.EndsWith("/authorized_keys2", StringComparison.Ordinal);
        }

        private static bool IsCronPath(string path)
        {
            string value = SourcePathLower(path);
            return value.EndsWith("/etc/crontab", StringComparison.Ordinal) ||
                value.EndsWith("/etc/anacrontab", StringComparison.Ordinal) ||
                value.IndexOf("/etc/cron.d/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.hourly/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.daily/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.weekly/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.monthly/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/var/spool/cron/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/var/at/tabs/", StringComparison.Ordinal) >= 0;
        }

        private static bool IsRcLocalPath(string path)
        {
            return SourcePathLower(path).EndsWith("/etc/rc.local", StringComparison.Ordinal);
        }

        private static bool IsLdPreloadPath(string path)
        {
            return SourcePathLower(path).EndsWith("/etc/ld.so.preload", StringComparison.Ordinal);
        }

        private static bool IsPeriodicCronScript(string path)
        {
            string value = SourcePathLower(path);
            return value.IndexOf("/etc/cron.hourly/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.daily/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.weekly/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/etc/cron.monthly/", StringComparison.Ordinal) >= 0;
        }

        private static string InferPeriodicCronTrigger(string path)
        {
            string value = SourcePathLower(path);
            if (value.IndexOf("/cron.hourly/", StringComparison.Ordinal) >= 0) return "hourly";
            if (value.IndexOf("/cron.daily/", StringComparison.Ordinal) >= 0) return "daily";
            if (value.IndexOf("/cron.weekly/", StringComparison.Ordinal) >= 0) return "weekly";
            if (value.IndexOf("/cron.monthly/", StringComparison.Ordinal) >= 0) return "monthly";
            return "periodic";
        }

        private static bool IsSystemCron(string path)
        {
            string value = SourcePathLower(path);
            return value.EndsWith("/etc/crontab", StringComparison.Ordinal) ||
                value.IndexOf("/etc/cron.d/", StringComparison.Ordinal) >= 0;
        }

        private static string InferCronUser(string path)
        {
            string name = Path.GetFileName((path ?? "").Replace('/', Path.DirectorySeparatorChar)) ?? "";
            if (string.Equals(name, "root", StringComparison.OrdinalIgnoreCase)) return "root";
            return name;
        }

        private static string InferUser(string path)
        {
            string value = "/" + SourcePathLower(path).Trim('/') + "/";
            string user = SegmentAfter(value, "/home/");
            if (user.Length == 0) user = SegmentAfter(value, "/users/");
            if (user.Length == 0 && (value.IndexOf("/[root]/root/", StringComparison.Ordinal) >= 0 ||
                                    value.IndexOf("/root/root/", StringComparison.Ordinal) >= 0 ||
                                    value.IndexOf("/var/root/", StringComparison.Ordinal) >= 0))
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

        private static bool IsUserScopedSystemd(string path)
        {
            string value = SourcePathLower(path);
            return value.IndexOf("/systemd/user/", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("/.config/systemd/", StringComparison.Ordinal) >= 0;
        }

        private static string InferSystemdUnitName(string path)
        {
            string value = (path ?? "").Replace('\\', '/');
            int dropIn = value.IndexOf(".service.d/", StringComparison.OrdinalIgnoreCase);
            if (dropIn < 0) dropIn = value.IndexOf(".timer.d/", StringComparison.OrdinalIgnoreCase);
            if (dropIn >= 0)
            {
                int start = value.LastIndexOf('/', dropIn);
                return value.Substring(start + 1, dropIn - start - 1) +
                    (value.IndexOf(".timer.d/", StringComparison.OrdinalIgnoreCase) >= 0 ? ".timer" : ".service");
            }
            return Path.GetFileName(value.Replace('/', Path.DirectorySeparatorChar)) ?? "";
        }

        private static string ExtractAnacronName(string trigger)
        {
            const string marker = "job=";
            int index = (trigger ?? "").IndexOf(marker, StringComparison.Ordinal);
            return index < 0 ? "anacrontab" : trigger.Substring(index + marker.Length);
        }

        private static string ToUnixCollectedPath(string source)
        {
            string value = (source ?? "").Replace('\\', '/');
            int index = value.IndexOf("[root]/", StringComparison.OrdinalIgnoreCase);
            if (index >= 0) return "/" + value.Substring(index + 7);
            return value;
        }

        private static bool IsInspectable(string path)
        {
            try
            {
                long size = new FileInfo(path).Length;
                return size > 0 && size <= MaxInspectableFileBytes;
            }
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
                return (full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)
                    ? full.Substring(rootFull.Length)
                    : Path.GetFileName(full)).Replace('\\', '/');
            }
            catch { return Path.GetFileName(file) ?? ""; }
        }

        private static string SourcePathLower(string path)
        {
            return "/" + (path ?? "").Replace('\\', '/').Trim('/').ToLowerInvariant();
        }

        private static string FormatModifiedTime(string file)
        {
            try { return File.GetLastWriteTimeUtc(file).ToString("o", CultureInfo.InvariantCulture); }
            catch { return ""; }
        }

        private static string Detail(string name, string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "" : name + "=" + value.Trim();
        }

        private static string JoinDetails(params string[] values)
        {
            return string.Join("; ", (values ?? new string[0]).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray());
        }

        private static string Limit(string value)
        {
            string text = value ?? "";
            return text.Length <= MaxFieldLength ? text : text.Substring(0, MaxFieldLength);
        }

        private static void Warn(List<string> warnings, string message)
        {
            if (warnings != null) warnings.Add("UAC derive: " + message);
        }

        private sealed class SystemdDirective
        {
            public string Section = "";
            public string Key = "";
            public string Value = "";
            public int LineNumber;
        }

        private sealed class LogicalLine
        {
            public string Text = "";
            public int LineNumber;
        }

        private sealed class AuthorizedKeyToken
        {
            public string Value = "";
            public int StartIndex;
            public int EndIndex;
        }

        private sealed class UacPersistenceRow
        {
            public string ModifiedTimeUtc = "";
            public string Platform = "";
            public string Mechanism = "";
            public string Scope = "";
            public string Name = "";
            public string User = "";
            public string Executable = "";
            public string Arguments = "";
            public string Trigger = "";
            public string EnabledState = "";
            public string KeyFingerprintSha256 = "";
            public string SourcePath = "";
            public int LineNumber;
            public string Details = "";
        }
    }
}
