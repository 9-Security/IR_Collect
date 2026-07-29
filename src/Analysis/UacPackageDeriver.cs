using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Bounded intake for high-confidence UAC package-manager command outputs.
    /// Package presence is a state observation, not a maliciousness verdict.
    /// </summary>
    public static class UacPackageDeriver
    {
        private const long MaxSourceFileBytes = 64L * 1024 * 1024;
        private const int MaxLineCharacters = 64 * 1024;
        private const int MaxRows = 50000;
        private const int MaxNameCharacters = 1024;
        private const int MaxVersionCharacters = 1024;
        private const int MaxDescriptionCharacters = 2048;
        private const int MaxDetailsCharacters = 2048;

        private static readonly Regex DpkgRegex = new Regex(
            @"^(?<status>[A-Za-z?]{2,3})\s+(?<name>\S+)\s+(?<version>\S+)\s+(?<arch>\S+)(?:\s+(?<description>.*))?$",
            RegexOptions.CultureInvariant);
        private static readonly Regex RpmTimestampRegex = new Regex(
            @"^(?<epoch>\d{1,12})~(?<name>[^~]+)~(?<version>.+)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex ApkRegex = new Regex(
            @"^(?<name>.+)-(?<version>\d[^\s]*)\s+-\s+(?<description>.*)$",
            RegexOptions.CultureInvariant);
        private static readonly Regex SnapRegex = new Regex(
            @"^(?<name>\S+)\s+(?<version>\S+)\s+(?<revision>\S+)\s+(?<tracking>\S+)\s+(?<publisher>\S+)(?:\s+(?<notes>.*))?$",
            RegexOptions.CultureInvariant);
        private static readonly Regex UacTimestampRegex = new Regex(
            @"^(?<stamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:Z|[+-]\d{2}:?\d{2}))",
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

            string output = Path.Combine(outputRoot, ArtifactNames.UacPackagesCsv);
            if (File.Exists(output))
                return;

            List<string> files = EnumeratePackageFiles(sourceRoot).ToList();
            if (files.Count == 0)
                return;

            string observedAtUtc;
            TryReadExplicitCollectionTime(sourceRoot, out observedAtUtc);
            bool hasRichRpm = files.Any(f => string.Equals(
                Path.GetFileName(f),
                "rpm_-q_-a_--queryformat_installtime_name_version_release.txt",
                StringComparison.OrdinalIgnoreCase));
            bool hasDetailedBrew = files.Any(f =>
                string.Equals(Path.GetFileName(f), "brew_list_--versions_--multiple.txt",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(f), "brew_list_--formula.txt",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(f), "brew_list_--cask.txt",
                    StringComparison.OrdinalIgnoreCase));

            var rows = new List<PackageRow>();
            bool hitCap = false;
            for (int i = 0; i < files.Count && !hitCap; i++)
            {
                string name = (Path.GetFileName(files[i]) ?? "").ToLowerInvariant();
                if (hasRichRpm && name == "rpm_-q_-a.txt")
                    continue;
                if (hasDetailedBrew && name == "brew_list.txt")
                    continue;

                try
                {
                    int oversizedLines;
                    hitCap = ParseFile(sourceRoot, files[i], observedAtUtc, rows,
                        out oversizedLines);
                    if (oversizedLines > 0)
                    {
                        Warn(warnings, "package source contained " +
                            oversizedLines.ToString(CultureInfo.InvariantCulture) +
                            " oversized line(s) that remained raw: " +
                            ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    }
                }
                catch (Exception ex)
                {
                    Warn(warnings, "package source could not be parsed: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + " (" +
                        (ex.Message ?? "") + ")");
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("ObservedAtUtc,InstallTimeUtc,InstallTimeParseStatus,Manager,Name,Version,Architecture,State,Scope,Publisher,Description,SourcePath,LineNumber,Details");
                for (int i = 0; i < rows.Count; i++)
                {
                    PackageRow row = rows[i];
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.ObservedAtUtc),
                        CsvUtils.EscapeField(row.InstallTimeUtc),
                        CsvUtils.EscapeField(row.InstallTimeParseStatus),
                        CsvUtils.EscapeField(row.Manager),
                        CsvUtils.EscapeField(row.Name),
                        CsvUtils.EscapeField(row.Version),
                        CsvUtils.EscapeField(row.Architecture),
                        CsvUtils.EscapeField(row.State),
                        CsvUtils.EscapeField(row.Scope),
                        CsvUtils.EscapeField(row.Publisher),
                        CsvUtils.EscapeField(row.Description),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (hitCap)
                Warn(warnings, "package rows were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) + " entries.");
            Logger.Info("Derived " + ArtifactNames.UacPackagesCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            if (path.IndexOf("/live_response/packages/", StringComparison.Ordinal) < 0)
                return false;

            string name = Path.GetFileName(path) ?? "";
            return name == "dpkg_-l.txt" ||
                name == "rpm_-q_-a.txt" ||
                name == "rpm_-q_-a_--queryformat_installtime_name_version_release.txt" ||
                name == "dnf_list_installed.txt" ||
                name == "yum_list_installed.txt" ||
                name == "pacman_-q_-e.txt" ||
                name == "pacman_-q_-m.txt" ||
                name == "pacman_-q_-n.txt" ||
                name == "apk_info_-vv.txt" ||
                name == "flatpak_list.txt" ||
                name == "snap_list.txt" ||
                name == "snap_list_--all.txt" ||
                name == "brew_list.txt" ||
                name == "brew_list_--formula.txt" ||
                name == "brew_list_--cask.txt" ||
                name == "brew_list_--versions_--multiple.txt";
        }

        private static IEnumerable<string> EnumeratePackageFiles(string folder)
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

        private static bool ParseFile(string root, string file, string observedAtUtc,
            List<PackageRow> rows, out int oversizedLines)
        {
            oversizedLines = 0;
            string source = ToRelativeSourcePath(root, file);
            string fileName = (Path.GetFileName(file) ?? "").ToLowerInvariant();
            using (var reader = new StreamReader(new FileStream(file, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite | FileShare.Delete),
                Encoding.UTF8, true))
            using (var bounded = new BoundedLineReader(reader, MaxLineCharacters))
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

                    List<PackageRow> parsed = ParseLine(fileName, line);
                    for (int i = 0; i < parsed.Count; i++)
                    {
                        PackageRow row = parsed[i];
                        row.ObservedAtUtc = observedAtUtc ?? "";
                        row.SourcePath = source;
                        row.LineNumber = lineNumber;
                        BoundCanonicalFields(row);
                        rows.Add(row);
                        if (rows.Count >= MaxRows)
                            return true;
                    }
                }
            }
            return false;
        }

        private static List<PackageRow> ParseLine(string fileName, string line)
        {
            var rows = new List<PackageRow>();
            string value = (line ?? "").Trim();
            if (value.Length == 0 || IsDiagnosticLine(value))
                return rows;

            PackageRow row;
            if (fileName == "dpkg_-l.txt")
            {
                row = ParseDpkg(value);
            }
            else if (fileName ==
                "rpm_-q_-a_--queryformat_installtime_name_version_release.txt")
            {
                row = ParseRpmTimestamp(value);
            }
            else if (fileName == "rpm_-q_-a.txt")
            {
                row = NewRow("rpm");
                row.Name = value;
                row.State = "installed";
                row.Scope = "system";
                row.Details = "parse_level=package-identifier-only";
            }
            else if (fileName == "dnf_list_installed.txt" ||
                fileName == "yum_list_installed.txt")
            {
                row = ParseDnfYum(value,
                    fileName.StartsWith("dnf_", StringComparison.Ordinal) ? "dnf" : "yum");
            }
            else if (fileName == "pacman_-q_-e.txt" ||
                fileName == "pacman_-q_-m.txt" ||
                fileName == "pacman_-q_-n.txt")
            {
                string scope = fileName == "pacman_-q_-m.txt" ? "foreign" :
                    fileName == "pacman_-q_-e.txt" ? "explicit" : "repository";
                row = ParseNameVersion(value, "pacman", scope);
            }
            else if (fileName == "apk_info_-vv.txt")
            {
                row = ParseApk(value);
            }
            else if (fileName == "flatpak_list.txt")
            {
                row = ParseFlatpak(line);
            }
            else if (fileName == "snap_list.txt" ||
                fileName == "snap_list_--all.txt")
            {
                row = ParseSnap(value);
            }
            else if (fileName == "brew_list_--versions_--multiple.txt")
            {
                ParseBrewVersions(value, rows);
                return rows;
            }
            else
            {
                string scope = fileName == "brew_list_--formula.txt" ? "formula" :
                    fileName == "brew_list_--cask.txt" ? "cask" : "unknown";
                row = NewRow("brew");
                row.Name = value;
                row.State = "installed";
                row.Scope = scope;
            }

            if (row != null && !string.IsNullOrWhiteSpace(row.Name))
                rows.Add(row);
            return rows;
        }

        private static PackageRow ParseDpkg(string value)
        {
            Match match = DpkgRegex.Match(value);
            if (!match.Success)
                return null;

            string rawStatus = match.Groups["status"].Value;
            var row = NewRow("dpkg");
            row.Name = match.Groups["name"].Value;
            row.Version = match.Groups["version"].Value;
            row.Architecture = match.Groups["arch"].Value;
            row.Description = match.Groups["description"].Value;
            row.State = rawStatus.Length > 1 &&
                char.ToLowerInvariant(rawStatus[1]) == 'i'
                ? "installed"
                : rawStatus.StartsWith("rc", StringComparison.OrdinalIgnoreCase)
                    ? "removed-config-remains"
                    : "package-state-observed";
            row.Scope = "system";
            row.Details = "raw_status=" + rawStatus;
            return row;
        }

        private static PackageRow ParseRpmTimestamp(string value)
        {
            Match match = RpmTimestampRegex.Match(value);
            if (!match.Success)
                return null;

            var row = NewRow("rpm");
            row.Name = match.Groups["name"].Value.Trim();
            row.Version = match.Groups["version"].Value.Trim();
            row.State = "installed";
            row.Scope = "system";

            long epochSeconds;
            if (long.TryParse(match.Groups["epoch"].Value, NumberStyles.None,
                CultureInfo.InvariantCulture, out epochSeconds) &&
                TryUnixSecondsToUtc(epochSeconds, out row.InstallTimeUtc))
            {
                row.InstallTimeParseStatus = "epoch-parsed";
            }
            else
            {
                row.InstallTimeParseStatus = "invalid-epoch";
                row.Details = "raw_install_epoch=" + match.Groups["epoch"].Value;
            }
            return row;
        }

        private static PackageRow ParseDnfYum(string value, string manager)
        {
            if (value.StartsWith("Installed Packages", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("Last metadata expiration check", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("Loaded plugins:", StringComparison.OrdinalIgnoreCase))
                return null;

            string[] parts = Regex.Split(value, @"\s+");
            if (parts.Length < 3)
                return null;

            var row = NewRow(manager);
            SplitNameArchitecture(parts[0], out row.Name, out row.Architecture);
            row.Version = parts[1];
            row.State = "installed";
            row.Scope = "system";
            if (parts.Length > 2)
                row.Details = "repository=" + string.Join(" ", parts.Skip(2).ToArray());
            return row;
        }

        private static PackageRow ParseNameVersion(string value, string manager,
            string scope)
        {
            int split = value.IndexOfAny(new char[] { ' ', '\t' });
            if (split <= 0)
                return null;

            var row = NewRow(manager);
            row.Name = value.Substring(0, split).Trim();
            row.Version = value.Substring(split).Trim();
            row.State = "installed";
            row.Scope = scope;
            return row;
        }

        private static PackageRow ParseApk(string value)
        {
            Match match = ApkRegex.Match(value);
            if (!match.Success)
                return null;

            var row = NewRow("apk");
            row.Name = match.Groups["name"].Value.Trim();
            row.Version = match.Groups["version"].Value.Trim();
            row.Description = match.Groups["description"].Value.Trim();
            row.State = "installed";
            row.Scope = "system";
            return row;
        }

        private static PackageRow ParseFlatpak(string line)
        {
            string[] parts = (line ?? "").Split(new char[] { '\t' },
                StringSplitOptions.None);
            if (parts.Length < 2 ||
                string.Equals(parts[0].Trim(), "Name", StringComparison.OrdinalIgnoreCase))
                return null;

            var row = NewRow("flatpak");
            row.Description = parts[0].Trim();
            row.Name = parts[1].Trim();
            row.Version = parts.Length > 2 ? parts[2].Trim() : "";
            row.State = "installed";
            row.Scope = parts.Length > 4 ? parts[4].Trim().ToLowerInvariant() : "unknown";
            if (parts.Length > 3 && !string.IsNullOrWhiteSpace(parts[3]))
                row.Details = "branch=" + parts[3].Trim();
            return row;
        }

        private static PackageRow ParseSnap(string value)
        {
            if (value.StartsWith("Name ", StringComparison.OrdinalIgnoreCase))
                return null;

            Match match = SnapRegex.Match(value);
            if (!match.Success)
                return null;

            string notes = match.Groups["notes"].Value.Trim();
            var row = NewRow("snap");
            row.Name = match.Groups["name"].Value;
            row.Version = match.Groups["version"].Value;
            row.State = notes.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0
                ? "disabled-revision"
                : "installed";
            row.Scope = "system";
            row.Publisher = match.Groups["publisher"].Value;
            row.Details = "revision=" + match.Groups["revision"].Value +
                "; tracking=" + match.Groups["tracking"].Value;
            if (!string.IsNullOrWhiteSpace(notes))
                row.Details += "; notes=" + notes;
            return row;
        }

        private static void ParseBrewVersions(string value, List<PackageRow> rows)
        {
            string[] parts = Regex.Split(value, @"\s+");
            if (parts.Length < 2)
                return;

            for (int i = 1; i < parts.Length; i++)
            {
                if (string.IsNullOrWhiteSpace(parts[i]))
                    continue;
                var row = NewRow("brew");
                row.Name = parts[0];
                row.Version = parts[i];
                row.State = "installed";
                row.Scope = "unknown";
                rows.Add(row);
            }
        }

        private static PackageRow NewRow(string manager)
        {
            var row = new PackageRow();
            row.Manager = manager ?? "";
            row.InstallTimeParseStatus = "not-provided";
            return row;
        }

        private static void SplitNameArchitecture(string value, out string name,
            out string architecture)
        {
            name = value ?? "";
            architecture = "";
            int dot = name.LastIndexOf('.');
            if (dot <= 0 || dot >= name.Length - 1)
                return;

            string suffix = name.Substring(dot + 1);
            if (!IsArchitectureToken(suffix))
                return;
            architecture = suffix;
            name = name.Substring(0, dot);
        }

        private static bool IsArchitectureToken(string value)
        {
            string token = (value ?? "").ToLowerInvariant();
            return token == "noarch" || token == "x86_64" || token == "amd64" ||
                token == "i386" || token == "i486" || token == "i586" ||
                token == "i686" || token == "aarch64" || token == "arm64" ||
                token == "armv7hl" || token == "ppc64" || token == "ppc64le" ||
                token == "s390x" || token == "src";
        }

        private static bool TryUnixSecondsToUtc(long seconds, out string utc)
        {
            utc = "";
            try
            {
                DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0,
                    DateTimeKind.Utc);
                DateTime value = epoch.AddSeconds(seconds);
                if (value.Year < 1980 || value.Year > 2100)
                    return false;
                utc = value.ToString("o", CultureInfo.InvariantCulture);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryReadExplicitCollectionTime(string folder,
            out string observedAtUtc)
        {
            observedAtUtc = "";
            IEnumerable<string> logs;
            try { logs = Directory.EnumerateFiles(folder, "uac.log", SearchOption.AllDirectories); }
            catch { return false; }

            foreach (string log in logs.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                long size;
                try { size = new FileInfo(log).Length; }
                catch { continue; }
                if (size <= 0 || size > 8L * 1024 * 1024)
                    continue;

                try
                {
                    using (var reader = new StreamReader(new FileStream(log,
                        FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8, true))
                    {
                        for (int i = 0; i < 256; i++)
                        {
                            string line = reader.ReadLine();
                            if (line == null)
                                break;
                            Match match = UacTimestampRegex.Match(line);
                            if (!match.Success)
                                continue;

                            string value = match.Groups["stamp"].Value.Trim()
                                .Replace(',', '.');
                            value = Regex.Replace(value,
                                @"([+-]\d{2})(\d{2})$", "$1:$2");
                            DateTimeOffset parsed;
                            if (DateTimeOffset.TryParse(value,
                                CultureInfo.InvariantCulture,
                                DateTimeStyles.AllowWhiteSpaces, out parsed))
                            {
                                if (parsed.Year < 1980 || parsed.Year > 2100)
                                    continue;
                                observedAtUtc = parsed.UtcDateTime.ToString("o",
                                    CultureInfo.InvariantCulture);
                                return true;
                            }
                        }
                    }
                }
                catch
                {
                }
            }
            return false;
        }

        private static bool IsDiagnosticLine(string value)
        {
            string text = (value ?? "").TrimStart();
            return text.StartsWith("error:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("warning:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("fatal:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("rpm:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("dpkg-query:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("dnf:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("yum:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("pacman:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("snap:", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("brew:", StringComparison.OrdinalIgnoreCase);
        }

        private static void BoundCanonicalFields(PackageRow row)
        {
            if (row == null)
                return;

            bool truncated = false;
            row.Name = LimitText(row.Name, MaxNameCharacters, ref truncated);
            row.Version = LimitText(row.Version, MaxVersionCharacters, ref truncated);
            row.Architecture = LimitText(row.Architecture, 128, ref truncated);
            row.State = LimitText(row.State, 128, ref truncated);
            row.Scope = LimitText(row.Scope, 256, ref truncated);
            row.Publisher = LimitText(row.Publisher, 512, ref truncated);
            row.Description = LimitText(row.Description, MaxDescriptionCharacters,
                ref truncated);
            row.Details = LimitText(row.Details, MaxDetailsCharacters, ref truncated);
            if (truncated)
            {
                string marker = "canonical_field_truncated=true";
                row.Details = string.IsNullOrWhiteSpace(row.Details) ? marker :
                    row.Details + "; " + marker;
                if (row.Details.Length > MaxDetailsCharacters)
                    row.Details = row.Details.Substring(0,
                        MaxDetailsCharacters - marker.Length - 2) + "; " + marker;
            }
        }

        private static string LimitText(string value, int limit, ref bool truncated)
        {
            string text = value ?? "";
            if (text.Length <= limit)
                return text;
            truncated = true;
            return text.Substring(0, limit);
        }

        private static string ToRelativeSourcePath(string root, string file)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;
                string fileFull = Path.GetFullPath(file);
                if (fileFull.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
                    return fileFull.Substring(rootFull.Length).Replace('\\', '/');
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

            public BoundedLineReader(TextReader reader, int maxLineCharacters)
            {
                _reader = reader;
                _maxLineCharacters = maxLineCharacters;
            }

            public string ReadLine(out bool oversized)
            {
                oversized = false;
                var sb = new StringBuilder();
                bool sawCharacter = false;
                while (true)
                {
                    int value = _reader.Read();
                    if (value < 0)
                        return sawCharacter ? sb.ToString() : null;
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

        private sealed class PackageRow
        {
            public string ObservedAtUtc = "";
            public string InstallTimeUtc = "";
            public string InstallTimeParseStatus = "";
            public string Manager = "";
            public string Name = "";
            public string Version = "";
            public string Architecture = "";
            public string State = "";
            public string Scope = "";
            public string Publisher = "";
            public string Description = "";
            public string SourcePath = "";
            public int LineNumber;
            public string Details = "";
        }
    }
}
