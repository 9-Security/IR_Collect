using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    [DataContract]
    public sealed class UacEvidenceMetadata
    {
        [DataMember(Name = "detected")] public bool IsUac { get; set; }
        [DataMember(Name = "version")] public string Version { get; set; }
        [DataMember(Name = "operating_system")] public string OperatingSystem { get; set; }
        [DataMember(Name = "architecture")] public string Architecture { get; set; }
        [DataMember(Name = "hostname")] public string Hostname { get; set; }
        [DataMember(Name = "profile")] public string Profile { get; set; }
        [DataMember(Name = "collection_started")] public string CollectionStarted { get; set; }
        [DataMember(Name = "collection_completed")] public string CollectionCompleted { get; set; }
        [DataMember(Name = "source_format")] public string SourceFormat { get; set; }
        [DataMember(Name = "evidence_file_count")] public int EvidenceFileCount { get; set; }
        [DataMember(Name = "evidence_bytes")] public long EvidenceBytes { get; set; }
        [DataMember(Name = "normalized_source_count")] public int NormalizedSourceCount { get; set; }
        [DataMember(Name = "parser_eligible_count")] public int ParserEligibleCount { get; set; }
        [DataMember(Name = "raw_only_count")] public int RawOnlyCount { get; set; }

        public UacEvidenceMetadata()
        {
            Version = "";
            OperatingSystem = "";
            Architecture = "";
            Hostname = "";
            Profile = "";
            CollectionStarted = "";
            CollectionCompleted = "";
            SourceFormat = "";
        }
    }

    public static class UacEvidenceIntake
    {
        private const long MaxMetadataLogBytes = 8L * 1024 * 1024;

        public static UacEvidenceMetadata Inspect(string root, string sourceFormat, IList<EvidenceFile> evidenceFiles)
        {
            var metadata = new UacEvidenceMetadata();
            metadata.SourceFormat = sourceFormat ?? "";
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                return metadata;

            string logPath = FindUacLog(root);
            int structuralMarkers = CountStructuralMarkers(root);
            metadata.IsUac = !string.IsNullOrEmpty(logPath) || structuralMarkers >= 2;
            if (!metadata.IsUac)
                return metadata;

            if (!string.IsNullOrEmpty(logPath))
                ReadMetadataLog(logPath, metadata);

            if (evidenceFiles != null)
            {
                metadata.EvidenceFileCount = evidenceFiles.Count;
                foreach (EvidenceFile evidence in evidenceFiles)
                {
                    if (evidence == null) continue;
                    if (evidence.SizeBytes > 0) metadata.EvidenceBytes += evidence.SizeBytes;
                }
            }
            return metadata;
        }

        public static void WriteEvidenceIndex(string root, UacEvidenceMetadata metadata, IList<EvidenceFile> evidenceFiles, List<string> warnings)
        {
            WriteEvidenceIndex(root, root, metadata, evidenceFiles, warnings);
        }

        public static void WriteEvidenceIndex(string sourceRoot, string outputRoot, UacEvidenceMetadata metadata,
            IList<EvidenceFile> evidenceFiles, List<string> warnings)
        {
            if (metadata == null || !metadata.IsUac || evidenceFiles == null)
                return;
            if (string.IsNullOrWhiteSpace(sourceRoot) || string.IsNullOrWhiteSpace(outputRoot))
                return;

            Directory.CreateDirectory(outputRoot);
            string output = Path.Combine(outputRoot, ArtifactNames.UacEvidenceIndexCsv);
            if (File.Exists(output)) return;

            int normalized = 0;
            int eligible = 0;
            int rawOnly = 0;
            HashSet<string> normalizedPersistenceSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacPersistenceCsv);
            HashSet<string> normalizedJournalSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacJournalFilesCsv);
            HashSet<string> normalizedBootSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacBootSessionsCsv);
            HashSet<string> normalizedLoginSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacLoginEventsCsv);
            HashSet<string> normalizedAuditSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacAuditEventsCsv);
            HashSet<string> normalizedSystemLogSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacSystemLogEventsCsv);
            HashSet<string> normalizedPackageSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacPackagesCsv);
            HashSet<string> normalizedWebServerSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacWebServerEventsCsv);
            HashSet<string> normalizedFileHashSources = LoadCanonicalSourcePaths(outputRoot, ArtifactNames.UacFileHashesCsv);
            try
            {
                AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
                {
                    sw.WriteLine("ModifiedTimeUtc,RelativePath,SizeBytes,Sha256,Category,AnalysisStatus");
                    foreach (EvidenceFile evidence in evidenceFiles)
                    {
                        if (evidence == null || string.IsNullOrWhiteSpace(evidence.RelPath)) continue;
                        string category = Classify(evidence.RelPath);
                        string status = ResolveAnalysisStatus(outputRoot, evidence.RelPath, category,
                            normalizedPersistenceSources, normalizedJournalSources, normalizedBootSources,
                            normalizedLoginSources, normalizedAuditSources, normalizedSystemLogSources,
                            normalizedPackageSources, normalizedWebServerSources,
                            normalizedFileHashSources);
                        if (string.Equals(status, "normalized-source", StringComparison.Ordinal)) normalized++;
                        else if (string.Equals(status, "parser-eligible", StringComparison.Ordinal)) eligible++;
                        else if (string.Equals(status, "metadata-source", StringComparison.Ordinal)) normalized++;
                        else rawOnly++;

                        string modified = ResolveModifiedTime(sourceRoot, evidence.RelPath);
                        sw.WriteLine(string.Join(",", new string[] {
                            CsvUtils.EscapeField(modified),
                            CsvUtils.EscapeField((evidence.RelPath ?? "").Replace('\\', '/')),
                            evidence.SizeBytes.ToString(CultureInfo.InvariantCulture),
                            CsvUtils.EscapeField(evidence.Sha256 ?? ""),
                            CsvUtils.EscapeField(category),
                            CsvUtils.EscapeField(status)
                        }));
                    }
                });

                metadata.NormalizedSourceCount = normalized;
                metadata.ParserEligibleCount = eligible;
                metadata.RawOnlyCount = rawOnly;
                Logger.Info("Indexed UAC evidence files: " + evidenceFiles.Count.ToString(CultureInfo.InvariantCulture));
            }
            catch (Exception ex)
            {
                if (warnings != null) warnings.Add("UAC evidence index could not be written: " + (ex.Message ?? ""));
                Logger.Warning("UAC evidence index: " + (ex.Message ?? ""));
            }
        }

        public static string Classify(string relativePath)
        {
            string path = "/" + Normalize(relativePath).TrimStart('/');
            string name = Path.GetFileName(path) ?? "";

            if (name == "uac.log" || name.StartsWith("uac-", StringComparison.Ordinal) && name.EndsWith(".log", StringComparison.Ordinal))
                return "AcquisitionMetadata";
            if (path.IndexOf("/bodyfile", StringComparison.Ordinal) >= 0 || name == "bodyfile.txt")
                return "FilesystemTimeline";
            if (UacFileHashDeriver.IsSupportedSourceRelativePath(path))
                return "FileHash";
            if (path.IndexOf("/live_response/process/", StringComparison.Ordinal) >= 0)
                return "LiveResponseProcess";
            if (path.IndexOf("/live_response/network/", StringComparison.Ordinal) >= 0)
                return "LiveResponseNetwork";
            if (UacPackageDeriver.IsSupportedSourceRelativePath(path))
                return "Packages";
            if (UacLoginEventDeriver.IsSupportedSourceRelativePath(path))
                return "LoginHistory";
            if (UacAuditEventDeriver.IsSupportedSourceRelativePath(path))
                return "LinuxAudit";
            if (UacSystemLogDeriver.IsSupportedSourceRelativePath(path))
                return "SystemLogText";
            if (UacWebServerLogDeriver.IsSupportedSourceRelativePath(path))
                return "WebServerLog";
            if (path.IndexOf("/live_response/system/", StringComparison.Ordinal) >= 0)
                return "LiveResponseSystem";
            if (UacJournalDeriver.IsJournalFilePath(path))
                return "SystemLog";
            if (IsAccountPath(path))
                return "Accounts";
            if (IsShellHistoryPath(path))
                return "ShellHistory";
            if (IsAuthenticationLog(path))
                return "AuthenticationLog";
            if (IsPersistencePath(path))
                return "Persistence";
            if (path.IndexOf("/files/browsers/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/root/home/", StringComparison.Ordinal) >= 0 && path.IndexOf("/.mozilla/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/root/users/", StringComparison.Ordinal) >= 0 && path.IndexOf("/safari/", StringComparison.Ordinal) >= 0)
                return "Browser";
            if (path.IndexOf("/live_response/packages/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/root/var/lib/dpkg/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/root/var/lib/rpm/", StringComparison.Ordinal) >= 0)
                return "Packages";
            if (path.IndexOf("/memory_dump/", StringComparison.Ordinal) >= 0)
                return "Memory";
            if (path.IndexOf("/hash", StringComparison.Ordinal) >= 0)
                return "HashList";
            if (path.IndexOf("/root/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/[root]/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/root/private/var/log/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/[root]/private/var/log/", StringComparison.Ordinal) >= 0)
                return "SystemLog";
            if (path.StartsWith("/root/", StringComparison.Ordinal) || path.StartsWith("/[root]/", StringComparison.Ordinal))
                return "CollectedFile";
            if (path.IndexOf("/live_response/", StringComparison.Ordinal) >= 0)
                return "LiveResponseOther";
            return "Other";
        }

        private static string ResolveAnalysisStatus(string root, string relativePath, string category,
            HashSet<string> normalizedPersistenceSources, HashSet<string> normalizedJournalSources,
            HashSet<string> normalizedBootSources, HashSet<string> normalizedLoginSources,
            HashSet<string> normalizedAuditSources, HashSet<string> normalizedSystemLogSources,
            HashSet<string> normalizedPackageSources,
            HashSet<string> normalizedWebServerSources,
            HashSet<string> normalizedFileHashSources)
        {
            if (string.Equals(category, "AcquisitionMetadata", StringComparison.Ordinal))
                return "metadata-source";

            string normalizedPath = Normalize(relativePath);
            string sourceName = Path.GetFileName(normalizedPath) ?? "";
            string normalizedOutput = null;
            if (string.Equals(category, "FilesystemTimeline", StringComparison.Ordinal))
                normalizedOutput = ArtifactNames.ActivityTimelineCsv;
            else if (string.Equals(category, "LiveResponseProcess", StringComparison.Ordinal))
            {
                if (!sourceName.EndsWith(".txt", StringComparison.Ordinal)) return "indexed-raw";
                return "parser-eligible";
            }
            else if (string.Equals(category, "LiveResponseNetwork", StringComparison.Ordinal))
            {
                if (!LooksLikeSupportedNetworkSnapshot(sourceName)) return "indexed-raw";
                return "parser-eligible";
            }
            else if (string.Equals(category, "LiveResponseSystem", StringComparison.Ordinal) &&
                UacJournalDeriver.IsBootListPath(normalizedPath))
            {
                return normalizedBootSources != null &&
                    normalizedBootSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "AuthenticationLog", StringComparison.Ordinal))
                return "parser-eligible";
            else if (string.Equals(category, "LoginHistory", StringComparison.Ordinal))
            {
                return normalizedLoginSources != null &&
                    normalizedLoginSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "LinuxAudit", StringComparison.Ordinal))
            {
                return normalizedAuditSources != null &&
                    normalizedAuditSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "SystemLogText", StringComparison.Ordinal))
            {
                return normalizedSystemLogSources != null &&
                    normalizedSystemLogSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "Packages", StringComparison.Ordinal))
            {
                if (!UacPackageDeriver.IsSupportedSourceRelativePath(normalizedPath))
                    return "indexed-raw";
                return normalizedPackageSources != null &&
                    normalizedPackageSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "parser-eligible";
            }
            else if (string.Equals(category, "WebServerLog", StringComparison.Ordinal))
            {
                return normalizedWebServerSources != null &&
                    normalizedWebServerSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "FileHash", StringComparison.Ordinal))
            {
                return normalizedFileHashSources != null &&
                    normalizedFileHashSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "parser-eligible";
            }
            else if (string.Equals(category, "Accounts", StringComparison.Ordinal))
                normalizedOutput = ArtifactNames.UacAccountsCsv;
            else if (string.Equals(category, "ShellHistory", StringComparison.Ordinal))
                normalizedOutput = ArtifactNames.UacShellHistoryCsv;
            else if (string.Equals(category, "Persistence", StringComparison.Ordinal))
            {
                if (!UacPersistenceDeriver.IsSupportedSourceRelativePath(normalizedPath))
                    return "indexed-raw";
                return normalizedPersistenceSources != null &&
                    normalizedPersistenceSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "normalized-source"
                    : "indexed-raw";
            }
            else if (string.Equals(category, "SystemLog", StringComparison.Ordinal) &&
                UacJournalDeriver.IsJournalFilePath(normalizedPath))
            {
                return normalizedJournalSources != null &&
                    normalizedJournalSources.Contains(NormalizeRelativePath(normalizedPath))
                    ? "metadata-source"
                    : "indexed-raw";
            }

            if (!string.IsNullOrEmpty(normalizedOutput))
                return File.Exists(Path.Combine(root, normalizedOutput)) ? "normalized-source" : "parser-eligible";
            return "indexed-raw";
        }

        private static HashSet<string> LoadCanonicalSourcePaths(string root, string artifactName)
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string path = Path.Combine(root, artifactName);
                foreach (Dictionary<string, string> row in Correlation.CorrelationCsvHelper.ReadCsv(path))
                {
                    string source;
                    if (row.TryGetValue("SourcePath", out source) && !string.IsNullOrWhiteSpace(source))
                        result.Add(NormalizeRelativePath(source));
                }
            }
            catch { }
            return result;
        }

        private static string NormalizeRelativePath(string path)
        {
            return (path ?? "").Replace('\\', '/').Trim().TrimStart('/');
        }

        private static bool LooksLikeSupportedNetworkSnapshot(string name)
        {
            string value = (name ?? "").ToLowerInvariant();
            return value.IndexOf("lsof", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("netstat", StringComparison.Ordinal) >= 0 ||
                value.StartsWith("ss", StringComparison.Ordinal) ||
                value.IndexOf("_ss", StringComparison.Ordinal) >= 0 ||
                value.IndexOf("-ss", StringComparison.Ordinal) >= 0;
        }

        private static string ResolveModifiedTime(string root, string relativePath)
        {
            try
            {
                string local = (relativePath ?? "").Replace('/', Path.DirectorySeparatorChar);
                string path = Path.Combine(root, local);
                if (File.Exists(path))
                    return File.GetLastWriteTimeUtc(path).ToString("o", CultureInfo.InvariantCulture);
            }
            catch { }
            return "";
        }

        private static string FindUacLog(string root)
        {
            try
            {
                string named = Directory.EnumerateFiles(root, "uac.log", SearchOption.AllDirectories).FirstOrDefault();
                if (!string.IsNullOrEmpty(named) && IsUacMetadataLog(named)) return named;
                foreach (string file in Directory.EnumerateFiles(root, "*.log", SearchOption.AllDirectories))
                    if (IsUacMetadataLog(file)) return file;
            }
            catch { }
            return null;
        }

        private static bool IsUacMetadataLog(string path)
        {
            try
            {
                FileInfo info = new FileInfo(path);
                if (info.Length <= 0 || info.Length > MaxMetadataLogBytes) return false;
                using (StreamReader sr = new StreamReader(path, Encoding.UTF8, true))
                {
                    for (int i = 0; i < 80; i++)
                    {
                        string line = sr.ReadLine();
                        if (line == null) break;
                        if (line.IndexOf("Unix-like Artifacts Collector", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            line.IndexOf("UAC directory:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            line.IndexOf("Operating system:", StringComparison.OrdinalIgnoreCase) >= 0 &&
                            line.IndexOf(" INF ", StringComparison.OrdinalIgnoreCase) >= 0)
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private static void ReadMetadataLog(string path, UacEvidenceMetadata metadata)
        {
            try
            {
                using (StreamReader sr = new StreamReader(path, Encoding.UTF8, true))
                {
                    string line;
                    int count = 0;
                    while ((line = sr.ReadLine()) != null && count++ < 1000)
                    {
                        ReadValue(line, "UAC version:", delegate (string v) { metadata.Version = v; });
                        ReadValue(line, "Operating system:", delegate (string v) { metadata.OperatingSystem = v; });
                        ReadValue(line, "Operating System:", delegate (string v) { metadata.OperatingSystem = v; });
                        ReadValue(line, "System architecture:", delegate (string v) { metadata.Architecture = v; });
                        ReadValue(line, "System Architecture:", delegate (string v) { metadata.Architecture = v; });
                        ReadValue(line, "Hostname:", delegate (string v) { metadata.Hostname = v; });
                        ReadValue(line, "Profile:", delegate (string v) { metadata.Profile = v; });
                        ReadValue(line, "Profiles:", delegate (string v) { metadata.Profile = v; });
                        ReadValue(line, "Collection started:", delegate (string v) { metadata.CollectionStarted = v; });
                        ReadValue(line, "Collection completed:", delegate (string v) { metadata.CollectionCompleted = v; });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("UAC metadata log: " + (ex.Message ?? ""));
            }
        }

        private static void ReadValue(string line, string label, Action<string> setter)
        {
            if (string.IsNullOrEmpty(line) || setter == null) return;
            int index = line.IndexOf(label, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return;
            string value = line.Substring(index + label.Length).Trim();
            if (!string.IsNullOrEmpty(value)) setter(value);
        }

        private static int CountStructuralMarkers(string root)
        {
            int count = 0;
            try
            {
                if (Directory.EnumerateDirectories(root, "live_response", SearchOption.AllDirectories).Any()) count++;
                if (Directory.EnumerateFiles(root, "bodyfile.txt", SearchOption.AllDirectories).Any()) count++;
                if (Directory.EnumerateDirectories(root, "[root]", SearchOption.AllDirectories).Any() ||
                    Directory.EnumerateDirectories(root, "root", SearchOption.TopDirectoryOnly).Any()) count++;
            }
            catch { }
            return count;
        }

        private static bool IsAuthenticationLog(string path)
        {
            string name = Path.GetFileName(path) ?? "";
            return (path.IndexOf("/var/log/", StringComparison.Ordinal) >= 0 ||
                    path.IndexOf("/private/var/log/", StringComparison.Ordinal) >= 0) &&
                (name.StartsWith("auth.log", StringComparison.Ordinal) ||
                 name.StartsWith("secure", StringComparison.Ordinal) ||
                 name.StartsWith("system.log", StringComparison.Ordinal));
        }

        private static bool IsAccountPath(string path)
        {
            return path.EndsWith("/etc/passwd", StringComparison.Ordinal) ||
                path.EndsWith("/etc/group", StringComparison.Ordinal) ||
                path.EndsWith("/etc/shadow", StringComparison.Ordinal);
        }

        private static bool IsShellHistoryPath(string path)
        {
            string name = Path.GetFileName(path) ?? "";
            return name == ".bash_history" || name == ".zsh_history" || name == ".sh_history" ||
                name == ".ksh_history" || name == ".ash_history" || name == "fish_history" ||
                name == "consolehost_history.txt";
        }

        private static bool IsPersistencePath(string path)
        {
            return path.IndexOf("/etc/cron", StringComparison.Ordinal) >= 0 ||
                path.EndsWith("/etc/anacrontab", StringComparison.Ordinal) ||
                path.IndexOf("/var/spool/cron", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/var/at/tabs/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/systemd/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/launchagents/", StringComparison.Ordinal) >= 0 ||
                path.IndexOf("/launchdaemons/", StringComparison.Ordinal) >= 0 ||
                path.EndsWith("/authorized_keys", StringComparison.Ordinal) ||
                path.EndsWith("/authorized_keys2", StringComparison.Ordinal) ||
                path.EndsWith("/etc/rc.local", StringComparison.Ordinal) ||
                path.EndsWith("/etc/ld.so.preload", StringComparison.Ordinal);
        }

        private static string Normalize(string path)
        {
            string value = (path ?? "").Replace('\\', '/').Trim().ToLowerInvariant();
            while (value.StartsWith("./", StringComparison.Ordinal)) value = value.Substring(2);
            return value;
        }
    }
}
