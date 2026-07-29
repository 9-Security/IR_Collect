using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    [DataContract]
    public sealed class AnalysisWorkspaceOutput
    {
        [DataMember(Name = "relative_path")] public string RelativePath { get; set; }
        [DataMember(Name = "size_bytes")] public long SizeBytes { get; set; }
        [DataMember(Name = "sha256")] public string Sha256 { get; set; }
    }

    [DataContract]
    public sealed class AnalysisWorkspaceRecord
    {
        [DataMember(Name = "schema")] public string Schema { get; set; }
        [DataMember(Name = "tool_name")] public string ToolName { get; set; }
        [DataMember(Name = "tool_version")] public string ToolVersion { get; set; }
        [DataMember(Name = "generated_at_utc")] public string GeneratedAtUtc { get; set; }
        [DataMember(Name = "source_format")] public string SourceFormat { get; set; }
        [DataMember(Name = "source_evidence_sha256")] public string SourceEvidenceSha256 { get; set; }
        [DataMember(Name = "evidence_digest")] public string EvidenceDigest { get; set; }
        [DataMember(Name = "source_read_only")] public bool SourceReadOnly { get; set; }
        [DataMember(Name = "outputs")] public List<AnalysisWorkspaceOutput> Outputs { get; set; }

        public AnalysisWorkspaceRecord()
        {
            Schema = "analysis_workspace_v1";
            ToolName = BuildInfo.ToolName;
            ToolVersion = BuildInfo.Version;
            GeneratedAtUtc = "";
            SourceFormat = "";
            SourceEvidenceSha256 = "";
            EvidenceDigest = "";
            SourceReadOnly = true;
            Outputs = new List<AnalysisWorkspaceOutput>();
        }
    }

    public static class AnalysisWorkspaceManifest
    {
        public static string Write(CaseData c)
        {
            if (c == null || string.IsNullOrWhiteSpace(c.AnalysisPath) || !Directory.Exists(c.AnalysisPath))
                return null;

            string root = Path.GetFullPath(c.AnalysisPath);
            var record = new AnalysisWorkspaceRecord();
            record.GeneratedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            record.SourceFormat = c.SourceFormat ?? "";
            record.SourceEvidenceSha256 = c.SourceEvidenceSha256 ?? "";
            record.EvidenceDigest = c.EvidenceDigest ?? "";

            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (string.Equals(Path.GetFileName(file), ArtifactNames.AnalysisWorkspaceManifestJson,
                    StringComparison.OrdinalIgnoreCase))
                    continue;

                var info = new FileInfo(file);
                record.Outputs.Add(new AnalysisWorkspaceOutput
                {
                    RelativePath = RelativePath(root, file),
                    SizeBytes = info.Length,
                    Sha256 = EvidenceManifest.ComputeSha256(file)
                });
            }
            record.Outputs.Sort(delegate(AnalysisWorkspaceOutput a, AnalysisWorkspaceOutput b)
            {
                return string.Compare(a.RelativePath, b.RelativePath, StringComparison.Ordinal);
            });

            string path = Path.Combine(root, ArtifactNames.AnalysisWorkspaceManifestJson);
            string temp = AtomicFile.CreateTempPath(path);
            var serializer = new DataContractJsonSerializer(typeof(AnalysisWorkspaceRecord));
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    serializer.WriteObject(stream, record);
                AtomicFile.Commit(temp, path);
                temp = null;
                return path;
            }
            finally
            {
                AtomicFile.TryDelete(temp);
            }
        }

        private static string RelativePath(string root, string path)
        {
            string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') +
                Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(path);
            return full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)
                ? full.Substring(rootFull.Length).Replace('\\', '/')
                : Path.GetFileName(full);
        }
    }
}
