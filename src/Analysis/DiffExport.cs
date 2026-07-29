using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    [DataContract]
    public sealed class DiffCaseReference
    {
        [DataMember(Name = "host")] public string Host { get; set; }
        [DataMember(Name = "case_id")] public string CaseId { get; set; }
        [DataMember(Name = "fact_count")] public int FactCount { get; set; }
        [DataMember(Name = "evidence_digest")] public string EvidenceDigest { get; set; }
        [DataMember(Name = "source_format")] public string SourceFormat { get; set; }
        [DataMember(Name = "source_evidence_sha256")] public string SourceEvidenceSha256 { get; set; }
        [DataMember(Name = "collection_coverage_status")] public string CollectionCoverageStatus { get; set; }
        [DataMember(Name = "fact_store_freshness_status")] public string FactStoreFreshnessStatus { get; set; }
        [DataMember(Name = "fact_store_build_mode")] public string FactStoreBuildMode { get; set; }
    }

    [DataContract]
    public sealed class DiffFactReference
    {
        [DataMember(Name = "id")] public string Id { get; set; }
        [DataMember(Name = "source")] public string Source { get; set; }
        [DataMember(Name = "action")] public string Action { get; set; }
        [DataMember(Name = "source_file")] public string SourceFile { get; set; }
        [DataMember(Name = "raw_ref")] public string RawRef { get; set; }
        [DataMember(Name = "collection_step")] public string CollectionStep { get; set; }
        [DataMember(Name = "collection_status")] public string CollectionStatus { get; set; }
        [DataMember(Name = "collection_privilege")] public string CollectionPrivilege { get; set; }
        [DataMember(Name = "parse_level")] public string ParseLevel { get; set; }
        [DataMember(Name = "fallback_used")] public bool FallbackUsed { get; set; }
        [DataMember(Name = "parser_note")] public string ParserNote { get; set; }
    }

    [DataContract]
    public sealed class DiffChange
    {
        [DataMember(Name = "category")] public string Category { get; set; }
        [DataMember(Name = "change_type")] public string ChangeType { get; set; }
        [DataMember(Name = "entity_key")] public string EntityKey { get; set; }
        [DataMember(Name = "display_value")] public string DisplayValue { get; set; }
        [DataMember(Name = "source_names")] public List<string> SourceNames { get; set; }
        [DataMember(Name = "confidence")] public string Confidence { get; set; }
        [DataMember(Name = "baseline_fact_count")] public int BaselineFactCount { get; set; }
        [DataMember(Name = "target_fact_count")] public int TargetFactCount { get; set; }
        [DataMember(Name = "baseline_fact_refs")] public List<DiffFactReference> BaselineFactRefs { get; set; }
        [DataMember(Name = "target_fact_refs")] public List<DiffFactReference> TargetFactRefs { get; set; }
        [DataMember(Name = "notes")] public List<string> Notes { get; set; }

        public DiffChange()
        {
            SourceNames = new List<string>();
            BaselineFactRefs = new List<DiffFactReference>();
            TargetFactRefs = new List<DiffFactReference>();
            Notes = new List<string>();
        }
    }

    [DataContract]
    public sealed class DiffReport
    {
        [DataMember(Name = "diff_schema")] public string DiffSchema { get; set; }
        [DataMember(Name = "generated_at")] public string GeneratedAt { get; set; }
        [DataMember(Name = "tool_name")] public string ToolName { get; set; }
        [DataMember(Name = "tool_version")] public string ToolVersion { get; set; }
        [DataMember(Name = "analysis_mode")] public string AnalysisMode { get; set; }
        [DataMember(Name = "baseline_ref")] public DiffCaseReference BaselineRef { get; set; }
        [DataMember(Name = "target_ref")] public DiffCaseReference TargetRef { get; set; }
        [DataMember(Name = "change_count")] public int ChangeCount { get; set; }
        [DataMember(Name = "changes_truncated")] public bool ChangesTruncated { get; set; }
        [DataMember(Name = "max_changes")] public int MaxChanges { get; set; }
        [DataMember(Name = "changes")] public List<DiffChange> Changes { get; set; }

        public DiffReport()
        {
            Changes = new List<DiffChange>();
        }
    }

    public static class DiffExport
    {
        public static string Serialize(DiffReport report)
        {
            var serializer = new DataContractJsonSerializer(typeof(DiffReport));
            using (var stream = new MemoryStream())
            {
                serializer.WriteObject(stream, report);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        public static void SaveToFile(DiffReport report, string path)
        {
            AtomicFile.WriteAllText(path, Serialize(report), new UTF8Encoding(false));
        }
    }
}
