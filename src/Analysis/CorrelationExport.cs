using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IR_Collect.Analysis
{
    // Phase 3.2: serializable DTOs for headless multi-host correlation output (schema "correlation_v1").
    // Times are emitted as ISO-8601 strings (empty for the MinValue sentinel) rather than the
    // DataContract "/Date(...)/" form, so downstream consumers get clean, comparable timestamps.

    [DataContract]
    public class CorrelationHostInfo
    {
        [DataMember(Name = "host")] public string Host { get; set; }
        [DataMember(Name = "case_id")] public string CaseId { get; set; }
        [DataMember(Name = "fact_count")] public int FactCount { get; set; }
        [DataMember(Name = "evidence_digest")] public string EvidenceDigest { get; set; }
        [DataMember(Name = "evidence_file_count")] public int EvidenceFileCount { get; set; }
    }

    [DataContract]
    public class SharedEntityDto
    {
        [DataMember(Name = "entity_type")] public string EntityType { get; set; }
        [DataMember(Name = "value")] public string Value { get; set; }
        [DataMember(Name = "fact_count")] public int FactCount { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "hosts")] public List<string> Hosts { get; set; }
        [DataMember(Name = "sources")] public List<string> Sources { get; set; }
        [DataMember(Name = "first_seen")] public string FirstSeen { get; set; }
        [DataMember(Name = "last_seen")] public string LastSeen { get; set; }
    }

    [DataContract]
    public class TemporalCorrelationDto
    {
        [DataMember(Name = "entity_type")] public string EntityType { get; set; }
        [DataMember(Name = "value")] public string Value { get; set; }
        [DataMember(Name = "fact_count")] public int FactCount { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "hosts")] public List<string> Hosts { get; set; }
        [DataMember(Name = "bucket_start")] public string BucketStart { get; set; }
        [DataMember(Name = "bucket_end")] public string BucketEnd { get; set; }
    }

    [DataContract]
    public class CorrelationReport
    {
        [DataMember(Name = "generated_at")] public string GeneratedAt { get; set; }
        [DataMember(Name = "export_schema")] public string ExportSchema { get; set; }
        [DataMember(Name = "tool_name")] public string ToolName { get; set; }
        [DataMember(Name = "tool_version")] public string ToolVersion { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "ready_hosts")] public int ReadyHosts { get; set; }
        [DataMember(Name = "skipped_hosts")] public int SkippedHosts { get; set; }
        [DataMember(Name = "bucket_minutes")] public int BucketMinutes { get; set; }
        [DataMember(Name = "entity_types")] public List<string> EntityTypes { get; set; }
        [DataMember(Name = "hosts")] public List<CorrelationHostInfo> Hosts { get; set; }
        [DataMember(Name = "shared_entities")] public List<SharedEntityDto> SharedEntities { get; set; }
        [DataMember(Name = "temporal_correlations")] public List<TemporalCorrelationDto> TemporalCorrelations { get; set; }

        public CorrelationReport()
        {
            EntityTypes = new List<string>();
            Hosts = new List<CorrelationHostInfo>();
            SharedEntities = new List<SharedEntityDto>();
            TemporalCorrelations = new List<TemporalCorrelationDto>();
        }
    }

    public static class CorrelationExport
    {
        public static string Serialize(CorrelationReport report)
        {
            var serializer = new DataContractJsonSerializer(typeof(CorrelationReport));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, report);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static void SaveToFile(CorrelationReport report, string path)
        {
            File.WriteAllText(path, Serialize(report), new UTF8Encoding(false));
        }

        /// <summary>ISO-8601 UTC, second precision; empty for sentinel/unset times.</summary>
        public static string Iso(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue || dt.Year <= 1601)
                return "";
            DateTime u = dt.Kind == DateTimeKind.Utc ? dt : dt.ToUniversalTime();
            return u.ToString("yyyy-MM-ddTHH:mm:ss");
        }
    }
}
