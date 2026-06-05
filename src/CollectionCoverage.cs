using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IR_Collect
{
    [DataContract]
    public sealed class CollectionCoverageStep
    {
        [DataMember(Name = "step")]
        public string Step { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }

        [DataMember(Name = "detail")]
        public string Detail { get; set; }

        [DataMember(Name = "artifact_count")]
        public int ArtifactCount { get; set; }

        [DataMember(Name = "artifacts_present")]
        public List<string> ArtifactsPresent { get; set; }

        [DataMember(Name = "artifacts_missing")]
        public List<string> ArtifactsMissing { get; set; }
    }

    [DataContract]
    public sealed class CollectionCoverageReport
    {
        [DataMember(Name = "generated_at")]
        public string GeneratedAt { get; set; }

        [DataMember(Name = "host")]
        public string Host { get; set; }

        [DataMember(Name = "evidence_id")]
        public string EvidenceId { get; set; }

        [DataMember(Name = "collector_user")]
        public string CollectorUser { get; set; }

        [DataMember(Name = "collector_privilege_state")]
        public string CollectorPrivilegeState { get; set; }

        [DataMember(Name = "is_administrator")]
        public bool IsAdministrator { get; set; }

        [DataMember(Name = "backup_privilege_enabled")]
        public bool BackupPrivilegeEnabled { get; set; }

        [DataMember(Name = "backup_privilege_status")]
        public string BackupPrivilegeStatus { get; set; }

        [DataMember(Name = "overall_status")]
        public string OverallStatus { get; set; }

        [DataMember(Name = "completed_steps")]
        public int CompletedSteps { get; set; }

        [DataMember(Name = "partial_steps")]
        public int PartialSteps { get; set; }

        [DataMember(Name = "failed_steps")]
        public int FailedSteps { get; set; }

        [DataMember(Name = "skipped_steps")]
        public int SkippedSteps { get; set; }

        [DataMember(Name = "missing_steps")]
        public int MissingSteps { get; set; }

        /// <summary>Collection mode profile active for this run (Standard, TriageFast, ForensicStrict). Omitted in legacy JSON.</summary>
        [DataMember(Name = "collection_mode_profile")]
        public string CollectionModeProfile { get; set; }

        [DataMember(Name = "steps")]
        public List<CollectionCoverageStep> Steps { get; set; }
    }

    public static class CollectionCoverageSerializer
    {
        public static string Serialize(CollectionCoverageReport report)
        {
            var serializer = new DataContractJsonSerializer(typeof(CollectionCoverageReport));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, report);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static void SaveToFile(CollectionCoverageReport report, string path)
        {
            if (report == null || string.IsNullOrEmpty(path)) return;
            File.WriteAllText(path, Serialize(report), new UTF8Encoding(false));
        }

        public static CollectionCoverageReport LoadFromFile(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var serializer = new DataContractJsonSerializer(typeof(CollectionCoverageReport));
            string json;
            using (var sr = new StreamReader(path, Encoding.UTF8, true))
            {
                json = sr.ReadToEnd();
            }

            if (!string.IsNullOrEmpty(json) && json[0] == '\uFEFF')
                json = json.Substring(1);

            using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json ?? string.Empty)))
            {
                return serializer.ReadObject(ms) as CollectionCoverageReport;
            }
        }
    }
}
