using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IR_Collect
{
    /// <summary>Sidecar metadata for external memory acquisition (collection-only; no analysis).</summary>
    [DataContract]
    public sealed class MemoryAcquisitionRecord
    {
        [DataMember(Name = "schema")]
        public string Schema { get; set; }
        [DataMember(Name = "status")]
        public string Status { get; set; }
        [DataMember(Name = "detail")]
        public string Detail { get; set; }
        [DataMember(Name = "tool_path")]
        public string ToolPath { get; set; }
        [DataMember(Name = "tool_args")]
        public string ToolArgs { get; set; }
        [DataMember(Name = "args_preset")]
        public string ArgsPreset { get; set; }
        [DataMember(Name = "output_relative_path")]
        public string OutputRelativePath { get; set; }
        [DataMember(Name = "started_at_utc")]
        public string StartedAtUtc { get; set; }
        [DataMember(Name = "ended_at_utc")]
        public string EndedAtUtc { get; set; }
        [DataMember(Name = "duration_ms")]
        public long DurationMs { get; set; }
        /// <summary>-1 when not applicable (e.g. timeout before exit).</summary>
        [DataMember(Name = "exit_code")]
        public int ExitCode { get; set; }
        [DataMember(Name = "stdout_tail")]
        public string StdoutTail { get; set; }
        [DataMember(Name = "stderr_tail")]
        public string StderrTail { get; set; }
        [DataMember(Name = "output_file_size_bytes")]
        public long OutputFileSizeBytes { get; set; }
        [DataMember(Name = "output_sha256")]
        public string OutputSha256 { get; set; }
        [DataMember(Name = "collector_user")]
        public string CollectorUser { get; set; }
        [DataMember(Name = "collector_was_admin")]
        public bool CollectorWasAdmin { get; set; }
        [DataMember(Name = "config_requires_admin")]
        public bool ConfigRequiresAdmin { get; set; }
        [DataMember(Name = "config_skip_if_not_elevated")]
        public bool ConfigSkipIfNotElevated { get; set; }
        [DataMember(Name = "timeout_sec_configured")]
        public int TimeoutSecConfigured { get; set; }
        [DataMember(Name = "validation_mode")]
        public string ValidationMode { get; set; }
        [DataMember(Name = "validation_status")]
        public string ValidationStatus { get; set; }
        [DataMember(Name = "validation_detail")]
        public string ValidationDetail { get; set; }
        [DataMember(Name = "diagnostic_category")]
        public string DiagnosticCategory { get; set; }
        [DataMember(Name = "diagnostic_detail")]
        public string DiagnosticDetail { get; set; }
        /// <summary>Audit note: tool args are operator-supplied and not path-validated (only the output placeholder is governed). Null/absent when no tool was invoked.</summary>
        [DataMember(Name = "args_governance_note", EmitDefaultValue = false)]
        public string ArgsGovernanceNote { get; set; }

        public MemoryAcquisitionRecord()
        {
            Schema = "memory_acquisition_v2";
        }

        public static MemoryAcquisitionRecord TryLoad(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            try
            {
                string json;
                using (var sr = new StreamReader(path, Encoding.UTF8, true))
                {
                    json = sr.ReadToEnd();
                }
                if (!string.IsNullOrEmpty(json) && json[0] == '\uFEFF')
                    json = json.Substring(1);
                var serializer = new DataContractJsonSerializer(typeof(MemoryAcquisitionRecord));
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json ?? "")))
                {
                    return serializer.ReadObject(ms) as MemoryAcquisitionRecord;
                }
            }
            catch
            {
                return null;
            }
        }

        public static void SaveToFile(MemoryAcquisitionRecord record, string path)
        {
            if (record == null || string.IsNullOrEmpty(path)) return;
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            var serializer = new DataContractJsonSerializer(typeof(MemoryAcquisitionRecord));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, record);
                File.WriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()), new UTF8Encoding(false));
            }
        }

        public string BuildSummaryLine()
        {
            string st = Status ?? "";
            string det = Detail ?? "";
            if (!string.IsNullOrEmpty(OutputRelativePath))
                det = string.IsNullOrEmpty(det) ? ("output=" + OutputRelativePath) : (det + "; output=" + OutputRelativePath);
            if (!string.IsNullOrEmpty(ArgsPreset))
                det = string.IsNullOrEmpty(det) ? ("preset=" + ArgsPreset) : (det + "; preset=" + ArgsPreset);
            if (OutputFileSizeBytes > 0)
                det = string.IsNullOrEmpty(det) ? ("size=" + OutputFileSizeBytes) : (det + "; size=" + OutputFileSizeBytes);
            if (!string.IsNullOrEmpty(OutputSha256))
                det = string.IsNullOrEmpty(det) ? ("sha256=" + OutputSha256) : (det + "; sha256=" + OutputSha256);
            if (!string.IsNullOrEmpty(ValidationStatus))
                det = string.IsNullOrEmpty(det) ? ("validation=" + ValidationStatus) : (det + "; validation=" + ValidationStatus);
            if (!string.IsNullOrEmpty(DiagnosticCategory) && !string.Equals(DiagnosticCategory, "success", StringComparison.OrdinalIgnoreCase))
                det = string.IsNullOrEmpty(det) ? ("diagnostic=" + DiagnosticCategory) : (det + "; diagnostic=" + DiagnosticCategory);
            return string.IsNullOrEmpty(det) ? st : st + " - " + det;
        }
    }
}
