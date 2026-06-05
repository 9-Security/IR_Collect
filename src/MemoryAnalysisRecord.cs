using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IR_Collect
{
    /// <summary>Sidecar metadata for external memory analysis handoff. No in-app memory verdicts are produced.</summary>
    [DataContract]
    public sealed class MemoryAnalysisRecord
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
        [DataMember(Name = "input_relative_path")]
        public string InputRelativePath { get; set; }
        [DataMember(Name = "output_directory_relative_path")]
        public string OutputDirectoryRelativePath { get; set; }
        [DataMember(Name = "output_files")]
        public List<string> OutputFiles { get; set; }
        [DataMember(Name = "output_file_count")]
        public int OutputFileCount { get; set; }
        [DataMember(Name = "output_total_bytes")]
        public long OutputTotalBytes { get; set; }
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
        [DataMember(Name = "collector_user")]
        public string CollectorUser { get; set; }
        [DataMember(Name = "collector_was_admin")]
        public bool CollectorWasAdmin { get; set; }
        [DataMember(Name = "timeout_sec_configured")]
        public int TimeoutSecConfigured { get; set; }
        [DataMember(Name = "validation_mode")]
        public string ValidationMode { get; set; }
        [DataMember(Name = "validation_status")]
        public string ValidationStatus { get; set; }
        [DataMember(Name = "validation_detail")]
        public string ValidationDetail { get; set; }
        [DataMember(Name = "required_output_patterns")]
        public List<string> RequiredOutputPatterns { get; set; }
        [DataMember(Name = "matched_output_patterns")]
        public List<string> MatchedOutputPatterns { get; set; }
        [DataMember(Name = "missing_output_patterns")]
        public List<string> MissingOutputPatterns { get; set; }
        [DataMember(Name = "diagnostic_category")]
        public string DiagnosticCategory { get; set; }
        [DataMember(Name = "diagnostic_detail")]
        public string DiagnosticDetail { get; set; }
        /// <summary>Audit note: tool args are operator-supplied and not path-validated (only the output placeholder is governed). Null/absent when no tool was invoked.</summary>
        [DataMember(Name = "args_governance_note", EmitDefaultValue = false)]
        public string ArgsGovernanceNote { get; set; }

        public MemoryAnalysisRecord()
        {
            Schema = "memory_analysis_v2";
            OutputFiles = new List<string>();
            RequiredOutputPatterns = new List<string>();
            MatchedOutputPatterns = new List<string>();
            MissingOutputPatterns = new List<string>();
        }

        public static MemoryAnalysisRecord TryLoad(string path)
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
                var serializer = new DataContractJsonSerializer(typeof(MemoryAnalysisRecord));
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json ?? "")))
                {
                    return serializer.ReadObject(ms) as MemoryAnalysisRecord;
                }
            }
            catch
            {
                return null;
            }
        }

        public static void SaveToFile(MemoryAnalysisRecord record, string path)
        {
            if (record == null || string.IsNullOrEmpty(path)) return;
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            var serializer = new DataContractJsonSerializer(typeof(MemoryAnalysisRecord));
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
            if (!string.IsNullOrEmpty(InputRelativePath))
                det = string.IsNullOrEmpty(det) ? ("input=" + InputRelativePath) : (det + "; input=" + InputRelativePath);
            if (!string.IsNullOrEmpty(OutputDirectoryRelativePath))
                det = string.IsNullOrEmpty(det) ? ("output_dir=" + OutputDirectoryRelativePath) : (det + "; output_dir=" + OutputDirectoryRelativePath);
            if (!string.IsNullOrEmpty(ArgsPreset))
                det = string.IsNullOrEmpty(det) ? ("preset=" + ArgsPreset) : (det + "; preset=" + ArgsPreset);
            if (OutputFileCount > 0)
                det = string.IsNullOrEmpty(det) ? ("files=" + OutputFileCount) : (det + "; files=" + OutputFileCount);
            if (OutputTotalBytes > 0)
                det = string.IsNullOrEmpty(det) ? ("bytes=" + OutputTotalBytes) : (det + "; bytes=" + OutputTotalBytes);
            if (!string.IsNullOrEmpty(ValidationStatus))
                det = string.IsNullOrEmpty(det) ? ("validation=" + ValidationStatus) : (det + "; validation=" + ValidationStatus);
            if (!string.IsNullOrEmpty(DiagnosticCategory) && !string.Equals(DiagnosticCategory, "success", StringComparison.OrdinalIgnoreCase))
                det = string.IsNullOrEmpty(det) ? ("diagnostic=" + DiagnosticCategory) : (det + "; diagnostic=" + DiagnosticCategory);
            return string.IsNullOrEmpty(det) ? st : st + " - " + det;
        }
    }
}
