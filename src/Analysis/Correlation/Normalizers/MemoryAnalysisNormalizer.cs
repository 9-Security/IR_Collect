using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class MemoryAnalysisNormalizer
    {
        public const string SourceName = "MemoryAnalysis";
        public const string ActionOutputObserved = "MemoryAnalysisOutputObserved";

        public static List<Fact> ToFacts(string jsonPath)
        {
            var list = new List<Fact>();
            MemoryAnalysisRecord rec = MemoryAnalysisRecord.TryLoad(jsonPath);
            if (rec == null)
                return list;

            DateTime time = ParseRecordTime(rec.EndedAtUtc, rec.StartedAtUtc);
            var summary = new Fact(SourceName + "_0", time, SourceName, MapAction(rec.Status));
            ApplyCommonMetadata(summary, ArtifactNames.MemoryAnalysisJson, time);
            summary.RawRef = ArtifactNames.MemoryAnalysisJson;
            summary.ParseLevel = FactProvenanceMetadata.SynthesizedParseLevel;
            summary.Details = BuildSummaryDetails(rec);
            summary.ParserNote = "Derived from memory analysis handoff sidecar metadata; generated outputs remain external-tool artifacts.";
            AddSharedEntities(summary, rec);
            list.Add(summary);

            if (rec.OutputFiles != null)
            {
                int outputIndex = 0;
                for (int i = 0; i < rec.OutputFiles.Count; i++)
                {
                    string rel = rec.OutputFiles[i];
                    if (string.IsNullOrWhiteSpace(rel))
                        continue;

                    var output = new Fact(SourceName + "_output_" + outputIndex.ToString(), time, SourceName, ActionOutputObserved);
                    ApplyCommonMetadata(output, ArtifactNames.MemoryAnalysisJson, time);
                    output.RawRef = ArtifactNames.MemoryAnalysisJson + "#output:" + outputIndex.ToString();
                    output.ParseLevel = FactProvenanceMetadata.SynthesizedParseLevel;
                    output.Details = BuildOutputDetails(rec, rel);
                    output.ParserNote = "Output artifact metadata derived from memory analysis handoff sidecar; file contents are not interpreted as in-app verdicts.";
                    output.AddEntity("Path", rel.Trim());
                    if (!string.IsNullOrWhiteSpace(rec.InputRelativePath))
                        output.AddEntity("InputPath", rec.InputRelativePath.Trim());
                    if (!string.IsNullOrWhiteSpace(rec.CollectorUser))
                        output.AddEntity("User", rec.CollectorUser.Trim());
                    list.Add(output);
                    outputIndex++;
                }
            }

            return list;
        }

        private static void ApplyCommonMetadata(Fact fact, string sourceFile, DateTime time)
        {
            if (fact == null)
                return;

            bool hasUsableTime = FactTimeMetadata.HasUsableTime(time);
            FactTimeMetadata.Apply(fact,
                hasUsableTime ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind,
                hasUsableTime ? FactTimeMetadata.HighConfidence : FactTimeMetadata.LowConfidence);
            fact.SourceFile = sourceFile;
            fact.FallbackUsed = !hasUsableTime;
        }

        private static void AddSharedEntities(Fact fact, MemoryAnalysisRecord rec)
        {
            if (fact == null || rec == null)
                return;

            if (!string.IsNullOrWhiteSpace(rec.CollectorUser))
                fact.AddEntity("User", rec.CollectorUser.Trim());
            if (!string.IsNullOrWhiteSpace(rec.ToolPath))
                fact.AddEntity("ToolPath", rec.ToolPath.Trim());
            if (!string.IsNullOrWhiteSpace(rec.InputRelativePath))
                fact.AddEntity("InputPath", rec.InputRelativePath.Trim());
            if (!string.IsNullOrWhiteSpace(rec.OutputDirectoryRelativePath))
                fact.AddEntity("Path", rec.OutputDirectoryRelativePath.Trim());
            if (!string.IsNullOrWhiteSpace(rec.DiagnosticCategory))
                fact.AddEntity("DiagnosticCategory", rec.DiagnosticCategory.Trim());
            if (!string.IsNullOrWhiteSpace(rec.ValidationStatus))
                fact.AddEntity("ValidationStatus", rec.ValidationStatus.Trim());
        }

        private static string MapAction(string status)
        {
            switch ((status ?? "").Trim().ToLowerInvariant())
            {
                case "complete":
                    return "MemoryAnalysisComplete";
                case "partial":
                    return "MemoryAnalysisPartial";
                case "failed":
                    return "MemoryAnalysisFailed";
                case "skipped":
                    return "MemoryAnalysisSkipped";
                case "missing":
                    return "MemoryAnalysisMissing";
                default:
                    return "MemoryAnalysisObserved";
            }
        }

        private static DateTime ParseRecordTime(string preferred, string fallback)
        {
            DateTime time;
            if (DateTime.TryParse(preferred, null, DateTimeStyles.RoundtripKind, out time))
                return time;
            if (DateTime.TryParse(fallback, null, DateTimeStyles.RoundtripKind, out time))
                return time;
            return DateTime.MinValue;
        }

        private static string BuildSummaryDetails(MemoryAnalysisRecord rec)
        {
            var sb = new StringBuilder();
            AppendPair(sb, "status", rec.Status);
            AppendPair(sb, "detail", rec.Detail);
            AppendPair(sb, "preset", rec.ArgsPreset);
            AppendPair(sb, "validation", rec.ValidationStatus);
            AppendPair(sb, "diagnostic", rec.DiagnosticCategory);
            AppendPair(sb, "output_dir", rec.OutputDirectoryRelativePath);
            if (rec.OutputFileCount > 0)
                AppendPair(sb, "output_files", rec.OutputFileCount.ToString());
            if (rec.OutputTotalBytes > 0)
                AppendPair(sb, "output_bytes", rec.OutputTotalBytes.ToString());
            return sb.ToString();
        }

        private static string BuildOutputDetails(MemoryAnalysisRecord rec, string rel)
        {
            var sb = new StringBuilder();
            AppendPair(sb, "output", rel);
            AppendPair(sb, "input", rec.InputRelativePath);
            AppendPair(sb, "validation", rec.ValidationStatus);
            if (rec.MissingOutputPatterns != null && rec.MissingOutputPatterns.Count > 0)
                AppendPair(sb, "missing_patterns", string.Join(", ", rec.MissingOutputPatterns.ToArray()));
            return sb.ToString();
        }

        private static void AppendPair(StringBuilder sb, string key, string value)
        {
            if (sb == null || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                return;
            if (sb.Length > 0)
                sb.Append("; ");
            sb.Append(key).Append('=').Append(value.Trim());
        }
    }
}
