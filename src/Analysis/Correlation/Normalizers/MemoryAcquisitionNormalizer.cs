using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class MemoryAcquisitionNormalizer
    {
        public const string SourceName = "MemoryAcquisition";
        public const string ActionOutputObserved = "MemoryDumpArtifactObserved";

        public static List<Fact> ToFacts(string jsonPath)
        {
            var list = new List<Fact>();
            MemoryAcquisitionRecord rec = MemoryAcquisitionRecord.TryLoad(jsonPath);
            if (rec == null)
                return list;

            DateTime time = ParseRecordTime(rec.EndedAtUtc, rec.StartedAtUtc);
            var summary = new Fact(SourceName + "_0", time, SourceName, MapAction(rec.Status));
            ApplyCommonMetadata(summary, ArtifactNames.MemoryAcquisitionJson, time);
            summary.RawRef = ArtifactNames.MemoryAcquisitionJson;
            summary.ParseLevel = FactProvenanceMetadata.SynthesizedParseLevel;
            summary.Details = BuildSummaryDetails(rec);
            summary.ParserNote = "Derived from memory acquisition sidecar metadata; dump contents are not parsed in-app.";
            AddSharedEntities(summary, rec);
            if (!string.IsNullOrWhiteSpace(rec.OutputRelativePath))
                summary.AddEntity("Path", rec.OutputRelativePath.Trim());
            if (!string.IsNullOrWhiteSpace(rec.OutputSha256))
                summary.AddEntity("Hash", rec.OutputSha256.Trim());
            list.Add(summary);

            if (!string.IsNullOrWhiteSpace(rec.OutputRelativePath))
            {
                var output = new Fact(SourceName + "_output_0", time, SourceName, ActionOutputObserved);
                ApplyCommonMetadata(output, ArtifactNames.MemoryAcquisitionJson, time);
                output.RawRef = ArtifactNames.MemoryAcquisitionJson + "#output";
                output.ParseLevel = FactProvenanceMetadata.SynthesizedParseLevel;
                output.Details = BuildOutputDetails(rec);
                output.ParserNote = "Output artifact metadata derived from memory acquisition sidecar; no dump content parsing was performed.";
                output.AddEntity("Path", rec.OutputRelativePath.Trim());
                if (!string.IsNullOrWhiteSpace(rec.OutputSha256))
                    output.AddEntity("Hash", rec.OutputSha256.Trim());
                if (!string.IsNullOrWhiteSpace(rec.CollectorUser))
                    output.AddEntity("User", rec.CollectorUser.Trim());
                list.Add(output);
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

        private static void AddSharedEntities(Fact fact, MemoryAcquisitionRecord rec)
        {
            if (fact == null || rec == null)
                return;

            if (!string.IsNullOrWhiteSpace(rec.CollectorUser))
                fact.AddEntity("User", rec.CollectorUser.Trim());
            if (!string.IsNullOrWhiteSpace(rec.ToolPath))
                fact.AddEntity("ToolPath", rec.ToolPath.Trim());
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
                    return "MemoryAcquisitionComplete";
                case "partial":
                    return "MemoryAcquisitionPartial";
                case "failed":
                    return "MemoryAcquisitionFailed";
                case "skipped":
                    return "MemoryAcquisitionSkipped";
                case "missing":
                    return "MemoryAcquisitionMissing";
                default:
                    return "MemoryAcquisitionObserved";
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

        private static string BuildSummaryDetails(MemoryAcquisitionRecord rec)
        {
            var sb = new StringBuilder();
            AppendPair(sb, "status", rec.Status);
            AppendPair(sb, "detail", rec.Detail);
            AppendPair(sb, "preset", rec.ArgsPreset);
            AppendPair(sb, "validation", rec.ValidationStatus);
            AppendPair(sb, "diagnostic", rec.DiagnosticCategory);
            if (rec.ExitCode != 0)
                AppendPair(sb, "exit_code", rec.ExitCode.ToString());
            if (rec.OutputFileSizeBytes > 0)
                AppendPair(sb, "size_bytes", rec.OutputFileSizeBytes.ToString());
            return sb.ToString();
        }

        private static string BuildOutputDetails(MemoryAcquisitionRecord rec)
        {
            var sb = new StringBuilder();
            AppendPair(sb, "output", rec.OutputRelativePath);
            if (rec.OutputFileSizeBytes > 0)
                AppendPair(sb, "size_bytes", rec.OutputFileSizeBytes.ToString());
            AppendPair(sb, "sha256", rec.OutputSha256);
            AppendPair(sb, "validation", rec.ValidationStatus);
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
