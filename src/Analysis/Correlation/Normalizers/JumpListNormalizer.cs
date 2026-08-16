using System;
using System.Collections.Generic;
using System.Text;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class JumpListNormalizer
    {
        public const string SourceName = "JumpList";

        /// <summary>Neutral action: a destination entry was read from jump_lists.csv (AutomaticDestinations / CustomDestinations).</summary>
        public const string ActionJumpListDestinationObserved = "JumpListDestinationObserved";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeStr = CorrelationCsvHelper.Get(row, "Time");
                string sourceCol = CorrelationCsvHelper.Get(row, "Source");
                string appId = CorrelationCsvHelper.Get(row, "AppId");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string user = CorrelationCsvHelper.Get(row, "User");
                string details = CorrelationCsvHelper.Get(row, "Details");

                if (IsRowEmpty(path, appId, user, sourceCol, details))
                    continue;

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeStr, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, ActionJumpListDestinationObserved);
                bool hasUsableTime = FactTimeMetadata.HasUsableTime(time);
                FactTimeMetadata.Apply(fact,
                    hasUsableTime ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    hasUsableTime ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.JumpListsCsv;
                fact.RawRef = ArtifactNames.JumpListsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(sourceCol, details);

                string parserMode = GetCollectorDetail(details, "Parser");
                string collectorParserNote = GetCollectorDetail(details, "ParserNote");
                bool collectorFallback = string.Equals(GetCollectorDetail(details, "Fallback"), "true",
                    StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrWhiteSpace(parserMode) &&
                     parserMode.IndexOf("Fallback", StringComparison.OrdinalIgnoreCase) >= 0);
                if (collectorFallback)
                {
                    fact.FallbackUsed = true;
                    AppendParserNote(fact, !string.IsNullOrWhiteSpace(collectorParserNote)
                        ? collectorParserNote
                        : "Jump List collector used " + parserMode + ".");
                }

                if (!hasUsableTime)
                {
                    fact.FallbackUsed = true;
                    AppendParserNote(fact, "Jump List row did not expose a usable timestamp in the Time column.");
                }

                if (!string.IsNullOrWhiteSpace(path))
                {
                    fact.AddEntity("Path", path.Trim());
                    UncNetworkEntityHelper.AddFromUncOrUrl(fact, path);
                }
                if (!string.IsNullOrWhiteSpace(user))
                    fact.AddEntity("User", user.Trim());
                if (!string.IsNullOrWhiteSpace(appId))
                    fact.AddEntity("AppId", appId.Trim());

                list.Add(fact);
            }
            return list;
        }

        private static bool IsRowEmpty(params string[] values)
        {
            if (values == null)
                return true;
            foreach (string v in values)
            {
                if (!string.IsNullOrWhiteSpace(v))
                    return false;
            }
            return true;
        }

        private static string BuildDetails(string sourceCol, string details)
        {
            var sb = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(sourceCol))
                sb.Append("JumpListSource=").Append(sourceCol.Trim());
            if (!string.IsNullOrWhiteSpace(details))
            {
                if (sb.Length > 0)
                    sb.Append("; ");
                sb.Append("CollectorDetails=").Append(details.Trim());
            }
            return sb.Length == 0 ? "" : sb.ToString();
        }

        private static string GetCollectorDetail(string details, string key)
        {
            if (string.IsNullOrWhiteSpace(details) || string.IsNullOrWhiteSpace(key))
                return "";
            string marker = key + "=";
            int start = details.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
                return "";
            start += marker.Length;
            int end = details.IndexOf(';', start);
            if (end < 0)
                end = details.Length;
            return details.Substring(start, end - start).Trim();
        }

        private static void AppendParserNote(Fact fact, string note)
        {
            if (fact == null || string.IsNullOrWhiteSpace(note))
                return;
            if (string.IsNullOrWhiteSpace(fact.ParserNote))
                fact.ParserNote = note.Trim();
            else
                fact.ParserNote += " " + note.Trim();
        }
    }
}
