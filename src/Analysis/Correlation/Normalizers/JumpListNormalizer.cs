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

                if (!hasUsableTime)
                {
                    fact.FallbackUsed = true;
                    fact.ParserNote = "Jump List row did not expose a usable timestamp in the Time column.";
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
    }
}
