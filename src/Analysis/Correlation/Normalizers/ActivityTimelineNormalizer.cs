using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ActivityTimelineNormalizer
    {
        public const string SourceName = "ActivityTimeline";

        /// <summary>
        /// activity_timeline.csv 格式: Time,Source,Action,Path,User,Details
        /// 已為扁平化多來源，這裡只轉成 Fact 並保留原始 Source 當作子來源標記。
        /// </summary>
        public static List<Fact> ToFacts(string activityTimelineCsvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(activityTimelineCsvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeStr = CorrelationCsvHelper.Get(row, "Time");
                string source = CorrelationCsvHelper.Get(row, "Source");
                string action = CorrelationCsvHelper.Get(row, "Action");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string user = CorrelationCsvHelper.Get(row, "User");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeStr, DateTime.MinValue);
                string id = "Activity_" + i;
                var fact = new Fact(id, time, string.IsNullOrWhiteSpace(source) ? SourceName : source, action ?? "Activity");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.InferTimeKind(fact.Source, time), FactTimeMetadata.InferTimeConfidence(fact.Source, time));
                fact.SourceFile = ArtifactNames.ActivityTimelineCsv;
                fact.RawRef = ArtifactNames.ActivityTimelineCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.SynthesizedParseLevel;
                fact.Details = details;
                if (!string.IsNullOrEmpty(fact.Details) && fact.Details.Length > 500) fact.Details = fact.Details.Substring(0, 497) + "...";
                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "Activity timeline row did not provide a usable timestamp.";
                    fact.FallbackUsed = true;
                }

                if (!string.IsNullOrWhiteSpace(path))
                    fact.AddEntity("Path", path.Trim());
                if (!string.IsNullOrWhiteSpace(user))
                    fact.AddEntity("User", user.Trim());

                list.Add(fact);
            }
            return list;
        }
    }
}
