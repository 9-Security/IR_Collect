using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class SrumAppNormalizer
    {
        public const string SourceName = "SRUMApp";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timestamp = CorrelationCsvHelper.Get(row, "Timestamp");
                string appId = CorrelationCsvHelper.Get(row, "AppId");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string user = CorrelationCsvHelper.Get(row, "User");
                string fg = CorrelationCsvHelper.Get(row, "ForegroundCycleTime");
                string bg = CorrelationCsvHelper.Get(row, "BackgroundCycleTime");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");

                if (IsEmpty(appId, path, user, fg, bg, parserNote))
                    continue;

                DateTime time = CorrelationCsvHelper.ParseDateTime(timestamp, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "AppResourceUsageObserved");
                FactTimeMetadata.Apply(
                    fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.SrumAppUsageCsv;
                fact.RawRef = ArtifactNames.SrumAppUsageCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "ForegroundCycleTime=" + (fg ?? "") + "; BackgroundCycleTime=" + (bg ?? "");

                AddEntity(fact, "AppId", appId);
                AddEntity(fact, "Path", path);
                AddEntity(fact, "User", user);

                if (!string.IsNullOrWhiteSpace(parserNote))
                    fact.ParserNote = parserNote;
                if (!FactTimeMetadata.HasUsableTime(time))
                    fact.FallbackUsed = true;
                list.Add(fact);
            }
            return list;
        }

        private static bool IsEmpty(params string[] values)
        {
            if (values == null) return true;
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return false;
            }
            return true;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
