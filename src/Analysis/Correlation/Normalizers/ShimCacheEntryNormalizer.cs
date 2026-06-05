using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ShimCacheEntryNormalizer
    {
        public const string SourceName = "ShimCache";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string path = CorrelationCsvHelper.Get(row, "Path");
                string fileName = CorrelationCsvHelper.Get(row, "FileName");
                string lastModified = CorrelationCsvHelper.Get(row, "LastModifiedTime");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");
                string valueName = CorrelationCsvHelper.Get(row, "ValueName");
                string hashPrefix = CorrelationCsvHelper.Get(row, "DataHashPrefix");

                if (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(fileName) && string.IsNullOrWhiteSpace(parserNote))
                    continue;

                DateTime time = CorrelationCsvHelper.ParseDateTime(lastModified, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "ExecutedCandidate");
                FactTimeMetadata.Apply(
                    fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.LowConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.ShimCacheEntriesCsv;
                fact.RawRef = ArtifactNames.ShimCacheEntriesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.RawArtifactDerivedParseLevel;
                fact.Details = "ValueName=" + (valueName ?? "") + "; DataHashPrefix=" + (hashPrefix ?? "");
                AddEntity(fact, "Path", path);
                AddEntity(fact, "FileName", fileName);
                if (!string.IsNullOrWhiteSpace(parserNote))
                    fact.ParserNote = parserNote;
                if (!FactTimeMetadata.HasUsableTime(time))
                    fact.FallbackUsed = true;
                list.Add(fact);
            }
            return list;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
