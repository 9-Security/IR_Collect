using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacEvidenceIndexNormalizer
    {
        public const string SourceName = "UacEvidence";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeText = CorrelationCsvHelper.Get(row, "ModifiedTimeUtc");
                string relativePath = CorrelationCsvHelper.Get(row, "RelativePath");
                string size = CorrelationCsvHelper.Get(row, "SizeBytes");
                string sha256 = CorrelationCsvHelper.Get(row, "Sha256");
                string category = CorrelationCsvHelper.Get(row, "Category");
                string status = CorrelationCsvHelper.Get(row, "AnalysisStatus");
                DateTime time = CorrelationCsvHelper.ParseDateTime(timeText, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "EvidenceFileIndexed");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacEvidenceIndexCsv;
                fact.RawRef = ArtifactNames.UacEvidenceIndexCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.MetadataDerivedParseLevel;
                fact.Details = "category=" + (category ?? "") + "; analysis_status=" + (status ?? "") + "; size_bytes=" + (size ?? "");
                AddEntity(fact, "Path", relativePath);
                AddEntity(fact, "Hash", sha256);
                AddEntity(fact, "ArtifactCategory", category);
                facts.Add(fact);
            }
            return facts;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact != null && !string.IsNullOrWhiteSpace(value))
                fact.AddEntity(type, value.Trim());
        }
    }
}
