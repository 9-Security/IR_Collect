using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacFileHashNormalizer
    {
        public const string SourceName = "UacFileHash";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            List<Dictionary<string, string>> rows =
                CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                Dictionary<string, string> row = rows[i];
                string algorithm = CorrelationCsvHelper.Get(row, "Algorithm");
                string hash = CorrelationCsvHelper.Get(row, "Hash");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string sourceKind = CorrelationCsvHelper.Get(row, "SourceKind");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string inputFormat = CorrelationCsvHelper.Get(row, "InputFormat");

                var fact = new Fact(SourceName + "_" + i.ToString(),
                    DateTime.MinValue, SourceName, "FileHashObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacFileHashesCsv;
                fact.RawRef = ArtifactNames.UacFileHashesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(algorithm, hash, path, sourceKind,
                    sourcePath, lineNumber, inputFormat);
                fact.ParserNote = "The UAC hash collector recorded a file path and digest without a reliable row timestamp. This is an untimed integrity observation and does not imply maliciousness.";
                fact.FallbackUsed = true;

                AddEntity(fact, "Hash", hash);
                AddEntity(fact, "Path", path);
                AddEntity(fact, "HashAlgorithm", algorithm);
                facts.Add(fact);
            }
            return facts;
        }

        private static string BuildDetails(string algorithm, string hash,
            string path, string sourceKind, string sourcePath,
            string lineNumber, string inputFormat)
        {
            var parts = new List<string>();
            AddPart(parts, "algorithm", algorithm);
            AddPart(parts, "hash", hash);
            AddPart(parts, "path", path);
            AddPart(parts, "source_kind", sourceKind);
            AddPart(parts, "source", sourcePath);
            AddPart(parts, "source_line", lineNumber);
            AddPart(parts, "input_format", inputFormat);
            return string.Join("; ", parts.ToArray());
        }

        private static void AddPart(List<string> parts, string name,
            string value)
        {
            if (!string.IsNullOrWhiteSpace(value))
                parts.Add(name + "=" + value.Trim());
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact != null && !string.IsNullOrWhiteSpace(value))
                fact.AddEntity(type, value.Trim());
        }
    }
}
