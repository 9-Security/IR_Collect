using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class BamDamNormalizer
    {
        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string source = CorrelationCsvHelper.Get(row, "Source");
                string user = CorrelationCsvHelper.Get(row, "User");
                string registryPath = CorrelationCsvHelper.Get(row, "RegistryPath");
                string valueName = CorrelationCsvHelper.Get(row, "ValueName");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string timeStr = CorrelationCsvHelper.Get(row, "LastExecutionTime");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeStr, DateTime.MinValue);
                string normalizedSource = string.IsNullOrWhiteSpace(source) ? "BAM" : source.Trim();
                var fact = new Fact(normalizedSource + "_" + i.ToString(), time, normalizedSource, "Executed");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.MetadataTimeKind, FactTimeMetadata.MediumConfidence);
                fact.SourceFile = ArtifactNames.BamDamCsv;
                fact.RawRef = ArtifactNames.BamDamCsv + ":" + (i + 2);
                fact.Details = string.IsNullOrWhiteSpace(details) ? valueName : details;
                fact.ParseLevel = FactProvenanceMetadata.RegistryValueParseLevel;

                if (!string.IsNullOrWhiteSpace(path))
                    fact.AddEntity("Path", path.Trim());
                if (!string.IsNullOrWhiteSpace(user))
                    fact.AddEntity("User", user.Trim());
                if (!string.IsNullOrWhiteSpace(registryPath))
                    fact.AddEntity("RegistryKey", registryPath.Trim());
                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = normalizedSource + " row did not expose a usable execution timestamp.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }
            return list;
        }
    }
}
