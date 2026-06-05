using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class AutorunNormalizer
    {
        public const string SourceName = "Autorun";

        public static List<Fact> ToFacts(string autorunsCsvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(autorunsCsvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string hive = CorrelationCsvHelper.Get(row, "Hive");
                string keyPath = CorrelationCsvHelper.Get(row, "Path");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string value = CorrelationCsvHelper.Get(row, "Value");

                if (string.IsNullOrWhiteSpace(value)) continue;

                string id = "Autorun_" + i;
                var fact = new Fact(id, DateTime.MinValue, SourceName, "Persist");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.InferTimeKind(SourceName, fact.Time), FactTimeMetadata.InferTimeConfidence(SourceName, fact.Time));
                fact.SourceFile = ArtifactNames.AutorunsRegistryCsv;
                fact.RawRef = ArtifactNames.AutorunsRegistryCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.RegistryValueParseLevel;
                fact.Details = value.Length > 500 ? value.Substring(0, 497) + "..." : value;

                fact.AddEntity("RegistryKey", (hive + "\\" + keyPath + "\\" + name).Trim('\\'));
                bool hasPath = value.IndexOf('\\') >= 0 || value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                if (hasPath)
                    fact.AddEntity("Path", value.Trim());
                else
                {
                    fact.ParserNote = "Autorun value did not expose a normalizable executable path; raw registry data is preserved in Details.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }
            return list;
        }
    }
}
