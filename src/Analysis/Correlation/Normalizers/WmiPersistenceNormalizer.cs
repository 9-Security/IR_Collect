using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class WmiPersistenceNormalizer
    {
        public const string SourceName = "WmiPersistence";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string className = CorrelationCsvHelper.Get(row, "Class");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string filter = CorrelationCsvHelper.Get(row, "Filter");
                string consumer = CorrelationCsvHelper.Get(row, "Consumer");
                string query = CorrelationCsvHelper.Get(row, "Query");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string details = CorrelationCsvHelper.Get(row, "Details");

                string action = InferAction(className);
                var fact = new Fact(SourceName + "_" + i.ToString(), DateTime.MinValue, SourceName, action);
                FactTimeMetadata.Apply(fact, FactTimeMetadata.UnknownTimeKind, FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.WmiPersistenceCsv;
                fact.RawRef = ArtifactNames.WmiPersistenceCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = string.IsNullOrWhiteSpace(details) ? className : details;

                AddEntity(fact, "WmiClass", className);
                AddEntity(fact, "WmiFilter", filter);
                AddEntity(fact, "WmiConsumer", consumer);
                AddEntity(fact, "TaskName", name);
                AddEntity(fact, "Query", query);
                AddEntity(fact, "Path", path);

                if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(filter) && string.IsNullOrWhiteSpace(consumer))
                {
                    fact.ParserNote = "WMI persistence row did not expose a stable filter or consumer name.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }
            return list;
        }

        private static string InferAction(string className)
        {
            string value = (className ?? "").Trim();
            if (string.Equals(value, "__EventFilter", StringComparison.OrdinalIgnoreCase))
                return "PersistedFilter";
            if (string.Equals(value, "__FilterToConsumerBinding", StringComparison.OrdinalIgnoreCase))
                return "PersistedBinding";
            if (value.IndexOf("Consumer", StringComparison.OrdinalIgnoreCase) >= 0)
                return "PersistedConsumer";
            return "PersistedWmiObject";
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
