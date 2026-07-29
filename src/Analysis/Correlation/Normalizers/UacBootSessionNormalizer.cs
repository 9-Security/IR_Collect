using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacBootSessionNormalizer
    {
        public const string SourceName = "UacBootSession";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string bootIndex = CorrelationCsvHelper.Get(row, "BootIndex");
                string bootId = CorrelationCsvHelper.Get(row, "BootId");
                string firstEntry = CorrelationCsvHelper.Get(row, "FirstEntry");
                string firstEntryUtc = CorrelationCsvHelper.Get(row, "FirstEntryUtc");
                string lastEntry = CorrelationCsvHelper.Get(row, "LastEntry");
                string lastEntryUtc = CorrelationCsvHelper.Get(row, "LastEntryUtc");
                string parseStatus = CorrelationCsvHelper.Get(row, "TimeParseStatus");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                DateTime time = CorrelationCsvHelper.ParseDateTime(firstEntryUtc, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "BootSessionObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacBootSessionsCsv;
                fact.RawRef = ArtifactNames.UacBootSessionsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "boot_index=" + (bootIndex ?? "") +
                    "; first_entry=" + (firstEntry ?? "") +
                    "; first_entry_utc=" + (firstEntryUtc ?? "") +
                    "; last_entry=" + (lastEntry ?? "") +
                    "; last_entry_utc=" + (lastEntryUtc ?? "") +
                    "; time_parse_status=" + (parseStatus ?? "") +
                    "; source=" + (sourcePath ?? "") +
                    "; source_line=" + (lineNumber ?? "");
                fact.ParserNote = "Boot range comes from journalctl --list-boots; it is not an individual journal event.";
                AddEntity(fact, "BootId", bootId);
                AddEntity(fact, "Path", sourcePath);
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
