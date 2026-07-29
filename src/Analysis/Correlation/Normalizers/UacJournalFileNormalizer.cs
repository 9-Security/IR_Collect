using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacJournalFileNormalizer
    {
        public const string SourceName = "UacJournalFile";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string state = CorrelationCsvHelper.Get(row, "State");
                string fileId = CorrelationCsvHelper.Get(row, "FileId");
                string machineId = CorrelationCsvHelper.Get(row, "MachineId");
                string bootId = CorrelationCsvHelper.Get(row, "TailBootId");
                string entryCount = CorrelationCsvHelper.Get(row, "EntryCount");
                string headTimeText = CorrelationCsvHelper.Get(row, "HeadEntryTimeUtc");
                string tailTimeText = CorrelationCsvHelper.Get(row, "TailEntryTimeUtc");
                string compatible = CorrelationCsvHelper.Get(row, "CompatibleFeatures");
                string incompatible = CorrelationCsvHelper.Get(row, "IncompatibleFeatures");
                string parseStatus = CorrelationCsvHelper.Get(row, "ParseStatus");
                string details = CorrelationCsvHelper.Get(row, "Details");
                DateTime time = CorrelationCsvHelper.ParseDateTime(headTimeText, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "JournalFileObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacJournalFilesCsv;
                fact.RawRef = ArtifactNames.UacJournalFilesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.MetadataDerivedParseLevel;
                fact.Details = "state=" + (state ?? "") +
                    "; entries=" + (entryCount ?? "") +
                    "; first_entry=" + (headTimeText ?? "") +
                    "; last_entry=" + (tailTimeText ?? "") +
                    "; compatible_features=" + (compatible ?? "") +
                    "; incompatible_features=" + (incompatible ?? "") +
                    "; parse_status=" + (parseStatus ?? "") +
                    (string.IsNullOrWhiteSpace(details) ? "" : "; " + details.Trim());
                fact.ParserNote = "Only the native journal file header was parsed; individual journal entries remain raw evidence.";
                AddEntity(fact, "Path", sourcePath);
                AddEntity(fact, "JournalFileId", fileId);
                AddEntity(fact, "MachineId", machineId);
                AddEntity(fact, "BootId", bootId);
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
