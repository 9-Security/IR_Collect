using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacShellHistoryNormalizer
    {
        public const string SourceName = "UacShellHistory";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeText = CorrelationCsvHelper.Get(row, "TimeUtc");
                string user = CorrelationCsvHelper.Get(row, "User");
                string shell = CorrelationCsvHelper.Get(row, "Shell");
                string commandLine = CorrelationCsvHelper.Get(row, "CommandLine");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");
                DateTime time = CorrelationCsvHelper.ParseDateTime(timeText, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "ShellCommandRecorded");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacShellHistoryCsv;
                fact.RawRef = ArtifactNames.UacShellHistoryCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "shell=" + (shell ?? "") + "; source=" + (sourcePath ?? "") +
                    "; source_line=" + (lineNumber ?? "") + (string.IsNullOrWhiteSpace(details) ? "" : "; " + details.Trim());
                fact.ParserNote = "Shell history records a command string; it does not by itself prove successful execution.";
                AddEntity(fact, "User", user);
                AddEntity(fact, "CommandLine", commandLine);
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
