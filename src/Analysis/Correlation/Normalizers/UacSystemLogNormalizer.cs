using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacSystemLogNormalizer
    {
        public const string SourceName = "UacSystemLog";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string rawTime = CorrelationCsvHelper.Get(row, "Time");
                string timeUtc = CorrelationCsvHelper.Get(row, "TimeUtc");
                string parseStatus = CorrelationCsvHelper.Get(row, "TimeParseStatus");
                string host = CorrelationCsvHelper.Get(row, "Host");
                string facility = CorrelationCsvHelper.Get(row, "Facility");
                string severity = CorrelationCsvHelper.Get(row, "Severity");
                string program = CorrelationCsvHelper.Get(row, "Program");
                string processId = CorrelationCsvHelper.Get(row, "ProcessId");
                string messageId = CorrelationCsvHelper.Get(row, "MessageId");
                string message = CorrelationCsvHelper.Get(row, "Message");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeUtc, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time,
                    SourceName, "SystemLogMessageObserved");
                bool hasTime = FactTimeMetadata.HasUsableTime(time);
                FactTimeMetadata.Apply(fact,
                    hasTime ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    hasTime ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacSystemLogEventsCsv;
                fact.RawRef = ArtifactNames.UacSystemLogEventsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(rawTime, timeUtc, parseStatus, facility,
                    severity, messageId, sourcePath, lineNumber, message, details);

                AddEntity(fact, "Computer", host);
                AddEntity(fact, "ProgramName", program);
                AddEntity(fact, "ProcessId", processId);
                AddEntity(fact, "Path", sourcePath);

                if (!hasTime)
                {
                    fact.ParserNote = "The system-log timestamp did not include enough year/timezone information for reliable UTC conversion; raw time was preserved and no UTC value was invented. The fact records only a message observation and does not independently prove success or maliciousness.";
                    fact.FallbackUsed = true;
                }
                else
                {
                    fact.ParserNote = "The fact records a parsed system-log message and does not independently prove that the described activity succeeded or was malicious.";
                }
                facts.Add(fact);
            }
            return facts;
        }

        private static string BuildDetails(string rawTime, string timeUtc,
            string parseStatus, string facility, string severity, string messageId,
            string sourcePath, string lineNumber, string message, string details)
        {
            var parts = new List<string>();
            AddPart(parts, "time", rawTime);
            AddPart(parts, "time_utc", timeUtc);
            AddPart(parts, "time_parse_status", parseStatus);
            AddPart(parts, "facility", facility);
            AddPart(parts, "severity", severity);
            AddPart(parts, "message_id", messageId);
            AddPart(parts, "source", sourcePath);
            AddPart(parts, "source_line", lineNumber);
            AddPart(parts, "message", message);
            if (!string.IsNullOrWhiteSpace(details))
                parts.Add(details.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static void AddPart(List<string> parts, string name, string value)
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
