using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacLoginEventNormalizer
    {
        public const string SourceName = "UacLoginEvent";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string time = CorrelationCsvHelper.Get(row, "Time");
                string timeUtc = CorrelationCsvHelper.Get(row, "TimeUtc");
                string endTime = CorrelationCsvHelper.Get(row, "EndTime");
                string endTimeUtc = CorrelationCsvHelper.Get(row, "EndTimeUtc");
                string parseStatus = CorrelationCsvHelper.Get(row, "TimeParseStatus");
                string action = CorrelationCsvHelper.Get(row, "Action");
                string user = CorrelationCsvHelper.Get(row, "User");
                string terminal = CorrelationCsvHelper.Get(row, "Terminal");
                string remoteHost = CorrelationCsvHelper.Get(row, "RemoteHost");
                string remoteAddress = CorrelationCsvHelper.Get(row, "RemoteAddress");
                string processId = CorrelationCsvHelper.Get(row, "ProcessId");
                string recordId = CorrelationCsvHelper.Get(row, "RecordId");
                string duration = CorrelationCsvHelper.Get(row, "Duration");
                string sourceType = CorrelationCsvHelper.Get(row, "SourceType");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime parsedTime = CorrelationCsvHelper.ParseDateTime(timeUtc, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), parsedTime, SourceName,
                    string.IsNullOrWhiteSpace(action) ? "LoginRecordObserved" : action.Trim());
                bool hasTime = FactTimeMetadata.HasUsableTime(parsedTime);
                FactTimeMetadata.Apply(fact,
                    hasTime ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    hasTime ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacLoginEventsCsv;
                fact.RawRef = ArtifactNames.UacLoginEventsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(time, timeUtc, endTime, endTimeUtc, parseStatus,
                    duration, sourceType, sourcePath, lineNumber, details);

                AddEntity(fact, "User", user);
                AddEntity(fact, "Terminal", terminal);
                AddEntity(fact, "RemoteName", remoteHost);
                AddEntity(fact, "RemoteIP", remoteAddress);
                AddEntity(fact, "ProcessId", processId);
                AddEntity(fact, "SessionRecordId", recordId);
                AddEntity(fact, "Path", sourcePath);

                if (!hasTime)
                {
                    fact.ParserNote = "The source supplied a local or unparseable timestamp without a reliable UTC offset; raw time was preserved and no UTC value was invented.";
                    fact.FallbackUsed = true;
                }
                else
                {
                    fact.ParserNote = "Login record was normalized from UAC command output; it does not independently prove interactive activity or authentication success beyond the source record semantics.";
                }
                facts.Add(fact);
            }
            return facts;
        }

        private static string BuildDetails(string time, string timeUtc, string endTime,
            string endTimeUtc, string parseStatus, string duration, string sourceType,
            string sourcePath, string lineNumber, string details)
        {
            var parts = new List<string>();
            AddPart(parts, "time", time);
            AddPart(parts, "time_utc", timeUtc);
            AddPart(parts, "end_time", endTime);
            AddPart(parts, "end_time_utc", endTimeUtc);
            AddPart(parts, "time_parse_status", parseStatus);
            AddPart(parts, "duration", duration);
            AddPart(parts, "source_type", sourceType);
            AddPart(parts, "source", sourcePath);
            AddPart(parts, "source_line", lineNumber);
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
