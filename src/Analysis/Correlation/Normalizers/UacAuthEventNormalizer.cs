using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacAuthEventNormalizer
    {
        public const string SourceName = "UacAuth";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeText = CorrelationCsvHelper.Get(row, "Time");
                string subSource = CorrelationCsvHelper.Get(row, "Source");
                string action = CorrelationCsvHelper.Get(row, "Action");
                string user = CorrelationCsvHelper.Get(row, "User");
                string targetUser = CorrelationCsvHelper.Get(row, "TargetUser");
                string remoteIp = CorrelationCsvHelper.Get(row, "RemoteIP");
                string remoteName = CorrelationCsvHelper.Get(row, "RemoteName");
                string terminal = CorrelationCsvHelper.Get(row, "Terminal");
                string commandLine = CorrelationCsvHelper.Get(row, "CommandLine");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeText, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, string.IsNullOrWhiteSpace(action) ? "AuthEventObserved" : action.Trim());
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacAuthEventsCsv;
                fact.RawRef = ArtifactNames.UacAuthEventsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(subSource, details, commandLine);

                AddEntity(fact, "User", user);
                AddEntity(fact, "TargetUser", targetUser);
                AddEntity(fact, "RemoteIP", remoteIp);
                AddEntity(fact, "RemoteName", remoteName);
                AddEntity(fact, "Terminal", terminal);
                AddEntity(fact, "CommandLine", commandLine);

                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "UAC auth row did not provide a usable timestamp.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }

            return list;
        }

        private static string BuildDetails(string subSource, string details, string commandLine)
        {
            string text = details ?? "";
            if (!string.IsNullOrWhiteSpace(commandLine))
            {
                if (text.Length > 0) text += " | ";
                text += "command=" + commandLine.Trim();
            }
            if (!string.IsNullOrWhiteSpace(subSource))
            {
                if (text.Length > 0) text += " | ";
                text += "source=" + subSource.Trim();
            }
            return text;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
