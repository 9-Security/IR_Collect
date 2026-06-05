using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class LogonSessionNormalizer
    {
        public const string SourceName = "LogonSession";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string observedAt = CorrelationCsvHelper.Get(row, "ObservedAtUtc");
                string startTime = CorrelationCsvHelper.Get(row, "StartTime");
                string logonId = CorrelationCsvHelper.Get(row, "LogonId");
                string user = CorrelationCsvHelper.Get(row, "User");
                string domain = CorrelationCsvHelper.Get(row, "Domain");
                string sid = CorrelationCsvHelper.Get(row, "Sid");
                string logonType = CorrelationCsvHelper.Get(row, "LogonType");
                string logonTypeName = CorrelationCsvHelper.Get(row, "LogonTypeName");
                string authPackage = CorrelationCsvHelper.Get(row, "AuthenticationPackage");
                string logonProcess = CorrelationCsvHelper.Get(row, "LogonProcessName");

                DateTime time = CorrelationCsvHelper.ParseDateTime(startTime, DateTime.MinValue);
                string timeKind = FactTimeMetadata.EventTimeKind;
                string confidence = FactTimeMetadata.HighConfidence;
                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    time = CorrelationCsvHelper.ParseDateTime(observedAt, DateTime.MinValue);
                    timeKind = FactTimeMetadata.ObservedTimeKind;
                    confidence = FactTimeMetadata.MediumConfidence;
                }

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, BuildAction(logonType));
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? timeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? confidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.LogonSessionsCsv;
                fact.RawRef = ArtifactNames.LogonSessionsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(logonId, logonTypeName, domain, authPackage, logonProcess, observedAt);

                AddEntity(fact, "User", user);
                AddEntity(fact, "Sid", sid);
                AddEntity(fact, "LogonType", logonType);
                AddEntity(fact, "AuthenticationPackage", authPackage);
                AddEntity(fact, "LogonProcess", logonProcess);

                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "Logon session row did not expose a usable StartTime; observation time was unavailable.";
                    fact.FallbackUsed = true;
                }
                else if (!string.IsNullOrWhiteSpace(observedAt) && string.IsNullOrWhiteSpace(startTime))
                {
                    fact.ParserNote = "Logon session fact uses ObservedAtUtc because StartTime was unavailable.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }

            return list;
        }

        private static string BuildAction(string logonType)
        {
            switch ((logonType ?? "").Trim())
            {
                case "2":
                    return "InteractiveLogonSessionObserved";
                case "3":
                    return "NetworkLogonSessionObserved";
                case "10":
                    return "RemoteInteractiveSessionObserved";
                case "11":
                    return "CachedInteractiveSessionObserved";
                default:
                    return "LogonSessionObserved";
            }
        }

        private static string BuildDetails(string logonId, string logonTypeName, string domain, string authPackage, string logonProcess, string observedAt)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(logonId))
                parts.Add("LogonId=" + logonId.Trim());
            if (!string.IsNullOrWhiteSpace(logonTypeName))
                parts.Add("Type=" + logonTypeName.Trim());
            if (!string.IsNullOrWhiteSpace(domain))
                parts.Add("Domain=" + domain.Trim());
            if (!string.IsNullOrWhiteSpace(authPackage))
                parts.Add("Auth=" + authPackage.Trim());
            if (!string.IsNullOrWhiteSpace(logonProcess))
                parts.Add("Process=" + logonProcess.Trim());
            if (!string.IsNullOrWhiteSpace(observedAt))
                parts.Add("ObservedAtUtc=" + observedAt.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
