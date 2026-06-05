using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ServerConnectionNormalizer
    {
        public const string SourceName = "ServerConnection";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string observedAt = CorrelationCsvHelper.Get(row, "ObservedAtUtc");
                string computerName = CorrelationCsvHelper.Get(row, "ComputerName");
                string user = CorrelationCsvHelper.Get(row, "UserName");
                string shareName = CorrelationCsvHelper.Get(row, "ShareName");
                string activeTime = CorrelationCsvHelper.Get(row, "ActiveTimeSec");
                string idleTime = CorrelationCsvHelper.Get(row, "IdleTimeSec");
                string connectionId = CorrelationCsvHelper.Get(row, "ConnectionId");
                string fileCount = CorrelationCsvHelper.Get(row, "NumberOfFiles");

                DateTime time = CorrelationCsvHelper.ParseDateTime(observedAt, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "ServerShareConnectionObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.ServerConnectionsCsv;
                fact.RawRef = ArtifactNames.ServerConnectionsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(connectionId, activeTime, idleTime, fileCount);

                AddEntity(fact, "User", user);
                AddEntity(fact, "ShareName", shareName);
                if (!string.IsNullOrWhiteSpace(computerName))
                {
                    string host = computerName.Trim();
                    fact.AddEntity("RemoteName", host);
                    if (LooksLikeIPv4(host))
                        fact.AddEntity("RemoteIP", host);
                    else
                        fact.AddEntity("Workstation", host);
                }

                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "Server connection row did not expose ObservedAtUtc.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }
            return list;
        }

        private static string BuildDetails(string connectionId, string activeTime, string idleTime, string fileCount)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(connectionId))
                parts.Add("ConnectionId=" + connectionId.Trim());
            if (!string.IsNullOrWhiteSpace(activeTime))
                parts.Add("ActiveTimeSec=" + activeTime.Trim());
            if (!string.IsNullOrWhiteSpace(idleTime))
                parts.Add("IdleTimeSec=" + idleTime.Trim());
            if (!string.IsNullOrWhiteSpace(fileCount))
                parts.Add("OpenFiles=" + fileCount.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }

        private static bool LooksLikeIPv4(string value)
        {
            IPAddress addr;
            return !string.IsNullOrWhiteSpace(value) &&
                IPAddress.TryParse(value.Trim(), out addr) &&
                addr.AddressFamily == AddressFamily.InterNetwork;
        }
    }
}
