using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class SrumNetworkNormalizer
    {
        public const string SourceName = "SRUMNetwork";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timestamp = CorrelationCsvHelper.Get(row, "Timestamp");
                string appId = CorrelationCsvHelper.Get(row, "AppId");
                string path = CorrelationCsvHelper.Get(row, "Path");
                string user = CorrelationCsvHelper.Get(row, "User");
                string remoteIp = CorrelationCsvHelper.Get(row, "RemoteIP");
                string iface = CorrelationCsvHelper.Get(row, "Interface");
                string bytesSent = CorrelationCsvHelper.Get(row, "BytesSent");
                string bytesRecv = CorrelationCsvHelper.Get(row, "BytesReceived");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");

                if (IsEmpty(appId, path, user, remoteIp, iface, parserNote))
                    continue;

                DateTime time = CorrelationCsvHelper.ParseDateTime(timestamp, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "NetworkUsageObserved");
                FactTimeMetadata.Apply(
                    fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.SrumNetworkUsageCsv;
                fact.RawRef = ArtifactNames.SrumNetworkUsageCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "BytesSent=" + (bytesSent ?? "") + "; BytesReceived=" + (bytesRecv ?? "");

                AddEntity(fact, "AppId", appId);
                AddEntity(fact, "Path", path);
                AddEntity(fact, "User", user);
                AddEntity(fact, "RemoteIP", remoteIp);
                AddEntity(fact, "Interface", iface);

                if (!string.IsNullOrWhiteSpace(parserNote))
                    fact.ParserNote = parserNote;
                if (!FactTimeMetadata.HasUsableTime(time))
                    fact.FallbackUsed = true;
                list.Add(fact);
            }
            return list;
        }

        private static bool IsEmpty(params string[] values)
        {
            if (values == null) return true;
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return false;
            }
            return true;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
