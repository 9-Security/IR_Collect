using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class NetworkResourceNormalizer
    {
        public const string SourceName = "NetworkResource";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string observedAt = CorrelationCsvHelper.Get(row, "ObservedAtUtc");
                string localName = CorrelationCsvHelper.Get(row, "LocalName");
                string remoteName = CorrelationCsvHelper.Get(row, "RemoteName");
                string user = CorrelationCsvHelper.Get(row, "UserName");
                string state = CorrelationCsvHelper.Get(row, "ConnectionState");
                string provider = CorrelationCsvHelper.Get(row, "ProviderName");
                string persistent = CorrelationCsvHelper.Get(row, "Persistent");
                string displayType = CorrelationCsvHelper.Get(row, "DisplayType");
                string comment = CorrelationCsvHelper.Get(row, "Comment");

                DateTime time = CorrelationCsvHelper.ParseDateTime(observedAt, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "NetworkResourceConnectionObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.NetworkResourcesCsv;
                fact.RawRef = ArtifactNames.NetworkResourcesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(localName, state, provider, persistent, displayType, comment);

                AddEntity(fact, "User", user);
                AddEntity(fact, "RemoteName", remoteName);
                AddEntity(fact, "Path", remoteName);
                AddEntity(fact, "Path", localName);
                if (!string.IsNullOrWhiteSpace(remoteName))
                    UncNetworkEntityHelper.AddFromUncOrUrl(fact, remoteName.Trim());

                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "Network resource row did not expose ObservedAtUtc.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }

            return list;
        }

        private static string BuildDetails(string localName, string state, string provider, string persistent, string displayType, string comment)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(localName))
                parts.Add("Local=" + localName.Trim());
            if (!string.IsNullOrWhiteSpace(state))
                parts.Add("State=" + state.Trim());
            if (!string.IsNullOrWhiteSpace(provider))
                parts.Add("Provider=" + provider.Trim());
            if (!string.IsNullOrWhiteSpace(persistent))
                parts.Add("Persistent=" + persistent.Trim());
            if (!string.IsNullOrWhiteSpace(displayType))
                parts.Add("DisplayType=" + displayType.Trim());
            if (!string.IsNullOrWhiteSpace(comment))
                parts.Add("Comment=" + comment.Trim());
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
