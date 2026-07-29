using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacNetworkConnectionNormalizer
    {
        public const string SourceName = "UacNetworkConnection";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string observedAt = CorrelationCsvHelper.Get(row, "ObservedAtUtc");
                string collector = CorrelationCsvHelper.Get(row, "Collector");
                string protocol = CorrelationCsvHelper.Get(row, "Protocol");
                string state = CorrelationCsvHelper.Get(row, "State");
                string localAddress = CorrelationCsvHelper.Get(row, "LocalAddress");
                string localPort = CorrelationCsvHelper.Get(row, "LocalPort");
                string remoteAddress = CorrelationCsvHelper.Get(row, "RemoteAddress");
                string remotePort = CorrelationCsvHelper.Get(row, "RemotePort");
                string processId = CorrelationCsvHelper.Get(row, "ProcessId");
                string processName = CorrelationCsvHelper.Get(row, "ProcessName");
                string user = CorrelationCsvHelper.Get(row, "User");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(observedAt, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, InferAction(state, remoteAddress, remotePort));
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacNetworkConnectionsCsv;
                fact.RawRef = ArtifactNames.UacNetworkConnectionsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(collector, protocol, state, localAddress, localPort, remoteAddress, remotePort, details);

                AddEntity(fact, "User", user);
                AddEntity(fact, "ProcessId", processId);
                AddEntity(fact, "FileName", processName);
                AddEntity(fact, "ProcessName", processName);
                AddEntity(fact, "LocalAddress", localAddress);
                AddEntity(fact, "LocalPort", localPort);
                AddEntity(fact, "RemotePort", remotePort);

                AddRemoteEndpointEntities(fact, remoteAddress);

                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "UAC network row did not provide a usable observation timestamp.";
                    fact.FallbackUsed = true;
                }

                list.Add(fact);
            }
            return list;
        }

        private static string InferAction(string state, string remoteAddress, string remotePort)
        {
            string normalizedState = (state ?? "").Trim();
            if (string.Equals(normalizedState, "LISTEN", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(normalizedState, "LISTENING", StringComparison.OrdinalIgnoreCase) ||
                IsWildcardEndpoint(remoteAddress, remotePort))
                return "ListenerObserved";
            return "ConnectionObserved";
        }

        private static string BuildDetails(string collector, string protocol, string state, string localAddress, string localPort, string remoteAddress, string remotePort, string details)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(collector))
                parts.Add("collector=" + collector.Trim());
            if (!string.IsNullOrWhiteSpace(protocol))
                parts.Add("protocol=" + protocol.Trim());
            if (!string.IsNullOrWhiteSpace(state))
                parts.Add("state=" + state.Trim());
            if (!string.IsNullOrWhiteSpace(localAddress) || !string.IsNullOrWhiteSpace(localPort))
                parts.Add("local=" + (localAddress ?? "").Trim() + ":" + (localPort ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(remoteAddress) || !string.IsNullOrWhiteSpace(remotePort))
                parts.Add("remote=" + (remoteAddress ?? "").Trim() + ":" + (remotePort ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(details))
                parts.Add(details.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static void AddRemoteEndpointEntities(Fact fact, string remoteAddress)
        {
            if (fact == null || string.IsNullOrWhiteSpace(remoteAddress))
                return;

            string value = remoteAddress.Trim();
            if (IsWildcardAddress(value))
                return;

            IPAddress address;
            if (IPAddress.TryParse(value, out address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork || address.AddressFamily == AddressFamily.InterNetworkV6)
                    fact.AddEntity("RemoteIP", value);
                return;
            }

            fact.AddEntity("RemoteName", value);
        }

        private static bool IsWildcardEndpoint(string remoteAddress, string remotePort)
        {
            return IsWildcardAddress(remoteAddress) ||
                string.Equals((remotePort ?? "").Trim(), "*", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(remotePort);
        }

        private static bool IsWildcardAddress(string value)
        {
            string normalized = (value ?? "").Trim();
            return normalized.Length == 0 ||
                normalized == "*" ||
                normalized == "0.0.0.0" ||
                normalized == "::" ||
                normalized == ":::" ||
                normalized == "[::]";
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }
    }
}
