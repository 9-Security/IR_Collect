using System;
using System.Collections.Generic;
using System.Net;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacWebServerEventNormalizer
    {
        public const string SourceName = "UacWebServer";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string rawTime = CorrelationCsvHelper.Get(row, "Time");
                string timeUtc = CorrelationCsvHelper.Get(row, "TimeUtc");
                string timeParseStatus = CorrelationCsvHelper.Get(row,
                    "TimeParseStatus");
                string serverType = CorrelationCsvHelper.Get(row, "ServerType");
                string eventType = CorrelationCsvHelper.Get(row, "EventType");
                string remoteAddress = CorrelationCsvHelper.Get(row,
                    "RemoteAddress");
                string remotePort = CorrelationCsvHelper.Get(row, "RemotePort");
                string user = CorrelationCsvHelper.Get(row, "User");
                string virtualHost = CorrelationCsvHelper.Get(row, "VirtualHost");
                string method = CorrelationCsvHelper.Get(row, "Method");
                string requestTarget = CorrelationCsvHelper.Get(row,
                    "RequestTarget");
                string protocol = CorrelationCsvHelper.Get(row, "Protocol");
                string statusCode = CorrelationCsvHelper.Get(row, "StatusCode");
                string responseBytes = CorrelationCsvHelper.Get(row,
                    "ResponseBytes");
                string referrer = CorrelationCsvHelper.Get(row, "Referrer");
                string userAgent = CorrelationCsvHelper.Get(row, "UserAgent");
                string severity = CorrelationCsvHelper.Get(row, "Severity");
                string processId = CorrelationCsvHelper.Get(row, "ProcessId");
                string message = CorrelationCsvHelper.Get(row, "Message");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeUtc,
                    DateTime.MinValue);
                bool hasTime = FactTimeMetadata.HasUsableTime(time);
                bool isAccess = string.Equals(eventType, "Access",
                    StringComparison.OrdinalIgnoreCase);
                var fact = new Fact(SourceName + "_" + i.ToString(), time,
                    SourceName, isAccess ? "HttpRequestObserved" :
                    "WebServerErrorMessageObserved");
                FactTimeMetadata.Apply(fact,
                    hasTime ? FactTimeMetadata.EventTimeKind :
                    FactTimeMetadata.UnknownTimeKind,
                    hasTime ? FactTimeMetadata.MediumConfidence :
                    FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacWebServerEventsCsv;
                fact.RawRef = ArtifactNames.UacWebServerEventsCsv + ":" +
                    (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(rawTime, timeUtc, timeParseStatus,
                    serverType, eventType, remoteAddress, remotePort, user,
                    virtualHost, method, requestTarget, protocol, statusCode,
                    responseBytes, referrer, userAgent, severity, processId,
                    message, sourcePath, lineNumber, details);

                AddRemoteEntity(fact, remoteAddress);
                AddEntity(fact, "RemotePort", remotePort);
                AddEntity(fact, "User", user);
                AddEntity(fact, "VirtualHost", virtualHost);
                AddEntity(fact, "HttpMethod", method);
                AddEntity(fact, "RequestTarget", requestTarget);
                AddEntity(fact, "HttpProtocol", protocol);
                AddEntity(fact, "HttpStatus", statusCode);
                AddEntity(fact, "Referrer", referrer);
                AddEntity(fact, "UserAgent", userAgent);
                AddEntity(fact, "ProcessId", processId);
                AddEntity(fact, "WebServer", serverType);
                AddEntity(fact, "Path", sourcePath);

                if (!hasTime)
                {
                    fact.ParserNote = "The web-server row did not include a reliable UTC offset, so raw local time was preserved without inventing UTC. The message or request is an observation, not a maliciousness verdict.";
                    fact.FallbackUsed = true;
                }
                else
                {
                    fact.ParserNote = "The web-server timestamp included a numeric offset. Remote addresses and HTTP headers may be proxy- or client-controlled; response status is not a maliciousness verdict.";
                }
                facts.Add(fact);
            }
            return facts;
        }

        private static void AddRemoteEntity(Fact fact, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            IPAddress address;
            AddEntity(fact, IPAddress.TryParse(value.Trim(), out address) ?
                "RemoteIP" : "RemoteName", value);
        }

        private static string BuildDetails(string rawTime, string timeUtc,
            string timeParseStatus, string serverType, string eventType,
            string remoteAddress, string remotePort, string user,
            string virtualHost, string method, string requestTarget,
            string protocol, string statusCode, string responseBytes,
            string referrer, string userAgent, string severity, string processId,
            string message, string sourcePath, string lineNumber, string details)
        {
            var parts = new List<string>();
            AddPart(parts, "time", rawTime);
            AddPart(parts, "time_utc", timeUtc);
            AddPart(parts, "time_parse_status", timeParseStatus);
            AddPart(parts, "server", serverType);
            AddPart(parts, "event_type", eventType);
            AddPart(parts, "remote", remoteAddress);
            AddPart(parts, "remote_port", remotePort);
            AddPart(parts, "user", user);
            AddPart(parts, "virtual_host", virtualHost);
            AddPart(parts, "method", method);
            AddPart(parts, "request_target", requestTarget);
            AddPart(parts, "protocol", protocol);
            AddPart(parts, "status", statusCode);
            AddPart(parts, "response_bytes", responseBytes);
            AddPart(parts, "referrer", referrer);
            AddPart(parts, "user_agent", userAgent);
            AddPart(parts, "severity", severity);
            AddPart(parts, "process_id", processId);
            AddPart(parts, "message", message);
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
