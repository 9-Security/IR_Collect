using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class KerberosTicketCacheNormalizer
    {
        public const string SourceName = "KerberosTicketCache";
        public const string ActionKerberosTicketCached = "KerberosTicketCached";

        public static List<Fact> ToFacts(string textPath)
        {
            var list = new List<Fact>();
            if (string.IsNullOrWhiteSpace(textPath) || !File.Exists(textPath))
                return list;

            string[] lines = File.ReadAllLines(textPath, Encoding.UTF8);
            DateTime observedAt = ExtractObservedAt(lines);
            string client = "";
            string server = "";
            string startTimeRaw = "";
            string endTimeRaw = "";
            string renewTimeRaw = "";
            string encryptionType = "";
            string ticketFlags = "";
            string kdcCalled = "";
            int blockLine = 0;

            for (int i = 0; i < lines.Length; i++)
            {
                string trimmed = (lines[i] ?? "").Trim();
                if (i == 0 && trimmed.StartsWith("ObservedAtUtc:", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (trimmed.StartsWith("#", StringComparison.Ordinal))
                {
                    AppendFact(list, observedAt, client, server, startTimeRaw, endTimeRaw, renewTimeRaw, encryptionType, ticketFlags, kdcCalled, blockLine);
                    client = "";
                    server = "";
                    startTimeRaw = "";
                    endTimeRaw = "";
                    renewTimeRaw = "";
                    encryptionType = "";
                    ticketFlags = "";
                    kdcCalled = "";
                    blockLine = i + 1;
                    trimmed = StripTicketBlockPrefix(trimmed);
                    if (trimmed.Length == 0)
                        continue;
                }

                string value = TryParseLabelValue(trimmed, "Client");
                if (!string.IsNullOrWhiteSpace(value)) { client = value; continue; }
                value = TryParseLabelValue(trimmed, "Server");
                if (!string.IsNullOrWhiteSpace(value)) { server = value; continue; }
                value = TryParseLabelValue(trimmed, "Start Time");
                if (!string.IsNullOrWhiteSpace(value)) { startTimeRaw = value; continue; }
                value = TryParseLabelValue(trimmed, "End Time");
                if (!string.IsNullOrWhiteSpace(value)) { endTimeRaw = value; continue; }
                value = TryParseLabelValue(trimmed, "Renew Time");
                if (!string.IsNullOrWhiteSpace(value)) { renewTimeRaw = value; continue; }
                value = TryParseLabelValue(trimmed, "KerbTicket Encryption Type");
                if (!string.IsNullOrWhiteSpace(value)) { encryptionType = value; continue; }
                value = TryParseLabelValue(trimmed, "Ticket Flags");
                if (!string.IsNullOrWhiteSpace(value)) { ticketFlags = value; continue; }
                value = TryParseLabelValue(trimmed, "Kdc Called");
                if (!string.IsNullOrWhiteSpace(value)) { kdcCalled = value; continue; }
            }

            AppendFact(list, observedAt, client, server, startTimeRaw, endTimeRaw, renewTimeRaw, encryptionType, ticketFlags, kdcCalled, blockLine);
            return list;
        }

        private static void AppendFact(List<Fact> list, DateTime observedAt, string client, string server, string startTimeRaw, string endTimeRaw, string renewTimeRaw, string encryptionType, string ticketFlags, string kdcCalled, int lineNumber)
        {
            if (list == null || (string.IsNullOrWhiteSpace(client) && string.IsNullOrWhiteSpace(server)))
                return;

            DateTime startTime = ParseTicketTime(startTimeRaw);
            DateTime time = FactTimeMetadata.HasUsableTime(startTime) ? startTime : observedAt;
            string timeKind = FactTimeMetadata.HasUsableTime(startTime) ? FactTimeMetadata.EventTimeKind :
                (FactTimeMetadata.HasUsableTime(observedAt) ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind);
            string confidence = FactTimeMetadata.HasUsableTime(startTime) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence;

            var fact = new Fact(SourceName + "_" + list.Count.ToString(), time, SourceName, ActionKerberosTicketCached);
            FactTimeMetadata.Apply(fact, timeKind, confidence);
            fact.SourceFile = ArtifactNames.KerberosTicketsTxt;
            fact.RawRef = ArtifactNames.KerberosTicketsTxt + ":" + Math.Max(1, lineNumber).ToString();
            fact.ParseLevel = FactProvenanceMetadata.RawArtifactDerivedParseLevel;
            fact.Details = BuildDetails(endTimeRaw, renewTimeRaw, encryptionType, ticketFlags, kdcCalled, server);

            string user = ExtractClientUser(client);
            if (!string.IsNullOrWhiteSpace(user))
                fact.AddEntity("User", user);
            if (!string.IsNullOrWhiteSpace(server))
                fact.AddEntity("ServiceName", server.Trim());
            AddTargetEntities(fact, server, kdcCalled);

            if (!FactTimeMetadata.HasUsableTime(startTime) && FactTimeMetadata.HasUsableTime(observedAt))
            {
                fact.ParserNote = "Kerberos ticket cache fact uses ObservedAtUtc because klist Start Time was unavailable or unparseable.";
                fact.FallbackUsed = true;
            }

            list.Add(fact);
        }

        private static string BuildDetails(string endTimeRaw, string renewTimeRaw, string encryptionType, string ticketFlags, string kdcCalled, string server)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(server))
                parts.Add("Server=" + server.Trim());
            if (!string.IsNullOrWhiteSpace(endTimeRaw))
                parts.Add("End=" + endTimeRaw.Trim());
            if (!string.IsNullOrWhiteSpace(renewTimeRaw))
                parts.Add("Renew=" + renewTimeRaw.Trim());
            if (!string.IsNullOrWhiteSpace(encryptionType))
                parts.Add("Encryption=" + encryptionType.Trim());
            if (!string.IsNullOrWhiteSpace(ticketFlags))
                parts.Add("Flags=" + ticketFlags.Trim());
            if (!string.IsNullOrWhiteSpace(kdcCalled))
                parts.Add("Kdc=" + kdcCalled.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static DateTime ExtractObservedAt(string[] lines)
        {
            if (lines == null || lines.Length == 0)
                return DateTime.MinValue;
            string first = (lines[0] ?? "").Trim();
            if (!first.StartsWith("ObservedAtUtc:", StringComparison.OrdinalIgnoreCase))
                return DateTime.MinValue;
            string raw = first.Substring("ObservedAtUtc:".Length).Trim();
            DateTime dt;
            return DateTime.TryParse(raw, out dt) ? dt : DateTime.MinValue;
        }

        private static string TryParseLabelValue(string line, string label)
        {
            if (string.IsNullOrWhiteSpace(line) || string.IsNullOrWhiteSpace(label))
                return "";

            int colon = line.IndexOf(':');
            if (colon < 0)
                return "";
            string lineLabel = line.Substring(0, colon).Trim();
            if (!string.Equals(lineLabel, label, StringComparison.OrdinalIgnoreCase))
                return "";
            return line.Substring(colon + 1).Trim();
        }

        private static DateTime ParseTicketTime(string raw)
        {
            string value = (raw ?? "").Trim();
            if (value.Length == 0)
                return DateTime.MinValue;

            int marker = value.IndexOf(" (", StringComparison.Ordinal);
            if (marker > 0)
                value = value.Substring(0, marker).Trim();

            DateTime dt;
            return DateTime.TryParse(value, out dt) ? dt : DateTime.MinValue;
        }

        private static string StripTicketBlockPrefix(string line)
        {
            string value = (line ?? "").Trim();
            if (!value.StartsWith("#", StringComparison.Ordinal))
                return value;

            int marker = value.IndexOf('>');
            if (marker < 0 || marker + 1 >= value.Length)
                return "";

            return value.Substring(marker + 1).Trim();
        }

        private static string ExtractClientUser(string client)
        {
            string value = (client ?? "").Trim();
            if (value.Length == 0)
                return "";
            int atIndex = value.IndexOf('@');
            if (atIndex > 0)
                value = value.Substring(0, atIndex).Trim();
            return value;
        }

        private static void AddTargetEntities(Fact fact, string serverPrincipal, string kdcCalled)
        {
            if (fact == null)
                return;

            string targetServer = ExtractServerHost(serverPrincipal);
            if (!string.IsNullOrWhiteSpace(targetServer))
            {
                fact.AddEntity("TargetServer", targetServer);
                fact.AddEntity("RemoteName", targetServer);
                AddHostEntity(fact, targetServer);
            }

            string kdc = (kdcCalled ?? "").Trim();
            if (!string.IsNullOrWhiteSpace(kdc))
                fact.AddEntity("Computer", kdc);
        }

        internal static string ExtractServerHost(string serverPrincipal)
        {
            string value = (serverPrincipal ?? "").Trim();
            if (value.Length == 0)
                return "";

            int atIndex = value.IndexOf('@');
            if (atIndex > 0)
                value = value.Substring(0, atIndex).Trim();

            int slashIndex = value.IndexOf('/');
            if (slashIndex >= 0 && slashIndex + 1 < value.Length)
                value = value.Substring(slashIndex + 1).Trim();

            int colonIndex = value.IndexOf(':');
            if (colonIndex > 0)
                value = value.Substring(0, colonIndex).Trim();

            int secondSlash = value.IndexOf('/');
            if (secondSlash > 0)
                value = value.Substring(0, secondSlash).Trim();

            return value.Trim();
        }

        private static void AddHostEntity(Fact fact, string host)
        {
            string value = (host ?? "").Trim();
            if (value.Length == 0)
                return;

            IPAddress addr;
            if (IPAddress.TryParse(value, out addr) && addr.AddressFamily == AddressFamily.InterNetwork)
                fact.AddEntity("RemoteIP", value);
            else
                fact.AddEntity("Workstation", value);
        }
    }
}
