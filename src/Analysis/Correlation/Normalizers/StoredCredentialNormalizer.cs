using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class StoredCredentialNormalizer
    {
        public const string SourceName = "StoredCredential";
        public const string ActionStoredCredentialObserved = "StoredCredentialObserved";

        public static List<Fact> ToFacts(string textPath)
        {
            var list = new List<Fact>();
            if (string.IsNullOrWhiteSpace(textPath) || !File.Exists(textPath))
                return list;

            string[] lines = File.ReadAllLines(textPath, Encoding.UTF8);
            DateTime observedAt = ExtractObservedAt(lines);
            string target = "";
            string type = "";
            string user = "";
            int targetLine = 0;

            for (int i = 0; i < lines.Length; i++)
            {
                string trimmed = (lines[i] ?? "").Trim();
                if (i == 0 && trimmed.StartsWith("ObservedAtUtc:", StringComparison.OrdinalIgnoreCase))
                    continue;

                string parsedTarget = TryParseTarget(trimmed);
                if (!string.IsNullOrWhiteSpace(parsedTarget))
                {
                    AppendFact(list, observedAt, target, type, user, targetLine);
                    target = parsedTarget;
                    type = "";
                    user = "";
                    targetLine = i + 1;
                    continue;
                }

                string parsedType = TryParseLabelValue(trimmed, "Type");
                if (!string.IsNullOrWhiteSpace(parsedType))
                {
                    type = parsedType;
                    continue;
                }

                string parsedUser = TryParseLabelValue(trimmed, "User");
                if (!string.IsNullOrWhiteSpace(parsedUser))
                {
                    user = parsedUser;
                    continue;
                }

                if (trimmed.Length == 0 && !string.IsNullOrWhiteSpace(target))
                {
                    AppendFact(list, observedAt, target, type, user, targetLine);
                    target = "";
                    type = "";
                    user = "";
                    targetLine = 0;
                }
            }

            AppendFact(list, observedAt, target, type, user, targetLine);
            return list;
        }

        private static void AppendFact(List<Fact> list, DateTime observedAt, string target, string type, string user, int lineNumber)
        {
            if (list == null || string.IsNullOrWhiteSpace(target))
                return;

            DateTime time = FactTimeMetadata.HasUsableTime(observedAt) ? observedAt : DateTime.MinValue;
            var fact = new Fact(SourceName + "_" + list.Count.ToString(), time, SourceName, ActionStoredCredentialObserved);
            FactTimeMetadata.Apply(fact,
                FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.ObservedTimeKind : FactTimeMetadata.UnknownTimeKind,
                FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
            fact.SourceFile = ArtifactNames.StoredCredentialsTxt;
            fact.RawRef = ArtifactNames.StoredCredentialsTxt + ":" + Math.Max(1, lineNumber).ToString();
            fact.ParseLevel = FactProvenanceMetadata.RawArtifactDerivedParseLevel;
            fact.Details = BuildDetails(type, user, target);

            if (!string.IsNullOrWhiteSpace(user))
                fact.AddEntity("User", user.Trim());
            fact.AddEntity("CredentialTarget", target.Trim());
            AddTargetEntities(fact, target);
            list.Add(fact);
        }

        private static string BuildDetails(string type, string user, string target)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(type))
                parts.Add("Type=" + type.Trim());
            if (!string.IsNullOrWhiteSpace(user))
                parts.Add("User=" + user.Trim());
            if (!string.IsNullOrWhiteSpace(target))
                parts.Add("Target=" + target.Trim());
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

        private static string TryParseTarget(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return "";

            int colon = line.IndexOf(':');
            if (colon >= 0)
            {
                string label = line.Substring(0, colon).Trim();
                if (string.Equals(label, "Target", StringComparison.OrdinalIgnoreCase))
                    return line.Substring(colon + 1).Trim();
            }

            int targetIndex = line.IndexOf("target=", StringComparison.OrdinalIgnoreCase);
            if (targetIndex >= 0)
                return line.Substring(targetIndex).Trim();

            return "";
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

        private static void AddTargetEntities(Fact fact, string target)
        {
            if (fact == null || string.IsNullOrWhiteSpace(target))
                return;

            string server = ExtractTargetServer(target);
            if (string.IsNullOrWhiteSpace(server))
                return;

            fact.AddEntity("TargetServer", server);
            fact.AddEntity("RemoteName", server);
            IPAddress addr;
            if (IPAddress.TryParse(server, out addr) && addr.AddressFamily == AddressFamily.InterNetwork)
                fact.AddEntity("RemoteIP", server);
            else
                fact.AddEntity("Workstation", server);
        }

        internal static string ExtractTargetServer(string target)
        {
            string value = (target ?? "").Trim();
            if (value.Length == 0)
                return "";

            int targetIndex = value.IndexOf("target=", StringComparison.OrdinalIgnoreCase);
            if (targetIndex >= 0)
                value = value.Substring(targetIndex + "target=".Length).Trim();

            if (value.StartsWith(@"\\", StringComparison.Ordinal))
            {
                string unc = value.Substring(2);
                int slash = unc.IndexOf('\\');
                return slash >= 0 ? unc.Substring(0, slash).Trim() : unc.Trim();
            }

            int firstSlash = value.IndexOf('/');
            if (firstSlash >= 0 && firstSlash + 1 < value.Length)
                value = value.Substring(firstSlash + 1).Trim();

            int atIndex = value.IndexOf('@');
            if (atIndex > 0)
                value = value.Substring(0, atIndex).Trim();

            int colonIndex = value.IndexOf(':');
            if (colonIndex > 0)
                value = value.Substring(0, colonIndex).Trim();

            int backslashIndex = value.IndexOf('\\');
            if (backslashIndex > 0)
                value = value.Substring(0, backslashIndex).Trim();

            int slashIndex = value.IndexOf('/');
            if (slashIndex > 0)
                value = value.Substring(0, slashIndex).Trim();

            return value.Trim();
        }
    }
}
