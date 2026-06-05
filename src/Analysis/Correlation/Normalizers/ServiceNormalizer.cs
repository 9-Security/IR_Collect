using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ServiceNormalizer
    {
        public const string SourceName = "Service";
        public const string ActionServiceConfigurationObserved = "ServiceConfigurationObserved";

        public static List<Fact> ToFacts(string servicesCsvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(servicesCsvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string serviceName = CorrelationCsvHelper.Get(row, "Name");
                string displayName = CorrelationCsvHelper.Get(row, "DisplayName");
                string pathName = CorrelationCsvHelper.Get(row, "PathName");
                string startMode = CorrelationCsvHelper.Get(row, "StartMode");
                string state = CorrelationCsvHelper.Get(row, "State");

                if (string.IsNullOrWhiteSpace(serviceName) && string.IsNullOrWhiteSpace(pathName))
                    continue;

                var fact = new Fact(SourceName + "_" + i.ToString(), DateTime.MinValue, SourceName, ActionServiceConfigurationObserved);
                FactTimeMetadata.Apply(fact, FactTimeMetadata.InferTimeKind(SourceName, fact.Time), FactTimeMetadata.InferTimeConfidence(SourceName, fact.Time));
                fact.SourceFile = ArtifactNames.ServicesCsv;
                fact.RawRef = ArtifactNames.ServicesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(displayName, startMode, state, pathName);

                AddEntity(fact, "ServiceName", serviceName);
                AddPathEntities(fact, pathName);
                list.Add(fact);
            }
            return list;
        }

        private static string BuildDetails(string displayName, string startMode, string state, string pathName)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(displayName))
                parts.Add("DisplayName=" + displayName.Trim());
            if (!string.IsNullOrWhiteSpace(startMode))
                parts.Add("StartMode=" + startMode.Trim());
            if (!string.IsNullOrWhiteSpace(state))
                parts.Add("State=" + state.Trim());
            if (!string.IsNullOrWhiteSpace(pathName))
                parts.Add("PathName=" + TrimForDetails(pathName.Trim(), 320));
            return string.Join("; ", parts.ToArray());
        }

        private static string TrimForDetails(string value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
                return value ?? "";
            return value.Substring(0, maxLength - 3) + "...";
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }

        private static void AddPathEntities(Fact fact, string pathName)
        {
            if (fact == null || string.IsNullOrWhiteSpace(pathName))
                return;

            string raw = pathName.Trim();
            fact.AddEntity("Path", raw);

            string binaryPath = TryExtractBinaryPath(raw);
            if (!string.IsNullOrWhiteSpace(binaryPath) &&
                !string.Equals(binaryPath, raw, StringComparison.OrdinalIgnoreCase))
                fact.AddEntity("Path", binaryPath);
        }

        private static string TryExtractBinaryPath(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "";

            string trimmed = value.Trim();
            if (trimmed.StartsWith("\"", StringComparison.Ordinal))
            {
                int endQuote = trimmed.IndexOf('"', 1);
                if (endQuote > 1)
                    return trimmed.Substring(1, endQuote - 1).Trim();
            }

            Match m = Regex.Match(trimmed, @"(?i)^[A-Z]:\\.*?\.(exe|com|cmd|bat|ps1|vbs|js)\b");
            if (m.Success)
                return m.Value.Trim();

            m = Regex.Match(trimmed, @"(?i)^\\\\[^\\]+\\[^\\]+\\.*?\.(exe|com|cmd|bat|ps1|vbs|js)\b");
            if (m.Success)
                return m.Value.Trim();

            return "";
        }
    }
}
