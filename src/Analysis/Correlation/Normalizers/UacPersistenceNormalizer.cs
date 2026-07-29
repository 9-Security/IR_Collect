using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacPersistenceNormalizer
    {
        public const string SourceName = "UacPersistence";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeText = CorrelationCsvHelper.Get(row, "ModifiedTimeUtc");
                string platform = CorrelationCsvHelper.Get(row, "Platform");
                string mechanism = CorrelationCsvHelper.Get(row, "Mechanism");
                string scope = CorrelationCsvHelper.Get(row, "Scope");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string user = CorrelationCsvHelper.Get(row, "User");
                string executable = CorrelationCsvHelper.Get(row, "Executable");
                string arguments = CorrelationCsvHelper.Get(row, "Arguments");
                string trigger = CorrelationCsvHelper.Get(row, "Trigger");
                string enabledState = CorrelationCsvHelper.Get(row, "EnabledState");
                string fingerprint = CorrelationCsvHelper.Get(row, "KeyFingerprintSha256");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");
                DateTime time = CorrelationCsvHelper.ParseDateTime(timeText, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, "PersistenceConfigurationObserved");
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.LowConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacPersistenceCsv;
                fact.RawRef = ArtifactNames.UacPersistenceCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "platform=" + (platform ?? "") +
                    "; mechanism=" + (mechanism ?? "") +
                    "; scope=" + (scope ?? "") +
                    "; name=" + (name ?? "") +
                    "; enabled_state=" + (enabledState ?? "") +
                    "; trigger=" + (trigger ?? "") +
                    "; source=" + (sourcePath ?? "") +
                    "; source_line=" + (lineNumber ?? "") +
                    (string.IsNullOrWhiteSpace(details) ? "" : "; " + details.Trim());
                fact.ParserNote = "Configuration presence does not by itself prove execution, maliciousness, or current enablement.";

                AddEntity(fact, "PersistenceMechanism", mechanism);
                AddEntity(fact, "PersistenceName", name);
                AddEntity(fact, "User", user);
                AddEntity(fact, "Path", executable);
                AddEntity(fact, "Path", sourcePath);
                AddEntity(fact, "CommandLine", JoinCommand(executable, arguments));
                AddEntity(fact, "Hash", fingerprint);
                if (IsServiceMechanism(mechanism)) AddEntity(fact, "ServiceName", name);
                if (IsTaskMechanism(mechanism)) AddEntity(fact, "TaskName", name);
                facts.Add(fact);
            }
            return facts;
        }

        private static string JoinCommand(string executable, string arguments)
        {
            if (string.IsNullOrWhiteSpace(executable)) return "";
            return string.IsNullOrWhiteSpace(arguments)
                ? executable.Trim()
                : executable.Trim() + " " + arguments.Trim();
        }

        private static bool IsServiceMechanism(string mechanism)
        {
            string value = mechanism ?? "";
            return value.StartsWith("systemd-", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("launchd-", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTaskMechanism(string mechanism)
        {
            string value = mechanism ?? "";
            return string.Equals(value, "cron", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "anacron", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "cron-periodic-script", StringComparison.OrdinalIgnoreCase);
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact != null && !string.IsNullOrWhiteSpace(value))
                fact.AddEntity(type, value.Trim());
        }
    }
}
