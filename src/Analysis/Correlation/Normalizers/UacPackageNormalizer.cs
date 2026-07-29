using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacPackageNormalizer
    {
        public const string SourceName = "UacPackage";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string observedAtUtc = CorrelationCsvHelper.Get(row, "ObservedAtUtc");
                string installTimeUtc = CorrelationCsvHelper.Get(row, "InstallTimeUtc");
                string installTimeParseStatus = CorrelationCsvHelper.Get(row, "InstallTimeParseStatus");
                string manager = CorrelationCsvHelper.Get(row, "Manager");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string version = CorrelationCsvHelper.Get(row, "Version");
                string architecture = CorrelationCsvHelper.Get(row, "Architecture");
                string state = CorrelationCsvHelper.Get(row, "State");
                string scope = CorrelationCsvHelper.Get(row, "Scope");
                string publisher = CorrelationCsvHelper.Get(row, "Publisher");
                string description = CorrelationCsvHelper.Get(row, "Description");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumber = CorrelationCsvHelper.Get(row, "LineNumber");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime installTime = CorrelationCsvHelper.ParseDateTime(
                    installTimeUtc, DateTime.MinValue);
                DateTime observedTime = CorrelationCsvHelper.ParseDateTime(
                    observedAtUtc, DateTime.MinValue);
                bool hasInstallTime = FactTimeMetadata.HasUsableTime(installTime);
                bool hasObservedTime = FactTimeMetadata.HasUsableTime(observedTime);
                DateTime factTime = hasInstallTime ? installTime :
                    hasObservedTime ? observedTime : DateTime.MinValue;

                var fact = new Fact(SourceName + "_" + i.ToString(), factTime,
                    SourceName, hasInstallTime ?
                    "PackageInstallTimeRecorded" : "PackageStateObserved");
                FactTimeMetadata.Apply(fact,
                    hasInstallTime ? FactTimeMetadata.MetadataTimeKind :
                    hasObservedTime ? FactTimeMetadata.ObservedTimeKind :
                    FactTimeMetadata.UnknownTimeKind,
                    hasInstallTime ? FactTimeMetadata.MediumConfidence :
                    FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacPackagesCsv;
                fact.RawRef = ArtifactNames.UacPackagesCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(observedAtUtc, installTimeUtc,
                    installTimeParseStatus, manager, name, version, architecture,
                    state, scope, publisher, description, sourcePath, lineNumber,
                    details);

                AddEntity(fact, "ProductName", name);
                AddEntity(fact, "ProductVersion", version);
                AddEntity(fact, "PackageManager", manager);
                AddEntity(fact, "Architecture", architecture);
                AddEntity(fact, "Publisher", publisher);
                AddEntity(fact, "Path", sourcePath);

                if (hasInstallTime)
                {
                    fact.ParserNote = "The package database recorded an install timestamp; this metadata does not identify who initiated installation and does not imply maliciousness.";
                }
                else if (hasObservedTime)
                {
                    fact.ParserNote = "The package-manager output records package state using the UAC acquisition reference time, not a row-level command timestamp; it does not establish the original install time and does not imply maliciousness.";
                }
                else
                {
                    fact.ParserNote = "No reliable package or collection timestamp was available. The untimed fact records package-manager state only and does not imply maliciousness.";
                    fact.FallbackUsed = true;
                }

                facts.Add(fact);
            }
            return facts;
        }

        private static string BuildDetails(string observedAtUtc,
            string installTimeUtc, string installTimeParseStatus, string manager,
            string name, string version, string architecture, string state,
            string scope, string publisher, string description, string sourcePath,
            string lineNumber, string details)
        {
            var parts = new List<string>();
            AddPart(parts, "observed_at_utc", observedAtUtc);
            AddPart(parts, "install_time_utc", installTimeUtc);
            AddPart(parts, "install_time_parse_status", installTimeParseStatus);
            AddPart(parts, "manager", manager);
            AddPart(parts, "name", name);
            AddPart(parts, "version", version);
            AddPart(parts, "architecture", architecture);
            AddPart(parts, "state", state);
            AddPart(parts, "scope", scope);
            AddPart(parts, "publisher", publisher);
            AddPart(parts, "description", description);
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
