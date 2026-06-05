using System;
using System.Collections.Generic;
using System.Linq;
using IR_Collect;
using IR_Collect.Analysis;

namespace IR_Collect.Analysis.Correlation
{
    public static class FactProvenanceHelper
    {
        public static void ApplyCaseMetadata(CaseData c, IEnumerable<Fact> facts)
        {
            if (facts == null)
                return;

            foreach (Fact fact in facts)
            {
                if (fact == null)
                    continue;

                FactTimeMetadata.ApplyDefaultsIfMissing(fact);
                if (string.IsNullOrWhiteSpace(fact.CollectionStep) || string.Equals(fact.CollectionStep, "unknown", StringComparison.OrdinalIgnoreCase))
                    fact.CollectionStep = InferCollectionStep(fact);
                if (string.IsNullOrWhiteSpace(fact.CollectionStatus) || string.Equals(fact.CollectionStatus, "unknown", StringComparison.OrdinalIgnoreCase))
                    fact.CollectionStatus = InferCollectionStatus(c, fact.CollectionStep);
                if (string.IsNullOrWhiteSpace(fact.CollectionPrivilege) || string.Equals(fact.CollectionPrivilege, "unknown", StringComparison.OrdinalIgnoreCase))
                    fact.CollectionPrivilege = InferCollectionPrivilege(c);
                fact.ParseLevel = InferParseLevel(fact);
            }
        }

        public static string BuildSummary(Fact fact)
        {
            if (fact == null)
                return "";

            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(fact.SourceFile))
                parts.Add(fact.SourceFile);
            if (!string.IsNullOrWhiteSpace(fact.ParseLevel) && !string.Equals(fact.ParseLevel, FactProvenanceMetadata.UnknownParseLevel, StringComparison.OrdinalIgnoreCase))
                parts.Add(fact.ParseLevel);

            string step = string.IsNullOrWhiteSpace(fact.CollectionStep) ? "" : fact.CollectionStep;
            string status = string.IsNullOrWhiteSpace(fact.CollectionStatus) ? "" : fact.CollectionStatus;
            if (!string.IsNullOrWhiteSpace(step) || !string.IsNullOrWhiteSpace(status))
                parts.Add((step.Length > 0 ? step : "Collection") + (status.Length > 0 ? (" / " + status) : ""));

            if (!string.IsNullOrWhiteSpace(fact.CollectionPrivilege) && !string.Equals(fact.CollectionPrivilege, "unknown", StringComparison.OrdinalIgnoreCase))
                parts.Add(fact.CollectionPrivilege);
            if (fact.FallbackUsed)
                parts.Add("fallback");

            return string.Join(" | ", parts.ToArray());
        }

        private static string InferCollectionStep(Fact fact)
        {
            string source = fact != null ? (fact.Source ?? "") : "";
            string sourceFile = fact != null ? (fact.SourceFile ?? "") : "";

            if (source.StartsWith("EventLog", StringComparison.OrdinalIgnoreCase) || ArtifactNames.IsEventLogFilteredCsv(sourceFile))
                return "Event Logs";
            if (string.Equals(source, "Process", StringComparison.OrdinalIgnoreCase))
                return "System Info";
            if (string.Equals(source, "LogonSession", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "StoredCredential", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "KerberosTicketCache", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "NetworkResource", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "ServerConnection", StringComparison.OrdinalIgnoreCase))
                return "System Info";
            if (string.Equals(source, "MemoryAcquisition", StringComparison.OrdinalIgnoreCase))
                return "Memory acquisition";
            if (string.Equals(source, "MemoryAnalysis", StringComparison.OrdinalIgnoreCase))
                return "Memory analysis handoff";
            if (string.Equals(source, "MFT", StringComparison.OrdinalIgnoreCase))
                return "MFT";
            if (string.Equals(source, "USN", StringComparison.OrdinalIgnoreCase))
                return "USN Journal";
            if (string.Equals(source, "ActivityTimeline", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(sourceFile, ArtifactNames.ActivityTimelineCsv, StringComparison.OrdinalIgnoreCase))
                return "Unified Timeline";
            if (string.Equals(source, "Autorun", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "Service", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "ScheduledTask", StringComparison.OrdinalIgnoreCase))
                return "Persistence";
            if (string.Equals(source, "WmiPersistence", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "BITS", StringComparison.OrdinalIgnoreCase))
                return "Execution Artifacts";
            if (string.Equals(source, "BAM", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "DAM", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "Amcache", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "ShimCache", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "SRUMNetwork", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "SRUMApp", StringComparison.OrdinalIgnoreCase))
                return "Execution Artifacts";
            return "unknown";
        }

        private static string InferCollectionStatus(CaseData c, string stepName)
        {
            if (c == null || c.CollectionCoverage == null || c.CollectionCoverage.Steps == null || string.IsNullOrWhiteSpace(stepName))
                return "unknown";

            foreach (CollectionCoverageStep step in c.CollectionCoverage.Steps)
            {
                if (step == null || string.IsNullOrWhiteSpace(step.Step))
                    continue;
                if (string.Equals(step.Step, stepName, StringComparison.OrdinalIgnoreCase))
                    return string.IsNullOrWhiteSpace(step.Status) ? "unknown" : step.Status;
            }
            return "unknown";
        }

        private static string InferCollectionPrivilege(CaseData c)
        {
            if (c == null || c.CollectionCoverage == null)
                return "unknown";

            string state = c.CollectionCoverage.CollectorPrivilegeState ?? "";
            if (!string.IsNullOrWhiteSpace(state))
                return state;
            if (c.CollectionCoverage.IsAdministrator)
                return "Administrator";
            return "StandardUser";
        }

        private static string InferParseLevel(Fact fact)
        {
            if (fact == null)
                return FactProvenanceMetadata.UnknownParseLevel;

            string current = FactProvenanceMetadata.NormalizeParseLevel(fact.ParseLevel);
            if (!string.Equals(current, FactProvenanceMetadata.UnknownParseLevel, StringComparison.OrdinalIgnoreCase))
                return current;

            string source = (fact.Source ?? "").Trim();
            if (source.StartsWith("EventLog", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.StructuredParseLevel;
            if (string.Equals(source, "Process", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "LogonSession", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "NetworkResource", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "Service", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "ServerConnection", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "WmiPersistence", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "BITS", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "SRUMNetwork", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "SRUMApp", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.StructuredParseLevel;
            if (string.Equals(source, "StoredCredential", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "KerberosTicketCache", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.RawArtifactDerivedParseLevel;
            if (string.Equals(source, "MemoryAcquisition", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "MemoryAnalysis", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.SynthesizedParseLevel;
            if (string.Equals(source, "ScheduledTask", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.StructuredXmlParseLevel;
            if (string.Equals(source, "Autorun", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "BAM", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "DAM", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "Amcache", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.RegistryValueParseLevel;
            if (string.Equals(source, "ShimCache", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.RawArtifactDerivedParseLevel;
            if (string.Equals(source, "MFT", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(source, "USN", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.MetadataDerivedParseLevel;
            if (string.Equals(source, "ActivityTimeline", StringComparison.OrdinalIgnoreCase))
                return FactProvenanceMetadata.SynthesizedParseLevel;
            return FactProvenanceMetadata.UnknownParseLevel;
        }
    }
}
