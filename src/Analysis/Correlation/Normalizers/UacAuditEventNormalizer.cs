using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacAuditEventNormalizer
    {
        public const string SourceName = "UacAudit";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeUtc = CorrelationCsvHelper.Get(row, "TimeUtc");
                string eventId = CorrelationCsvHelper.Get(row, "AuditEventId");
                string recordTypes = CorrelationCsvHelper.Get(row, "RecordTypes");
                string action = CorrelationCsvHelper.Get(row, "Action");
                string success = CorrelationCsvHelper.Get(row, "Success");
                string syscall = CorrelationCsvHelper.Get(row, "Syscall");
                string executable = CorrelationCsvHelper.Get(row, "Executable");
                string commandLine = CorrelationCsvHelper.Get(row, "CommandLine");
                string workingDirectory = CorrelationCsvHelper.Get(row, "WorkingDirectory");
                string user = CorrelationCsvHelper.Get(row, "User");
                string auditUserId = CorrelationCsvHelper.Get(row, "AuditUserId");
                string realUserId = CorrelationCsvHelper.Get(row, "RealUserId");
                string effectiveUserId = CorrelationCsvHelper.Get(row, "EffectiveUserId");
                string sessionId = CorrelationCsvHelper.Get(row, "SessionId");
                string processId = CorrelationCsvHelper.Get(row, "ProcessId");
                string parentProcessId = CorrelationCsvHelper.Get(row, "ParentProcessId");
                string terminal = CorrelationCsvHelper.Get(row, "Terminal");
                string remoteAddress = CorrelationCsvHelper.Get(row, "RemoteAddress");
                string remoteHost = CorrelationCsvHelper.Get(row, "RemoteHost");
                string targetPaths = CorrelationCsvHelper.Get(row, "TargetPaths");
                string selinuxDecision = CorrelationCsvHelper.Get(row, "SELinuxDecision");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                string lineNumbers = CorrelationCsvHelper.Get(row, "LineNumbers");
                string details = CorrelationCsvHelper.Get(row, "Details");

                DateTime time = CorrelationCsvHelper.ParseDateTime(timeUtc, DateTime.MinValue);
                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName,
                    string.IsNullOrWhiteSpace(action) ? "AuditEventObserved" : action.Trim());
                bool hasTime = FactTimeMetadata.HasUsableTime(time);
                FactTimeMetadata.Apply(fact,
                    hasTime ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    hasTime ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacAuditEventsCsv;
                fact.RawRef = ArtifactNames.UacAuditEventsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(eventId, recordTypes, success, syscall,
                    workingDirectory, sessionId, selinuxDecision, sourcePath, lineNumbers, details);

                AddEntity(fact, "AuditEventId", eventId);
                AddEntity(fact, "User", user);
                AddEntity(fact, "AuditUserId", auditUserId);
                AddEntity(fact, "UserId", realUserId);
                AddEntity(fact, "EffectiveUserId", effectiveUserId);
                AddEntity(fact, "SessionId", sessionId);
                AddEntity(fact, "ProcessId", processId);
                AddEntity(fact, "ParentProcessId", parentProcessId);
                AddEntity(fact, "Terminal", terminal);
                AddEntity(fact, "RemoteIP", remoteAddress);
                AddEntity(fact, "RemoteName", remoteHost);
                AddEntity(fact, "Path", executable);
                AddEntity(fact, "Path", workingDirectory);
                AddPathEntities(fact, targetPaths);
                AddEntity(fact, "CommandLine", commandLine);

                fact.ParserNote = "Linux audit records sharing the same audit event identifier were grouped; the record describes audited activity and policy results, not an automatic malicious verdict.";
                if (!hasTime)
                {
                    fact.FallbackUsed = true;
                    fact.ParserNote += " The audit epoch timestamp was not usable.";
                }
                facts.Add(fact);
            }
            return facts;
        }

        private static string BuildDetails(string eventId, string recordTypes,
            string success, string syscall, string workingDirectory, string sessionId,
            string selinuxDecision, string sourcePath, string lineNumbers, string details)
        {
            var parts = new List<string>();
            AddPart(parts, "audit_event_id", eventId);
            AddPart(parts, "record_types", recordTypes);
            AddPart(parts, "success", success);
            AddPart(parts, "syscall", syscall);
            AddPart(parts, "cwd", workingDirectory);
            AddPart(parts, "session", sessionId);
            AddPart(parts, "selinux_decision", selinuxDecision);
            AddPart(parts, "source", sourcePath);
            AddPart(parts, "source_lines", lineNumbers);
            if (!string.IsNullOrWhiteSpace(details))
                parts.Add(details.Trim());
            return string.Join("; ", parts.ToArray());
        }

        private static void AddPathEntities(Fact fact, string targetPaths)
        {
            if (string.IsNullOrWhiteSpace(targetPaths))
                return;
            var current = new System.Text.StringBuilder();
            bool escaped = false;
            for (int i = 0; i < targetPaths.Length; i++)
            {
                char c = targetPaths[i];
                if (escaped)
                {
                    current.Append(c);
                    escaped = false;
                }
                else if (c == '\\')
                {
                    escaped = true;
                }
                else if (c == '|')
                {
                    AddEntity(fact, "Path", current.ToString());
                    current.Length = 0;
                }
                else
                {
                    current.Append(c);
                }
            }
            if (escaped)
                current.Append('\\');
            AddEntity(fact, "Path", current.ToString());
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
