using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using IR_Collect.Analysis.Correlation;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    /// <summary>
    /// 從 Event Log 篩選匯出的 CSV（*_filtered.csv）產生 Fact。
    /// 欄位：TimeCreated, EventId, LevelDisplayName, ProviderName, Computer, UserId, TaskDisplayName, Message, EventData
    /// </summary>
    public static class EventLogNormalizer
    {
        public const string SourcePrefix = "EventLog";

        public static List<Fact> ToFacts(string csvPath, string logLabel)
        {
            var list = new List<Fact>();
            if (string.IsNullOrEmpty(csvPath) || !File.Exists(csvPath)) return list;
            if (string.IsNullOrWhiteSpace(logLabel)) logLabel = Path.GetFileNameWithoutExtension(csvPath).Replace("_filtered", "");

            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string timeStr = CorrelationCsvHelper.Get(row, "TimeCreated");
                string eventId = CorrelationCsvHelper.Get(row, "EventId");
                string level = CorrelationCsvHelper.Get(row, "LevelDisplayName");
                string provider = CorrelationCsvHelper.Get(row, "ProviderName");
                string computer = CorrelationCsvHelper.Get(row, "Computer");
                string userId = CorrelationCsvHelper.Get(row, "UserId");
                string taskDisplayName = CorrelationCsvHelper.Get(row, "TaskDisplayName");
                string message = CorrelationCsvHelper.Get(row, "Message");
                string flattenedEventData = CorrelationCsvHelper.Get(row, EventLogDataHelper.EventDataColumn);
                Dictionary<string, string> eventData = EventLogDataHelper.ParseFlattenedEventData(flattenedEventData);

                // Keep high-value lateral-movement events (4624/4625/4769/5145…) even when the
                // exported TimeCreated is blank/corrupt: drop only the timestamp, not the entities.
                // Dropping the whole row would silently lose the user/IP/share facts these events carry.
                DateTime parsedTime = CorrelationCsvHelper.ParseDateTime(timeStr, DateTime.MinValue);
                bool hasUsableTime = parsedTime.Year >= 1980;
                DateTime time = hasUsableTime ? parsedTime : DateTime.MinValue;

                string id = SourcePrefix + "_" + logLabel + "_" + i;
                string source = SourcePrefix + ":" + logLabel;
                string action = InferAction(eventId, provider, eventData);

                var fact = new Fact(id, time, source, action);
                FactTimeMetadata.Apply(fact,
                    hasUsableTime ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    hasUsableTime ? FactTimeMetadata.HighConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = Path.GetFileName(csvPath);
                fact.RawRef = Path.GetFileName(csvPath) + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = BuildDetails(message, flattenedEventData);

                AddEntityIfPresent(fact, "Provider", provider);
                AddEntityIfPresent(fact, "EventId", eventId);
                AddEntityIfPresent(fact, "Level", level);
                AddEntityIfPresent(fact, "Computer", computer);
                AddEntityIfPresent(fact, "UserSid", userId);
                AddEntityIfPresent(fact, "TaskDisplay", taskDisplayName);

                AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "TargetUserName", "AccountName", "User", "SubjectUserName"));
                AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "SubjectUserName"));
                AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "UserName", "SamAccountName", "MemberName"));
                AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "ServiceStartName", "StartAccount"));
                AddEntityIfPresent(fact, "RemoteIP", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpAddress", "ClientAddress", "SourceAddress", "RemoteAddress")));
                AddEntityIfPresent(fact, "RemotePort", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpPort", "SourcePort", "Port")));
                AddEntityIfPresent(fact, "LogonType", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "LogonType")));
                AddEntityIfPresent(fact, "LogonProcess", EventLogDataHelper.GetValue(eventData, "LogonProcessName"));
                AddEntityIfPresent(fact, "AuthenticationPackage", EventLogDataHelper.GetValue(eventData, "AuthenticationPackageName"));
                AddEntityIfPresent(fact, "Workstation", EventLogDataHelper.GetValue(eventData, "WorkstationName", "ClientName"));
                AddEntityIfPresent(fact, "ServiceName", EventLogDataHelper.GetValue(eventData, "ServiceName"));
                AddEntityIfPresent(fact, "TaskName", EventLogDataHelper.GetValue(eventData, "TaskName", "Task"));
                AddEntityIfPresent(fact, "GroupName", EventLogDataHelper.GetValue(eventData, "GroupName", "TargetSid"));
                AddEntityIfPresent(fact, "ThreatName", EventLogDataHelper.GetValue(eventData, "Threat Name", "ThreatName", "Name"));
                AddEntityIfPresent(fact, "CommandLine", EventLogDataHelper.GetValue(eventData, "CommandLine", "ProcessCommandLine"));
                AddEntityIfPresent(fact, "ProcessId", EventLogDataHelper.GetValue(eventData, "ProcessId", "NewProcessId"));
                AddEntityIfPresent(fact, "ShareName", EventLogDataHelper.GetValue(eventData, "ShareName"));
                AddEntityIfPresent(fact, "ShareLocalPath", EventLogDataHelper.GetValue(eventData, "ShareLocalPath"));
                AddEntityIfPresent(fact, "RuleName", EventLogDataHelper.GetValue(eventData, "RuleName"));
                AddEntityIfPresent(fact, "TargetServer", EventLogDataHelper.GetValue(eventData, "TargetServerName", "ServerName", "Destination"));
                AddEntityIfPresent(fact, "ParentPath", EventLogDataHelper.GetValue(eventData, "ParentProcessName"));

                AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "NewProcessName", "ProcessName", "Image", "Application", "ProcessPath"));
                AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "ImagePath", "ServiceFileName", "FilePath", "TargetFilename", "Path"));
                AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "ParentProcessName", "ScriptPath", "ObjectName"));
                string pathFromMessage = TryExtractPathFromMessage(message);
                AddPathEntityIfPresent(fact, pathFromMessage);

                ApplyPhase3LateralMovementEnrichment(fact, eventId, eventData, computer, message);
                string parserBase = BuildParserNote(flattenedEventData, pathFromMessage);
                fact.ParserNote = parserBase;
                AppendPhase3SupplementalParserNote(fact, eventId, eventData);
                fact.FallbackUsed = !string.IsNullOrWhiteSpace(parserBase);

                if (!hasUsableTime)
                {
                    fact.FallbackUsed = true;
                    fact.ParserNote = string.IsNullOrWhiteSpace(fact.ParserNote)
                        ? "TimeCreated missing or unparseable; event retained with entities but no usable timestamp."
                        : fact.ParserNote + " | TimeCreated missing or unparseable; no usable timestamp.";
                }

                list.Add(fact);
            }
            return list;
        }

        private static string InferAction(string eventId, string provider, IDictionary<string, string> eventData)
        {
            switch ((eventId ?? "").Trim())
            {
                case "4624":
                    return "LogonSucceeded";
                case "4625":
                    return "LogonFailed";
                case "4634":
                    return "Logoff";
                case "4647":
                    return "UserInitiatedLogoff";
                case "4648":
                    return "ExplicitCredentialUsed";
                case "4672":
                    return "SpecialPrivilegesAssigned";
                case "4688":
                    return "ProcessCreated";
                case "4697":
                    return "ServiceInstalled";
                case "4698":
                    return "ScheduledTaskCreated";
                case "4702":
                    return "ScheduledTaskUpdated";
                case "4720":
                    return "AccountCreated";
                case "4726":
                    return "AccountDeleted";
                case "4728":
                case "4732":
                    return "GroupMemberAdded";
                case "4729":
                case "4733":
                    return "GroupMemberRemoved";
                case "4776":
                    return "NtlmCredentialValidated";
                case "4778":
                    return "SessionReconnected";
                case "4779":
                    return "SessionDisconnected";
                case "5140":
                    return "ShareAccessed";
                case "5142":
                    return "ShareCreated";
                case "5143":
                    return "ShareModified";
                case "5144":
                    return "ShareDeleted";
                case "5145":
                    return "ShareAccessChecked";
                case "7045":
                    return "ServiceInstalled";
                case "4103":
                    return "PowerShellCommandInvoked";
                case "4104":
                    return "ScriptBlockLogged";
                case "1102":
                    return "AuditLogCleared";
                case "1116":
                    return "DefenderThreatDetected";
                case "1117":
                case "1118":
                    return "DefenderThreatAction";
                case "5001":
                    return "DefenderRealtimeProtectionChanged";
                case "5007":
                    return "DefenderConfigurationChanged";
                case "4768":
                    return "KerberosTgtRequested";
                case "4769":
                    return "KerberosServiceTicketRequested";
                case "1149":
                    return "RemoteDesktopAuthenticated";
                case "21":
                    return "RdpSessionLogon";
                case "24":
                    return "RdpSessionDisconnected";
                case "25":
                    return "RdpSessionReconnected";
            }

            string providerText = (provider ?? "").Trim();
            if (providerText.IndexOf("Windows Defender", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                string threatName = EventLogDataHelper.GetValue(eventData, "Threat Name", "ThreatName", "Name");
                return string.IsNullOrWhiteSpace(threatName) ? "DefenderEvent" : "DefenderThreatEvent";
            }
            if (providerText.IndexOf("TerminalServices", StringComparison.OrdinalIgnoreCase) >= 0 ||
                providerText.IndexOf("RemoteDesktop", StringComparison.OrdinalIgnoreCase) >= 0)
                return "RdpEvent";
            if (providerText.IndexOf("SMB", StringComparison.OrdinalIgnoreCase) >= 0)
                return "SmbEvent";

            return string.IsNullOrWhiteSpace(eventId) ? "Event" : ("EventId " + eventId.Trim());
        }

        private static string BuildDetails(string message, string flattenedEventData)
        {
            string normalizedMessage = EventLogDataHelper.SanitizeSingleLine(message);
            string normalizedEventData = EventLogDataHelper.SanitizeSingleLine(flattenedEventData);

            string details = normalizedMessage;
            if (!string.IsNullOrWhiteSpace(normalizedEventData))
                details = string.IsNullOrWhiteSpace(details) ? normalizedEventData : (details + " | Data: " + normalizedEventData);

            if (details.Length > 900) details = details.Substring(0, 897) + "...";
            return details;
        }

        private static string BuildParserNote(string flattenedEventData, string pathFromMessage)
        {
            bool hasStructuredData = !string.IsNullOrWhiteSpace(flattenedEventData);
            bool hasMessagePath = !string.IsNullOrWhiteSpace(pathFromMessage);

            if (!hasStructuredData && hasMessagePath)
                return "Structured EventData was unavailable; path entity was derived from message text.";
            if (!hasStructuredData)
                return "Structured EventData was unavailable; fact was derived from standard event columns only.";
            if (hasMessagePath)
                return "Structured EventData was available; an additional path entity was derived from message text.";
            return "";
        }

        /// <summary>Phase 3: lateral movement / identity — event-specific entities (facts-only, no verdicts).</summary>
        private static void ApplyPhase3LateralMovementEnrichment(Fact fact, string eventId, IDictionary<string, string> eventData, string computer, string message)
        {
            if (fact == null || eventData == null) return;
            string id = (eventId ?? "").Trim();

            switch (id)
            {
                case "4624":
                case "4625":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    AddEntityIfPresent(fact, "TargetUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "TargetDomainName"),
                        EventLogDataHelper.GetValue(eventData, "TargetUserName")));
                    AddEntityIfPresent(fact, "RemoteIP", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpAddress", "ClientAddress")));
                    break;
                case "4648":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    AddEntityIfPresent(fact, "TargetUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "TargetDomainName"),
                        EventLogDataHelper.GetValue(eventData, "TargetUserName", "TargetUser")));
                    AddEntityIfPresent(fact, "TargetServer", EventLogDataHelper.GetValue(eventData, "TargetServerName", "TargetInfo"));
                    AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "ProcessName"));
                    AddEntityIfPresent(fact, "ProcessId", EventLogDataHelper.GetValue(eventData, "ProcessId"));
                    break;
                case "4672":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    break;
                case "4768":
                    AddEntityIfPresent(fact, "TargetUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "TargetDomainName"),
                        EventLogDataHelper.GetValue(eventData, "TargetUserName")));
                    AddEntityIfPresent(fact, "ServiceName", EventLogDataHelper.GetValue(eventData, "ServiceName"));
                    break;
                case "4769":
                    AddEntityIfPresent(fact, "TargetUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "TargetDomainName"),
                        EventLogDataHelper.GetValue(eventData, "TargetUserName")));
                    AddEntityIfPresent(fact, "ServiceName", EventLogDataHelper.GetValue(eventData, "ServiceName"));
                    break;
                case "4776":
                    AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "AccountName", "UserName"));
                    AddEntityIfPresent(fact, "Workstation", EventLogDataHelper.GetValue(eventData, "Workstation"));
                    break;
                case "5140":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    AddEntityIfPresent(fact, "ShareName", EventLogDataHelper.GetValue(eventData, "ShareName"));
                    AddEntityIfPresent(fact, "ShareLocalPath", EventLogDataHelper.GetValue(eventData, "ShareLocalPath"));
                    AddEntityIfPresent(fact, "RemoteIP", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpAddress", "ClientAddress")));
                    break;
                case "5145":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    AddEntityIfPresent(fact, "ShareName", EventLogDataHelper.GetValue(eventData, "ShareName"));
                    string shareLocal5145 = EventLogDataHelper.GetValue(eventData, "ShareLocalPath");
                    string relTarget5145 = EventLogDataHelper.GetValue(eventData, "RelativeTargetName");
                    AddEntityIfPresent(fact, "ShareLocalPath", shareLocal5145);
                    AddPathEntityIfPresent(fact, relTarget5145);
                    // Also emit the composed absolute path so SMB file-access pivots connect to on-disk
                    // artifacts (MFT/USN/Amcache name absolute paths, not share-relative fragments).
                    if (!string.IsNullOrWhiteSpace(shareLocal5145) && !string.IsNullOrWhiteSpace(relTarget5145))
                        AddPathEntityIfPresent(fact, shareLocal5145.TrimEnd('\\', '/') + "\\" + relTarget5145.TrimStart('\\', '/'));
                    AddEntityIfPresent(fact, "RemoteIP", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpAddress", "ClientAddress")));
                    AddEntityIfPresent(fact, "RemotePort", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "IpPort", "Port")));
                    break;
                case "1149":
                    ApplyRemoteDesktopAuthEntities(fact, eventData, message);
                    break;
                case "4688":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    break;
                case "4697":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName")));
                    AddEntityIfPresent(fact, "ServiceName", EventLogDataHelper.GetValue(eventData, "ServiceName"));
                    AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "ServiceFileName"));
                    AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "ServiceStartName", "AccountName"));
                    break;
                case "7045":
                    AddEntityIfPresent(fact, "ServiceName", EventLogDataHelper.GetValue(eventData, "ServiceName"));
                    AddPathEntityIfPresent(fact, EventLogDataHelper.GetValue(eventData, "ImagePath", "ServiceFileName"));
                    AddEntityIfPresent(fact, "User", EventLogDataHelper.GetValue(eventData, "AccountName", "StartName"));
                    break;
                case "4698":
                case "4702":
                    AddEntityIfPresent(fact, "SubjectUser", FormatAccount(
                        EventLogDataHelper.GetValue(eventData, "SubjectDomainName"),
                        EventLogDataHelper.GetValue(eventData, "SubjectUserName", "SubjectUser")));
                    AddEntityIfPresent(fact, "TaskName", EventLogDataHelper.GetValue(eventData, "TaskName", "Name"));
                    break;
            }
        }

        private static void ApplyRemoteDesktopAuthEntities(Fact fact, IDictionary<string, string> eventData, string message)
        {
            string u = EventLogDataHelper.GetValue(eventData, "User", "UserName");
            string d = EventLogDataHelper.GetValue(eventData, "Domain", "DomainName");
            if (string.IsNullOrWhiteSpace(u))
            {
                u = EventLogDataHelper.GetValue(eventData, "Param2", "Param1");
                d = EventLogDataHelper.GetValue(eventData, "Param1");
                if (string.IsNullOrWhiteSpace(d) || string.Equals(d, u, StringComparison.OrdinalIgnoreCase))
                    d = EventLogDataHelper.GetValue(eventData, "Param3");
            }
            AddEntityIfPresent(fact, "TargetUser", FormatAccount(d, u));
            AddEntityIfPresent(fact, "RemoteIP", NormalizePlaceholder(EventLogDataHelper.GetValue(eventData, "ClientAddress", "ClientIP", "IpAddress", "NASIdentifier", "SourceIp")));
            if (!string.IsNullOrWhiteSpace(message) && !FactHasTargetUserEntity(fact))
                TryAddRdpUserFromMessage(fact, message);
        }

        private static bool FactHasTargetUserEntity(Fact fact)
        {
            if (fact == null || fact.EntityRefs == null) return false;
            foreach (EntityRef er in fact.EntityRefs)
            {
                if (er == null) continue;
                if (!string.Equals(er.Type, "TargetUser", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrWhiteSpace(er.Value)) continue;
                return true;
            }
            return false;
        }

        private static void TryAddRdpUserFromMessage(Fact fact, string message)
        {
            if (string.IsNullOrWhiteSpace(message) || fact == null) return;
            Match m = Regex.Match(message, @"(?i)([A-Za-z0-9\.\-_]+)\\([A-Za-z0-9\.\-_$]+)");
            if (!m.Success) return;
            AddEntityIfPresent(fact, "TargetUser", FormatAccount(m.Groups[1].Value, m.Groups[2].Value));
        }

        private static void AppendPhase3SupplementalParserNote(Fact fact, string eventId, IDictionary<string, string> eventData)
        {
            if (fact == null || eventData == null) return;
            string id = (eventId ?? "").Trim();
            var parts = new List<string>();

            if (id == "4768" || id == "4769")
            {
                string opts = EventLogDataHelper.GetValue(eventData, "TicketOptions", "TicketEncryptionType", "Status", "ResultCode");
                if (!string.IsNullOrWhiteSpace(opts))
                    parts.Add("Kerberos:" + opts);
            }

            if (id == "4776")
            {
                string status = EventLogDataHelper.GetValue(eventData, "Status", "ErrorCode");
                if (!string.IsNullOrWhiteSpace(status))
                    parts.Add("ValidationStatus:" + status);
            }

            if (id == "4698" || id == "4702")
            {
                if (!string.IsNullOrWhiteSpace(EventLogDataHelper.GetValue(eventData, "TaskContent")))
                    parts.Add("ScheduledTaskXmlPresent");
            }

            if (parts.Count == 0) return;
            string extra = string.Join(" | ", parts.ToArray());
            if (string.IsNullOrWhiteSpace(fact.ParserNote))
                fact.ParserNote = extra;
            else
                fact.ParserNote = fact.ParserNote + " | " + extra;
        }

        private static string FormatAccount(string domain, string user)
        {
            string u = NormalizePlaceholder(user ?? "");
            if (string.IsNullOrWhiteSpace(u)) return "";
            string d = NormalizePlaceholder(domain ?? "");
            if (string.IsNullOrWhiteSpace(d)) return u;
            return d + "\\" + u;
        }

        private static void AddPathEntityIfPresent(Fact fact, string path)
        {
            string normalized = NormalizePlaceholder(path);
            if (string.IsNullOrWhiteSpace(normalized)) return;
            fact.AddEntity("Path", normalized);
        }

        private static void AddEntityIfPresent(Fact fact, string type, string value)
        {
            string normalized = NormalizePlaceholder(value);
            if (string.IsNullOrWhiteSpace(normalized)) return;
            fact.AddEntity(type, normalized);
        }

        private static string NormalizePlaceholder(string value)
        {
            string normalized = EventLogDataHelper.SanitizeSingleLine(value);
            if (normalized == "-" || normalized == "N/A" || normalized == "n/a" || normalized == "(null)")
                return "";
            return normalized;
        }

        private static string TryExtractPathFromMessage(string message)
        {
            if (string.IsNullOrWhiteSpace(message)) return null;
            Match m = Regex.Match(message, @"(?i)([A-Z]:\\[^\s""'';]+)");
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
    }
}
