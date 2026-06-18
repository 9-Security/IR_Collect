using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    [DataContract]
    public sealed class GuidedHuntResult
    {
        [DataMember(Name = "enabled")]
        public bool Enabled { get; set; }
        [DataMember(Name = "generated_at")]
        public string GeneratedAt { get; set; }
        [DataMember(Name = "host")]
        public string Host { get; set; }
        [DataMember(Name = "fact_count_evaluated")]
        public int FactCountEvaluated { get; set; }
        [DataMember(Name = "rule_matches")]
        public List<GuidedHuntRuleMatch> RuleMatches { get; set; }
        [DataMember(Name = "hypothesis_templates")]
        public List<GuidedHuntHypothesisTemplate> HypothesisTemplates { get; set; }
        [DataMember(Name = "notes")]
        public List<string> Notes { get; set; }

        public GuidedHuntResult()
        {
            GeneratedAt = DateTime.UtcNow.ToString("o");
            Host = "";
            RuleMatches = new List<GuidedHuntRuleMatch>();
            HypothesisTemplates = new List<GuidedHuntHypothesisTemplate>();
            Notes = new List<string>();
        }
    }

    [DataContract]
    public sealed class GuidedHuntRuleMatch
    {
        [DataMember(Name = "id")]
        public string Id { get; set; }
        [DataMember(Name = "title")]
        public string Title { get; set; }
        [DataMember(Name = "severity")]
        public string Severity { get; set; }
        [DataMember(Name = "summary")]
        public string Summary { get; set; }
        [DataMember(Name = "explanation")]
        public string Explanation { get; set; }
        [DataMember(Name = "attack_tactic")]
        public string AttackTactic { get; set; }
        [DataMember(Name = "attack_technique_id")]
        public string AttackTechniqueId { get; set; }
        [DataMember(Name = "attack_technique_name")]
        public string AttackTechniqueName { get; set; }
        [DataMember(Name = "fact_ids")]
        public List<string> FactIds { get; set; }
        [DataMember(Name = "evidence")]
        public List<string> Evidence { get; set; }
        [DataMember(Name = "suggested_hypothesis_id")]
        public string SuggestedHypothesisId { get; set; }

        public GuidedHuntRuleMatch()
        {
            FactIds = new List<string>();
            Evidence = new List<string>();
        }
    }

    [DataContract]
    public sealed class GuidedHuntHypothesisTemplate
    {
        [DataMember(Name = "id")]
        public string Id { get; set; }
        [DataMember(Name = "title")]
        public string Title { get; set; }
        [DataMember(Name = "question")]
        public string Question { get; set; }
        [DataMember(Name = "why")]
        public string Why { get; set; }
        [DataMember(Name = "related_rule_ids")]
        public List<string> RelatedRuleIds { get; set; }
        [DataMember(Name = "suggested_tags")]
        public List<string> SuggestedTags { get; set; }

        public GuidedHuntHypothesisTemplate()
        {
            RelatedRuleIds = new List<string>();
            SuggestedTags = new List<string>();
        }
    }

    public static class GuidedHuntPack
    {
        public static GuidedHuntResult Evaluate(CaseData c)
        {
            var cfg = new ConfigManager();
            return Evaluate(c, cfg.Get("GuidedHuntEnabled") != "0");
        }

        internal static GuidedHuntResult Evaluate(CaseData c, bool enabled)
        {
            var result = new GuidedHuntResult();
            result.Enabled = enabled;
            result.Host = c != null ? (c.Hostname ?? "") : "";

            List<Fact> facts = c != null && c.FactStore != null && c.FactStore.Facts != null
                ? c.FactStore.Facts.Where(f => f != null).ToList()
                : new List<Fact>();
            result.FactCountEvaluated = facts.Count;

            if (!enabled)
            {
                result.Notes.Add("Guided Hunt Pack is disabled in Settings.");
                return result;
            }

            if (facts.Count == 0)
            {
                result.Notes.Add("No facts available for Guided Hunt evaluation.");
                return result;
            }

            AddRemoteDesktopRule(result, facts);
            AddAdminShareRule(result, facts);
            AddCredentialedRemoteAccessRule(result, facts);
            AddBitsRule(result, facts);
            AddWmiRule(result, facts);
            AddAutorunRule(result, facts);
            AddScheduledTaskRule(result, facts);
            AddServiceRule(result, facts);
            AddPrefetchSideLoadRule(result, facts);

            if (result.RuleMatches.Count == 0)
                result.Notes.Add("No current Guided Hunt rules matched the loaded facts.");
            else
                result.Notes.Add("Guided Hunt matches are explainable leads derived from facts; they are not verdicts and do not modify the underlying Fact Store.");

            return result;
        }

        private static void AddRemoteDesktopRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f =>
                string.Equals(f.Source, "LogonSession", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(f.Action, "RemoteInteractiveSessionObserved", StringComparison.OrdinalIgnoreCase)).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-RDP-001",
                "Remote interactive logon session observed",
                "High",
                "Lateral Movement",
                "T1021.001",
                "Remote Desktop Protocol",
                "GH-HYP-RDP");
            match.Summary = matches.Count.ToString() + " remote interactive logon session fact(s) were observed outside the Event Log dependency path.";
            match.Explanation = "The rule matched live-observed LogonSession facts with LogonType=10 semantics. This can indicate RDP usage and should be correlated with operator approval, source host, and follow-on process activity.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-RDP",
                "Validate remote desktop usage",
                "Were the remote interactive sessions expected administrative activity, or do they reflect unauthorized RDP access or staging?",
                "RemoteInteractiveSessionObserved facts indicate RDP-like interactive access without relying solely on Event Logs.",
                new[] { "GH-RDP-001" },
                new[] { "lateral-movement", "rdp", "identity" });
            result.RuleMatches.Add(match);
        }

        private static void AddAdminShareRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f =>
                (string.Equals(f.Source, "ServerConnection", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(f.Source, "NetworkResource", StringComparison.OrdinalIgnoreCase)) &&
                GetEntityValues(f, "ShareName").Any(v => IsAdminShare(v))).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-SMB-001",
                "Administrative share connection observed",
                "High",
                "Lateral Movement",
                "T1021.002",
                "SMB/Windows Admin Shares",
                "GH-HYP-SMB");
            match.Summary = matches.Count.ToString() + " fact(s) referenced administrative shares such as ADMIN$, C$, or IPC$.";
            match.Explanation = "The rule matched share connections that target built-in administrative shares. In incident response, these often merit review for lateral movement, remote execution staging, or credential reuse.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-SMB",
                "Validate administrative share access",
                "Which account accessed administrative shares, from or to which remote host, and was that access expected in the investigation window?",
                "Administrative share access is commonly associated with remote management and lateral movement workflows.",
                new[] { "GH-SMB-001" },
                new[] { "lateral-movement", "smb", "admin-share" });
            result.RuleMatches.Add(match);
        }

        private static void AddBitsRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f => string.Equals(f.Source, "BITS", StringComparison.OrdinalIgnoreCase)).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-BITS-001",
                "BITS transfer activity observed",
                "Medium",
                "Persistence",
                "T1197",
                "BITS Jobs",
                "GH-HYP-BITS");
            match.Summary = matches.Count.ToString() + " BITS job fact(s) were observed and may reflect background transfer or staging behavior.";
            match.Explanation = "The rule matched BITS facts regardless of remote target type. Review owner account, remote name, and local destination to distinguish benign software distribution from covert transfer or persistence patterns.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-BITS",
                "Review BITS job intent",
                "Do the observed BITS jobs align with approved software deployment, or do they indicate file transfer, download staging, or persistence activity?",
                "BITS jobs can blend into normal background activity while still moving payloads or maintaining access.",
                new[] { "GH-BITS-001" },
                new[] { "bits", "transfer", "persistence" });
            result.RuleMatches.Add(match);
        }

        private static void AddCredentialedRemoteAccessRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> credentialFacts = facts.Where(f => IsCredentialLead(f)).ToList();
            if (credentialFacts.Count == 0)
                return;

            List<Fact> remoteFacts = facts.Where(f => IsRemoteAccessLead(f)).ToList();
            if (remoteFacts.Count == 0)
                return;

            var matchedFacts = new List<Fact>();
            var matchedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var matchedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Fact credentialFact in credentialFacts)
            {
                string[] principals = GetPrincipalValues(credentialFact).ToArray();
                string[] targetServers = GetRemoteTargetValues(credentialFact).ToArray();

                foreach (Fact remoteFact in remoteFacts)
                {
                    bool principalMatched = false;
                    foreach (string principal in principals)
                    {
                        if (GetPrincipalValues(remoteFact).Any(v => string.Equals(v, principal, StringComparison.OrdinalIgnoreCase)))
                        {
                            matchedUsers.Add(principal);
                            principalMatched = true;
                        }
                    }

                    bool targetMatched = false;
                    foreach (string targetServer in targetServers)
                    {
                        if (GetRemoteTargetValues(remoteFact).Any(v => string.Equals(v, targetServer, StringComparison.OrdinalIgnoreCase)))
                        {
                            matchedTargets.Add(targetServer);
                            targetMatched = true;
                        }
                    }

                    if (!principalMatched && !targetMatched)
                        continue;

                    if (!matchedFacts.Contains(credentialFact))
                        matchedFacts.Add(credentialFact);
                    if (!matchedFacts.Contains(remoteFact))
                        matchedFacts.Add(remoteFact);
                }
            }

            if (matchedFacts.Count == 0)
                return;

            var match = CreateMatch(
                "GH-CRED-001",
                "Credential-backed remote access lead",
                "Medium",
                "Lateral Movement",
                "T1078",
                "Valid Accounts",
                "GH-HYP-CRED");
            match.Summary = matchedUsers.Count.ToString() + " principal(s) or " + matchedTargets.Count.ToString() + " remote target(s) showed credential material alongside remote access facts in the loaded case.";
            match.Explanation = "The rule correlates credential-use leads such as ExplicitCredentialUsed, NewCredentials-style logons, stored credentials, or cached Kerberos tickets with remote access facts by matching either principal identity or remote target server. This is a hunt lead for credential reuse or operator-driven lateral movement, not a verdict.";
            PopulateEvidence(match, matchedFacts, 6);
            AddHypothesis(result,
                "GH-HYP-CRED",
                "Validate credential-backed remote access",
                "Did the same user legitimately use alternate credentials for remote access, or does this fact combination indicate lateral movement or credential reuse?",
                "Stored credentials and cached tickets become more important when the same principal or target server also appears in remote access facts such as admin shares or remote sessions.",
                new[] { "GH-CRED-001" },
                new[] { "credentials", "lateral-movement", "identity" });
            result.RuleMatches.Add(match);
        }

        private static void AddWmiRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f => string.Equals(f.Source, "WmiPersistence", StringComparison.OrdinalIgnoreCase)).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-WMI-001",
                "WMI persistence artifact observed",
                "High",
                "Persistence",
                "T1546.003",
                "WMI Event Subscription",
                "GH-HYP-WMI");
            match.Summary = matches.Count.ToString() + " WMI persistence fact(s) were observed.";
            match.Explanation = "The rule matched structured WmiPersistence facts. WMI event filters, consumers, or bindings often warrant direct validation because they can establish stealthy persistence or automated execution.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-WMI",
                "Validate WMI persistence objects",
                "Are the observed WMI filters, consumers, or bindings part of expected management tooling, or do they represent malicious persistence?",
                "WMI persistence is high-signal because it is less common than standard autoruns and can trigger command execution indirectly.",
                new[] { "GH-WMI-001" },
                new[] { "persistence", "wmi", "execution" });
            result.RuleMatches.Add(match);
        }

        private static void AddAutorunRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f =>
                string.Equals(f.Source, "Autorun", StringComparison.OrdinalIgnoreCase) &&
                GetEntityValues(f, "Path").Any(v => IsUserWritableOrTempPath(v))).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-AUTORUN-001",
                "Autorun entry references user-writable or temp path",
                "Medium",
                "Persistence",
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "GH-HYP-AUTORUN");
            match.Summary = matches.Count.ToString() + " autorun fact(s) pointed to AppData, Temp, Public, ProgramData, or other user-writable paths.";
            match.Explanation = "The rule matched Autorun facts whose normalized executable path appears in common user-writable or staging locations. This is not a verdict, but it is a useful persistence hunt lead.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-AUTORUN",
                "Validate autorun persistence path",
                "Does the autorun path belong to approved software, or is it staging from a user-writable location inconsistent with normal persistence?",
                "Run-key persistence that references user-writable paths is a common triage lead and should be compared against signed software and installation context.",
                new[] { "GH-AUTORUN-001" },
                new[] { "persistence", "autorun", "user-writable" });
            result.RuleMatches.Add(match);
        }

        private static void AddScheduledTaskRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f =>
                string.Equals(f.Source, "ScheduledTask", StringComparison.OrdinalIgnoreCase) &&
                (GetEntityValues(f, "Path").Any(v => IsSuspiciousScheduledTaskPath(v)) ||
                 IsSuspiciousTaskArguments(f.Details))).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-TASK-001",
                "Scheduled task references suspicious execution path or arguments",
                "High",
                "Persistence",
                "T1053.005",
                "Scheduled Task",
                "GH-HYP-TASK");
            match.Summary = matches.Count.ToString() + " scheduled task fact(s) referenced user-writable paths, common script interpreters, or suspicious inline task arguments.";
            match.Explanation = "The rule matched scheduled task definitions whose command path or arguments look more like staging or script execution than normal OS maintenance. These facts describe task definitions only and should be correlated with runtime evidence.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-TASK",
                "Validate scheduled task intent",
                "Is the scheduled task an approved administrative or software-maintenance job, or does it establish persistence or delayed execution from a suspicious path?",
                "Scheduled tasks that launch from user-writable locations or through generic interpreters are common persistence and execution leads.",
                new[] { "GH-TASK-001" },
                new[] { "persistence", "scheduled-task", "execution" });
            result.RuleMatches.Add(match);
        }

        private static void AddServiceRule(GuidedHuntResult result, List<Fact> facts)
        {
            List<Fact> matches = facts.Where(f =>
                (string.Equals(f.Source, "Service", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(f.Action, "ServiceInstalled", StringComparison.OrdinalIgnoreCase)) &&
                GetEntityValues(f, "Path").Any(v => IsTaskOrServiceSuspiciousPath(v) || IsPotentialUnquotedServicePath(v))).ToList();
            if (matches.Count == 0)
                return;

            var match = CreateMatch(
                "GH-SVC-001",
                "Service path suggests suspicious persistence or execution",
                "High",
                "Persistence",
                "T1543.003",
                "Windows Service",
                "GH-HYP-SVC");
            match.Summary = matches.Count.ToString() + " service fact(s) referenced user-writable, interpreter-driven, or potentially unsafe service paths.";
            match.Explanation = "The rule matched current service configuration or service-install facts where the binary path points to user-writable locations, common interpreter binaries, or resembles an unquoted service path. Review service ownership and installation context before drawing conclusions.";
            PopulateEvidence(match, matches, 4);
            AddHypothesis(result,
                "GH-HYP-SVC",
                "Validate service persistence path",
                "Does the service path and start configuration align with legitimate software, or does it indicate service-based persistence or execution from an unsafe location?",
                "Windows services are a durable persistence surface. Paths outside normal system locations or interpreter-based launch patterns deserve review.",
                new[] { "GH-SVC-001" },
                new[] { "persistence", "service", "execution" });
            result.RuleMatches.Add(match);
        }

        private static void AddPrefetchSideLoadRule(GuidedHuntResult result, List<Fact> facts)
        {
            // Prefetch records the files an executable loaded at startup. PrefetchNormalizer only attaches
            // a ReferencedFile entity when that file was loaded from a user-writable / non-system path
            // (Users / Temp / AppData / ProgramData / Downloads) - a hallmark of DLL side-loading.
            List<Fact> matches = facts.Where(f =>
                f != null && string.Equals(f.Source, "Prefetch", StringComparison.OrdinalIgnoreCase) &&
                GetEntityValues(f, "ReferencedFile").Any()).ToList();
            if (matches.Count == 0)
                return;

            int exeCount = matches.SelectMany(f => GetEntityValues(f, "FileName"))
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();

            var match = CreateMatch(
                "GH-PF-SIDELOAD-001",
                "Executable loaded a file from a user-writable location (possible DLL side-loading)",
                "High",
                "Defense Evasion",
                "T1574.002",
                "Hijack Execution Flow: DLL Side-Loading",
                "GH-HYP-PF-SIDELOAD");
            match.Summary = matches.Count.ToString() + " Prefetch execution fact(s) across " + exeCount
                + " executable(s) loaded a file from a user-writable / non-system path (Users / Temp / AppData / ProgramData / Downloads).";
            match.Explanation = "Loading a DLL or module from a user-writable location rather than System32 / WinSxS / Program Files is a hallmark of DLL side-loading and masquerading. Confirm the loaded file's Authenticode signature and whether the legitimate vendor ships it from that path.";
            PopulateEvidence(match, matches, 6);
            AddHypothesis(result,
                "GH-HYP-PF-SIDELOAD",
                "Confirm side-loaded module",
                "Is the file loaded from the user-writable location a legitimate component of the executable, or a planted / masqueraded module (DLL side-loading)?",
                "Adversaries place a malicious DLL next to (or in the search path of) a trusted signed executable so it loads their code; Prefetch's referenced-files list surfaces exactly which non-system files were loaded.",
                new[] { "GH-PF-SIDELOAD-001" },
                new[] { "execution", "dll-side-loading", "defense-evasion", "prefetch" });
            result.RuleMatches.Add(match);
        }

        private static GuidedHuntRuleMatch CreateMatch(string id, string title, string severity, string tactic, string techniqueId, string techniqueName, string hypothesisId)
        {
            return new GuidedHuntRuleMatch
            {
                Id = id,
                Title = title,
                Severity = severity,
                AttackTactic = tactic,
                AttackTechniqueId = techniqueId,
                AttackTechniqueName = techniqueName,
                SuggestedHypothesisId = hypothesisId
            };
        }

        private static void PopulateEvidence(GuidedHuntRuleMatch match, List<Fact> facts, int maxEvidence)
        {
            if (match == null || facts == null)
                return;

            List<Fact> ordered = facts
                .OrderByDescending(f => f != null && FactTimeMetadata.HasUsableTime(f.Time) ? f.Time : DateTime.MinValue)
                .ThenBy(f => f != null ? (f.Id ?? "") : "")
                .ToList();
            foreach (Fact fact in ordered.Take(maxEvidence))
            {
                if (fact == null)
                    continue;
                match.FactIds.Add(fact.Id ?? "");
                match.Evidence.Add(BuildEvidenceLine(fact));
            }
        }

        private static string BuildEvidenceLine(Fact fact)
        {
            string time = FactTimeMetadata.HasUsableTime(fact.Time) ? fact.Time.ToString("o") : "(time unavailable)";
            string user = FirstEntity(fact, "User");
            string path = FirstEntity(fact, "Path");
            string remote = FirstEntity(fact, "RemoteName");
            if (string.IsNullOrWhiteSpace(remote))
                remote = FirstEntity(fact, "Workstation");
            if (string.IsNullOrWhiteSpace(remote))
                remote = FirstEntity(fact, "TargetServer");
            string share = FirstEntity(fact, "ShareName");
            string fileName = FirstEntity(fact, "FileName");
            string loaded = FirstEntity(fact, "ReferencedFile");

            string detail = fact.Details ?? "";
            if (detail.Length > 120)
                detail = detail.Substring(0, 117) + "...";

            var parts = new List<string>();
            parts.Add(time);
            parts.Add(fact.Source + "/" + fact.Action);
            if (!string.IsNullOrWhiteSpace(user))
                parts.Add("user=" + user);
            if (!string.IsNullOrWhiteSpace(remote))
                parts.Add("remote=" + remote);
            if (!string.IsNullOrWhiteSpace(share))
                parts.Add("share=" + share);
            if (!string.IsNullOrWhiteSpace(fileName))
                parts.Add("file=" + fileName);
            if (!string.IsNullOrWhiteSpace(loaded))
                parts.Add("loaded=" + loaded);
            if (!string.IsNullOrWhiteSpace(path))
                parts.Add("path=" + path);
            if (!string.IsNullOrWhiteSpace(detail))
                parts.Add("detail=" + detail);
            return string.Join(" | ", parts.ToArray());
        }

        private static void AddHypothesis(GuidedHuntResult result, string id, string title, string question, string why, IEnumerable<string> relatedRuleIds, IEnumerable<string> tags)
        {
            if (result == null || result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, id, StringComparison.OrdinalIgnoreCase)))
                return;

            var hypothesis = new GuidedHuntHypothesisTemplate();
            hypothesis.Id = id;
            hypothesis.Title = title;
            hypothesis.Question = question;
            hypothesis.Why = why;
            hypothesis.RelatedRuleIds = relatedRuleIds != null ? relatedRuleIds.ToList() : new List<string>();
            hypothesis.SuggestedTags = tags != null ? tags.ToList() : new List<string>();
            result.HypothesisTemplates.Add(hypothesis);
        }

        private static IEnumerable<string> GetEntityValues(Fact fact, string type)
        {
            if (fact == null || fact.EntityRefs == null || string.IsNullOrWhiteSpace(type))
                return Enumerable.Empty<string>();

            return fact.EntityRefs
                .Where(e => e != null &&
                            string.Equals(e.Type, type, StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrWhiteSpace(e.Value))
                .Select(e => e.Value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static string FirstEntity(Fact fact, string type)
        {
            return GetEntityValues(fact, type).FirstOrDefault() ?? "";
        }

        private static IEnumerable<string> GetPrincipalValues(Fact fact)
        {
            return GetEntityValues(fact, "User")
                .Concat(GetEntityValues(fact, "TargetUser"))
                .Concat(GetEntityValues(fact, "SubjectUser"))
                .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> GetRemoteTargetValues(Fact fact)
        {
            return GetEntityValues(fact, "TargetServer")
                .Concat(GetEntityValues(fact, "RemoteName"))
                .Concat(GetEntityValues(fact, "Workstation"))
                .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static bool IsCredentialLead(Fact fact)
        {
            if (fact == null)
                return false;

            if (string.Equals(fact.Action, "ExplicitCredentialUsed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fact.Action, "KerberosServiceTicketRequested", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fact.Source, "StoredCredential", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fact.Source, "KerberosTicketCache", StringComparison.OrdinalIgnoreCase))
                return true;

            return string.Equals(fact.Source, "LogonSession", StringComparison.OrdinalIgnoreCase) &&
                GetEntityValues(fact, "LogonType").Any(v => string.Equals(v, "9", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsRemoteAccessLead(Fact fact)
        {
            if (fact == null)
                return false;

            if (string.Equals(fact.Source, "ServerConnection", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fact.Source, "NetworkResource", StringComparison.OrdinalIgnoreCase))
                return true;

            return string.Equals(fact.Source, "LogonSession", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(fact.Action, "RemoteInteractiveSessionObserved", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(fact.Action, "NetworkLogonSessionObserved", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsAdminShare(string value)
        {
            string share = (value ?? "").Trim();
            if (share.Length == 0)
                return false;
            return string.Equals(share, "ADMIN$", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(share, "IPC$", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(share, "C$", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(share, "D$", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTaskOrServiceSuspiciousPath(string value)
        {
            return IsUserWritableOrTempPath(value) || IsInterpreterOrScriptPath(value);
        }

        private static bool IsSuspiciousScheduledTaskPath(string value)
        {
            return IsUserWritableOrTempPath(value) || IsScriptPath(value);
        }

        private static bool IsUserWritableOrTempPath(string value)
        {
            string path = (value ?? "").Trim();
            if (path.Length == 0)
                return false;
            string normalized = path.ToLowerInvariant();
            return normalized.Contains("\\users\\") ||
                normalized.Contains("\\appdata\\") ||
                normalized.Contains("\\temp\\") ||
                normalized.Contains("\\public\\") ||
                normalized.Contains("\\programdata\\");
        }

        private static bool IsInterpreterOrScriptPath(string value)
        {
            string path = (value ?? "").Trim();
            if (path.Length == 0)
                return false;

            string normalized = path.ToLowerInvariant();
            return IsInterpreterBinaryPath(normalized) ||
                IsScriptPath(normalized);
        }

        private static bool IsInterpreterBinaryPath(string normalizedPath)
        {
            string normalized = (normalizedPath ?? "").Trim().ToLowerInvariant();
            if (normalized.Length == 0)
                return false;
            return normalized.EndsWith("\\cmd.exe") ||
                normalized.EndsWith("\\powershell.exe") ||
                normalized.EndsWith("\\pwsh.exe") ||
                normalized.EndsWith("\\wscript.exe") ||
                normalized.EndsWith("\\cscript.exe") ||
                normalized.EndsWith("\\rundll32.exe") ||
                normalized.EndsWith("\\regsvr32.exe") ||
                normalized.EndsWith("\\mshta.exe");
        }

        private static bool IsScriptPath(string normalizedPath)
        {
            string normalized = (normalizedPath ?? "").Trim().ToLowerInvariant();
            if (normalized.Length == 0)
                return false;
            return normalized.EndsWith(".cmd") ||
                normalized.EndsWith(".bat") ||
                normalized.EndsWith(".ps1") ||
                normalized.EndsWith(".vbs") ||
                normalized.EndsWith(".js");
        }

        private static bool IsSuspiciousTaskArguments(string details)
        {
            string text = (details ?? "").ToLowerInvariant();
            if (text.Length == 0)
                return false;

            return text.Contains(" -enc") ||
                text.Contains(" -encodedcommand") ||
                text.Contains(" /c ") ||
                text.Contains(" -nop") ||
                text.Contains("\\users\\") ||
                text.Contains("\\temp\\") ||
                text.Contains("\\public\\");
        }

        private static bool IsPotentialUnquotedServicePath(string value)
        {
            string text = (value ?? "").Trim();
            if (text.Length == 0 || text.StartsWith("\"", StringComparison.Ordinal))
                return false;

            int exeIndex = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeIndex < 0)
                return false;

            string prefix = text.Substring(0, exeIndex + 4);
            return prefix.IndexOf(' ') >= 0;
        }
    }
}
