using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using IR_Collect.Analysis.Correlation;
using IR_Collect;

namespace IR_Collect.Analysis
{
    /// <summary>Deterministic literal masking for AI-bound Summary JSON only (not file export verdicts).</summary>
    public static class SummaryPayloadAiRedactor
    {
        /// <summary>Bound every redaction match. These run on attacker-influenced free text
        /// (stdout/stderr tails, ParserNotes, fact Details) right before the AI handoff, so a
        /// crafted artifact must not be able to peg CPU / hang the redaction pass (ReDoS).</summary>
        private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(1);
        private static readonly Regex RxIpv4 = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxEmail = new Regex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxIpv6Bracket = new Regex(@"\[(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\]", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        /// <summary>UNC or drive-based Windows paths (segment-wise, conservative invalid-char set).</summary>
        private static readonly Regex RxUncPath = new Regex(@"\\\\[^\\/:?\s""<>|]+(?:\\[^\\/:?\s""<>|]+)+", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        /// <summary>D:\ style paths with one or more segments.</summary>
        private static readonly Regex RxDrivePath = new Regex(@"[A-Za-z]:(?:\\[^\\/:*?""<>|\r\n]+)+", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        /// <summary>Forward-slash drive paths sometimes seen in mixed args.</summary>
        private static readonly Regex RxDrivePathFwd = new Regex(@"[A-Za-z]:(?:/[^/:*?""<>|\r\n]+)+", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        /// <summary>/home or /Users profile paths. Head segment excludes '/' so it does not overlap
        /// the trailing segment group (which would make matching ambiguous / catastrophic).</summary>
        private static readonly Regex RxUnixProfilePath = new Regex(@"(?i)/(?:home|Users)/[^/:\s""]+(?:/[^/:\s""]+)*", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxKnownProfileEnvToken = new Regex(@"(?i)%(?:userprofile|homedrive|homepath|username|localappdata|appdata|temp)%", RegexOptions.Compiled | RegexOptions.CultureInvariant, RxTimeout);

        public static string NormalizeProfile(string raw)
        {
            string t = (raw ?? "").Trim();
            if (string.Equals(t, "None", StringComparison.OrdinalIgnoreCase)) return "None";
            if (string.Equals(t, "Basic", StringComparison.OrdinalIgnoreCase)) return "Basic";
            if (string.Equals(t, "Strict", StringComparison.OrdinalIgnoreCase)) return "Strict";
            return "Basic";
        }

        public static void Apply(SummaryPayload payload, string profileNormalized)
        {
            if (payload == null)
                return;
            if (profileNormalized == "None")
                return;
            DetachSharedPayloadState(payload);
            if (profileNormalized == "Basic")
            {
                ApplyBasic(payload);
                return;
            }
            if (profileNormalized == "Strict")
            {
                ApplyStrict(payload);
            }
        }

        /// <summary>
        /// SummaryExport.CloneForSerialization shallow-copies several collections/metadata references from the live case.
        /// Detach before mutating so redaction never rewrites in-memory CaseData.
        /// </summary>
        private static void DetachSharedPayloadState(SummaryPayload p)
        {
            if (p == null) return;
            if (p.EventHighlights != null)
                p.EventHighlights = new List<string>(p.EventHighlights);
            if (p.LoadWarnings != null)
                p.LoadWarnings = new List<string>(p.LoadWarnings);
            if (p.ParserNotes != null)
                p.ParserNotes = new List<string>(p.ParserNotes);
            p.CollectionCoverage = CloneCoverageReport(p.CollectionCoverage);
            if (p.AnalystWorkflow != null)
            {
                var w = p.AnalystWorkflow;
                var nw = new AnalystWorkflowState();
                nw.Bookmarked = w.Bookmarked;
                nw.Priority = w.Priority ?? "";
                nw.Hypothesis = w.Hypothesis ?? "";
                nw.Notes = w.Notes ?? "";
                nw.UpdatedAt = w.UpdatedAt ?? "";
                nw.Tags = w.Tags != null ? new List<string>(w.Tags) : new List<string>();
                p.AnalystWorkflow = nw;
            }
            if (p.GuidedHunt != null)
                p.GuidedHunt = CloneGuidedHunt(p.GuidedHunt);
            if (p.MemoryAcquisition != null)
                p.MemoryAcquisition = CloneMemoryAcquisition(p.MemoryAcquisition);
            if (p.MemoryAnalysis != null)
                p.MemoryAnalysis = CloneMemoryAnalysis(p.MemoryAnalysis);
        }

        private static CollectionCoverageReport CloneCoverageReport(CollectionCoverageReport src)
        {
            if (src == null) return null;
            var d = new CollectionCoverageReport();
            d.GeneratedAt = src.GeneratedAt;
            d.Host = src.Host;
            d.EvidenceId = src.EvidenceId;
            d.CollectorUser = src.CollectorUser;
            d.CollectorPrivilegeState = src.CollectorPrivilegeState;
            d.IsAdministrator = src.IsAdministrator;
            d.BackupPrivilegeEnabled = src.BackupPrivilegeEnabled;
            d.BackupPrivilegeStatus = src.BackupPrivilegeStatus;
            d.OverallStatus = src.OverallStatus;
            d.CompletedSteps = src.CompletedSteps;
            d.PartialSteps = src.PartialSteps;
            d.FailedSteps = src.FailedSteps;
            d.SkippedSteps = src.SkippedSteps;
            d.MissingSteps = src.MissingSteps;
            d.Steps = new List<CollectionCoverageStep>();
            if (src.Steps != null)
            {
                foreach (CollectionCoverageStep step in src.Steps)
                {
                    if (step == null) continue;
                    var st = new CollectionCoverageStep();
                    st.Step = step.Step;
                    st.Status = step.Status;
                    st.Detail = step.Detail;
                    st.ArtifactCount = step.ArtifactCount;
                    st.ArtifactsPresent = step.ArtifactsPresent != null ? new List<string>(step.ArtifactsPresent) : new List<string>();
                    st.ArtifactsMissing = step.ArtifactsMissing != null ? new List<string>(step.ArtifactsMissing) : new List<string>();
                    d.Steps.Add(st);
                }
            }
            return d;
        }

        private static MemoryAcquisitionRecord CloneMemoryAcquisition(MemoryAcquisitionRecord src)
        {
            if (src == null) return null;
            var d = new MemoryAcquisitionRecord();
            d.Schema = src.Schema;
            d.Status = src.Status;
            d.Detail = src.Detail;
            d.ToolPath = src.ToolPath;
            d.ToolArgs = src.ToolArgs;
            d.ArgsPreset = src.ArgsPreset;
            d.OutputRelativePath = src.OutputRelativePath;
            d.StartedAtUtc = src.StartedAtUtc;
            d.EndedAtUtc = src.EndedAtUtc;
            d.DurationMs = src.DurationMs;
            d.ExitCode = src.ExitCode;
            d.StdoutTail = src.StdoutTail;
            d.StderrTail = src.StderrTail;
            d.OutputFileSizeBytes = src.OutputFileSizeBytes;
            d.OutputSha256 = src.OutputSha256;
            d.CollectorUser = src.CollectorUser;
            d.CollectorWasAdmin = src.CollectorWasAdmin;
            d.ConfigRequiresAdmin = src.ConfigRequiresAdmin;
            d.ConfigSkipIfNotElevated = src.ConfigSkipIfNotElevated;
            d.TimeoutSecConfigured = src.TimeoutSecConfigured;
            d.ValidationMode = src.ValidationMode;
            d.ValidationStatus = src.ValidationStatus;
            d.ValidationDetail = src.ValidationDetail;
            d.DiagnosticCategory = src.DiagnosticCategory;
            d.DiagnosticDetail = src.DiagnosticDetail;
            return d;
        }

        private static MemoryAnalysisRecord CloneMemoryAnalysis(MemoryAnalysisRecord src)
        {
            if (src == null) return null;
            var d = new MemoryAnalysisRecord();
            d.Schema = src.Schema;
            d.Status = src.Status;
            d.Detail = src.Detail;
            d.ToolPath = src.ToolPath;
            d.ToolArgs = src.ToolArgs;
            d.ArgsPreset = src.ArgsPreset;
            d.InputRelativePath = src.InputRelativePath;
            d.OutputDirectoryRelativePath = src.OutputDirectoryRelativePath;
            d.OutputFileCount = src.OutputFileCount;
            d.OutputTotalBytes = src.OutputTotalBytes;
            d.StartedAtUtc = src.StartedAtUtc;
            d.EndedAtUtc = src.EndedAtUtc;
            d.DurationMs = src.DurationMs;
            d.ExitCode = src.ExitCode;
            d.StdoutTail = src.StdoutTail;
            d.StderrTail = src.StderrTail;
            d.CollectorUser = src.CollectorUser;
            d.CollectorWasAdmin = src.CollectorWasAdmin;
            d.TimeoutSecConfigured = src.TimeoutSecConfigured;
            d.OutputFiles = src.OutputFiles != null ? new List<string>(src.OutputFiles) : new List<string>();
            d.ValidationMode = src.ValidationMode;
            d.ValidationStatus = src.ValidationStatus;
            d.ValidationDetail = src.ValidationDetail;
            d.RequiredOutputPatterns = src.RequiredOutputPatterns != null ? new List<string>(src.RequiredOutputPatterns) : new List<string>();
            d.MatchedOutputPatterns = src.MatchedOutputPatterns != null ? new List<string>(src.MatchedOutputPatterns) : new List<string>();
            d.MissingOutputPatterns = src.MissingOutputPatterns != null ? new List<string>(src.MissingOutputPatterns) : new List<string>();
            d.DiagnosticCategory = src.DiagnosticCategory;
            d.DiagnosticDetail = src.DiagnosticDetail;
            return d;
        }

        private static GuidedHuntResult CloneGuidedHunt(GuidedHuntResult src)
        {
            if (src == null) return null;
            var d = new GuidedHuntResult();
            d.Enabled = src.Enabled;
            d.GeneratedAt = src.GeneratedAt;
            d.Host = src.Host;
            d.FactCountEvaluated = src.FactCountEvaluated;
            d.Notes = src.Notes != null ? new List<string>(src.Notes) : new List<string>();
            d.RuleMatches = new List<GuidedHuntRuleMatch>();
            if (src.RuleMatches != null)
            {
                foreach (GuidedHuntRuleMatch match in src.RuleMatches)
                {
                    if (match == null) continue;
                    var m = new GuidedHuntRuleMatch();
                    m.Id = match.Id;
                    m.Title = match.Title;
                    m.Severity = match.Severity;
                    m.Summary = match.Summary;
                    m.Explanation = match.Explanation;
                    m.AttackTactic = match.AttackTactic;
                    m.AttackTechniqueId = match.AttackTechniqueId;
                    m.AttackTechniqueName = match.AttackTechniqueName;
                    m.SuggestedHypothesisId = match.SuggestedHypothesisId;
                    m.FactIds = match.FactIds != null ? new List<string>(match.FactIds) : new List<string>();
                    m.Evidence = match.Evidence != null ? new List<string>(match.Evidence) : new List<string>();
                    d.RuleMatches.Add(m);
                }
            }
            d.HypothesisTemplates = new List<GuidedHuntHypothesisTemplate>();
            if (src.HypothesisTemplates != null)
            {
                foreach (GuidedHuntHypothesisTemplate hypothesis in src.HypothesisTemplates)
                {
                    if (hypothesis == null) continue;
                    var h = new GuidedHuntHypothesisTemplate();
                    h.Id = hypothesis.Id;
                    h.Title = hypothesis.Title;
                    h.Question = hypothesis.Question;
                    h.Why = hypothesis.Why;
                    h.RelatedRuleIds = hypothesis.RelatedRuleIds != null ? new List<string>(hypothesis.RelatedRuleIds) : new List<string>();
                    h.SuggestedTags = hypothesis.SuggestedTags != null ? new List<string>(hypothesis.SuggestedTags) : new List<string>();
                    d.HypothesisTemplates.Add(h);
                }
            }
            return d;
        }

        private static void ApplyBasic(SummaryPayload p)
        {
            if (!string.IsNullOrEmpty(p.Host))
                p.Host = "[redacted]";
            if (!string.IsNullOrEmpty(p.CaseId))
                p.CaseId = "[redacted]";

            p.FactStoreFreshnessDetail = MaskPathLikeAfterLiterals(p.FactStoreFreshnessDetail);

            if (p.EventHighlights != null)
            {
                for (int i = 0; i < p.EventHighlights.Count; i++)
                    p.EventHighlights[i] = MaskPathLikeAfterLiterals(p.EventHighlights[i]);
            }
            if (p.LoadWarnings != null)
            {
                for (int i = 0; i < p.LoadWarnings.Count; i++)
                    p.LoadWarnings[i] = MaskPathLikeAfterLiterals(p.LoadWarnings[i]);
            }
            if (p.ParserNotes != null)
            {
                for (int i = 0; i < p.ParserNotes.Count; i++)
                    p.ParserNotes[i] = MaskPathLikeAfterLiterals(p.ParserNotes[i]);
            }

            RedactGuidedHuntBasic(p.GuidedHunt);
            RedactMemoryBasic(p.MemoryAcquisition);
            RedactMemoryBasic(p.MemoryAnalysis);

            if (p.FactSamples != null)
            {
                foreach (Fact f in p.FactSamples)
                {
                    if (f == null) continue;
                    f.Details = MaskPathLikeAfterLiterals(f.Details);
                    f.RawRef = MaskPathLikeAfterLiterals(f.RawRef);
                    f.ParserNote = MaskPathLikeAfterLiterals(f.ParserNote);
                    f.SourceFile = BasenameOnly(f.SourceFile);
                    if (f.EntityRefs != null)
                    {
                        foreach (EntityRef er in f.EntityRefs)
                        {
                            if (er == null) continue;
                            er.Value = MaskPathLikeAfterLiterals(er.Value);
                        }
                    }
                }
            }

            RedactWorkflowBasic(p.AnalystWorkflow);
            RedactCoverageBasic(p.CollectionCoverage);
        }

        private static void ApplyStrict(SummaryPayload p)
        {
            p.Host = "[redacted]";
            p.CaseId = "[redacted]";
            p.FactStoreFreshnessDetail = "";
            p.EventHighlights = new List<string>();
            p.LoadWarnings = new List<string>();
            p.ParserNotes = new List<string>
            {
                "Strict AI redaction: sampled narratives, workflow text, and collection coverage detail were removed; aggregate counts and fact totals may remain."
            };
            p.FactSamples = new List<Fact>();
            p.CollectionCoverage = null;
            p.GuidedHunt = null;
            p.MemoryAcquisition = null;
            p.MemoryAnalysis = null;

            if (p.AnalystWorkflow != null)
            {
                p.AnalystWorkflow.Hypothesis = "";
                p.AnalystWorkflow.Notes = "";
                p.AnalystWorkflow.Priority = "";
                if (p.AnalystWorkflow.Tags != null)
                    p.AnalystWorkflow.Tags.Clear();
            }
        }

        private static void RedactMemoryBasic(MemoryAcquisitionRecord r)
        {
            if (r == null) return;
            r.Detail = MaskPathLikeAfterLiterals(r.Detail);
            r.ToolPath = BasenameOnly(r.ToolPath);
            r.ToolArgs = MaskPathLikeAfterLiterals(r.ToolArgs);
            r.OutputRelativePath = BasenameOnly(r.OutputRelativePath);
            r.StdoutTail = MaskPathLikeAfterLiterals(r.StdoutTail);
            r.StderrTail = MaskPathLikeAfterLiterals(r.StderrTail);
            if (!string.IsNullOrEmpty(r.OutputSha256))
                r.OutputSha256 = "[sha256_redacted]";
            r.CollectorUser = MaskPrincipalIdentityForBasic(r.CollectorUser);
        }

        private static void RedactMemoryBasic(MemoryAnalysisRecord r)
        {
            if (r == null) return;
            r.Detail = MaskPathLikeAfterLiterals(r.Detail);
            r.ToolPath = BasenameOnly(r.ToolPath);
            r.ToolArgs = MaskPathLikeAfterLiterals(r.ToolArgs);
            r.InputRelativePath = BasenameOnly(r.InputRelativePath);
            r.OutputDirectoryRelativePath = BasenameOnly(r.OutputDirectoryRelativePath);
            r.StdoutTail = MaskPathLikeAfterLiterals(r.StdoutTail);
            r.StderrTail = MaskPathLikeAfterLiterals(r.StderrTail);
            if (r.OutputFiles != null)
            {
                for (int i = 0; i < r.OutputFiles.Count; i++)
                    r.OutputFiles[i] = BasenameOnly(r.OutputFiles[i]);
            }
            r.CollectorUser = MaskPrincipalIdentityForBasic(r.CollectorUser);
        }

        private static void RedactWorkflowBasic(AnalystWorkflowState w)
        {
            if (w == null) return;
            w.Hypothesis = MaskPathLikeAfterLiterals(w.Hypothesis);
            w.Notes = MaskPathLikeAfterLiterals(w.Notes);
            if (w.Tags != null)
            {
                for (int i = 0; i < w.Tags.Count; i++)
                    w.Tags[i] = MaskPathLikeAfterLiterals(w.Tags[i]);
            }
        }

        private static void RedactGuidedHuntBasic(GuidedHuntResult result)
        {
            if (result == null) return;
            if (!string.IsNullOrEmpty(result.Host))
                result.Host = "[redacted]";
            if (result.Notes != null)
            {
                for (int i = 0; i < result.Notes.Count; i++)
                    result.Notes[i] = MaskPathLikeAfterLiterals(result.Notes[i]);
            }
            if (result.RuleMatches != null)
            {
                foreach (GuidedHuntRuleMatch match in result.RuleMatches)
                {
                    if (match == null) continue;
                    match.Summary = MaskPathLikeAfterLiterals(match.Summary);
                    match.Explanation = MaskPathLikeAfterLiterals(match.Explanation);
                    if (match.Evidence != null)
                    {
                        for (int i = 0; i < match.Evidence.Count; i++)
                            match.Evidence[i] = MaskPathLikeAfterLiterals(match.Evidence[i]);
                    }
                }
            }
            if (result.HypothesisTemplates != null)
            {
                foreach (GuidedHuntHypothesisTemplate hypothesis in result.HypothesisTemplates)
                {
                    if (hypothesis == null) continue;
                    hypothesis.Question = MaskPathLikeAfterLiterals(hypothesis.Question);
                    hypothesis.Why = MaskPathLikeAfterLiterals(hypothesis.Why);
                    if (hypothesis.SuggestedTags != null)
                    {
                        for (int i = 0; i < hypothesis.SuggestedTags.Count; i++)
                            hypothesis.SuggestedTags[i] = MaskPathLikeAfterLiterals(hypothesis.SuggestedTags[i]);
                    }
                }
            }
        }

        private static void RedactCoverageBasic(CollectionCoverageReport report)
        {
            if (report == null) return;
            if (!string.IsNullOrEmpty(report.Host))
                report.Host = "[redacted]";
            if (!string.IsNullOrEmpty(report.EvidenceId))
                report.EvidenceId = "[redacted]";
            if (!string.IsNullOrEmpty(report.CollectorUser))
                report.CollectorUser = "[redacted]";
            if (report.Steps == null) return;
            foreach (CollectionCoverageStep step in report.Steps)
            {
                if (step == null) continue;
                step.Detail = RedactLiterals(step.Detail);
                if (step.ArtifactsPresent != null)
                {
                    for (int i = 0; i < step.ArtifactsPresent.Count; i++)
                        step.ArtifactsPresent[i] = BasenameOnly(step.ArtifactsPresent[i]);
                }
                if (step.ArtifactsMissing != null)
                {
                    for (int i = 0; i < step.ArtifactsMissing.Count; i++)
                        step.ArtifactsMissing[i] = BasenameOnly(step.ArtifactsMissing[i]);
                }
            }
        }

        private static string RedactLiterals(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            try
            {
                string x = RxIpv4.Replace(s, "[ipv4]");
                x = RxIpv6Bracket.Replace(x, "[ipv6]");
                x = RxEmail.Replace(x, "[email]");
                return x;
            }
            catch (RegexMatchTimeoutException)
            {
                // Fail closed: never let a crafted value bypass redaction by timing out.
                return "[redacted]";
            }
        }

        /// <summary>
        /// Windows-style account strings (e.g. DOMAIN\user) for sidecar operator fields — not drive paths (X:\).
        /// </summary>
        private static string MaskPrincipalIdentityForBasic(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            string t = s.Trim();
            if (t.Length >= 3 && char.IsLetter(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/'))
                return MaskPathLikeAfterLiterals(s);
            int bs = t.IndexOf('\\');
            if (bs > 0 && bs < t.Length - 1)
                return "[user_redacted]";
            return MaskPathLikeAfterLiterals(s);
        }

        /// <summary>High-risk free text: network literals then path-like tokens (used across Basic narrative fields and memory tool strings).</summary>
        private static string MaskPathLikeAfterLiterals(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            try
            {
                string x = RedactLiterals(s);
                x = RxKnownProfileEnvToken.Replace(x, "[env_redacted]");
                x = RxUncPath.Replace(x, "[path_redacted]");
                x = RxDrivePath.Replace(x, "[path_redacted]");
                x = RxDrivePathFwd.Replace(x, "[path_redacted]");
                x = RxUnixProfilePath.Replace(x, "[path_redacted]");
                return x;
            }
            catch (RegexMatchTimeoutException)
            {
                // Fail closed: never let a crafted value bypass redaction by timing out.
                return "[redacted]";
            }
        }

        private static string BasenameOnly(string path)
        {
            if (string.IsNullOrEmpty(path)) return path ?? "";
            try
            {
                string t = path.Trim();
                char c = t.Length > 0 ? t[t.Length - 1] : ' ';
                if (c == '\\' || c == '/')
                    return "";
                return Path.GetFileName(t);
            }
            catch
            {
                return "";
            }
        }
    }
}
