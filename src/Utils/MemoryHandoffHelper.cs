using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using IR_Collect;

namespace IR_Collect.Utils
{
    /// <summary>
    /// Shared args templates, output validation, diagnostics, and analyst-facing guidance for memory acquisition / analysis handoff.
    /// Facts-only: describes orchestration and disk state, not memory content verdicts.
    /// </summary>
    public static class MemoryHandoffHelper
    {
        public const string AcquirePresetCustom = "custom";
        public const string AcquirePresetQuotedOutput = "quoted_output";
        public const string AcquirePresetWinPmemO = "winpmem_o";
        public const string AcquirePresetWinPmemRaw = "winpmem_raw";

        public const string AnalyzePresetCustom = "custom";
        public const string AnalyzePresetDualQuoted = "dual_quoted";
        public const string AnalyzePresetInputOutputFlags = "input_output_flags";
        public const string AnalyzePresetVolatility3OutputDir = "volatility3_output_dir";

        public const string AcquireValidationExistsOnly = "exists_only";
        public const string AcquireValidationMinSize = "min_size";

        public const string AnalyzeValidationDirectoryHasFiles = "directory_has_files";
        public const string AnalyzeValidationRequiredPatterns = "required_patterns";

        /// <summary>Shown in Summary tab, HTML, summary parser notes, and full_log_v3 export notes when memory handoff applies.</summary>
        public const string CoverageVsSidecarGuidance =
            "Memory handoff: Coverage (per collection_coverage.json) reconciles disk artifacts with the sidecar; Sidecar (memory_*.json) records the external tool run. If a coverage step Detail includes [Coverage], disk checks adjusted that step for auditability. If a sidecar Detail includes [Reconciled], the collector re-checked disk immediately before writing memory_*.json and adjusted Status/Detail when expected dump or listed analysis outputs were absent.";

        /// <summary>
        /// Audit note recorded in memory_*.json: the external tool's command-line arguments are
        /// operator-supplied and NOT validated by IR_Collect. Only the {OutputPath}/{OutputDir}
        /// placeholder is constrained to the case Memory directory; any other flags the operator
        /// adds (or a fully custom template) can direct the tool to write/read elsewhere.
        /// </summary>
        public const string ArgsGovernanceNote =
            "Tool arguments are operator-supplied and not validated by IR_Collect; only the {OutputPath}/{OutputDir} placeholder is constrained to the case Memory directory. Other operator-supplied flags are not path-governed.";

        private static readonly Regex RxWhitespace = new Regex(@"\s+", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex RxAccessDenied = new Regex(@"access\s+is\s+denied|permission\s+denied|administrator|elevat", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxToolMissing = new Regex(@"cannot\s+find|not\s+recognized|no\s+such\s+file|file\s+not\s+found|could\s+not\s+find", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxInvalidArgs = new Regex(@"invalid\s+argument|unknown\s+option|unrecognized\s+option|usage:|syntax\s+error|parameter\s+is\s+incorrect", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxDiskFull = new Regex(@"disk\s+full|not\s+enough\s+space|no\s+space\s+left|there is not enough space", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxRuntimeMissing = new Regex(@"python(\.exe)?\s+is\s+not\s+recognized|module\s+not\s+found|dotnet", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxProfileMissing = new Regex(@"profile|symbol|layer|kernel|dtb", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxPathMissing = new Regex(@"path\s+not\s+found|directory\s+name\s+is\s+invalid|cannot\s+find\s+the\s+path", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RxOutputLocked = new Regex(@"being\s+used\s+by\s+another\s+process|cannot\s+access\s+the\s+file", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public sealed class ValidationOutcome
        {
            public string Status { get; set; }
            public string Detail { get; set; }
            public List<string> RequiredPatterns { get; set; }
            public List<string> MatchedPatterns { get; set; }
            public List<string> MissingPatterns { get; set; }

            public ValidationOutcome()
            {
                Status = "not_evaluated";
                Detail = "";
                RequiredPatterns = new List<string>();
                MatchedPatterns = new List<string>();
                MissingPatterns = new List<string>();
            }
        }

        public sealed class DiagnosticOutcome
        {
            public string Category { get; set; }
            public string Detail { get; set; }

            public DiagnosticOutcome()
            {
                Category = "unknown";
                Detail = "";
            }
        }

        public static string NormalizeAcquirePreset(string raw)
        {
            string t = (raw ?? "").Trim();
            if (string.IsNullOrEmpty(t)) return AcquirePresetCustom;
            if (string.Equals(t, AcquirePresetQuotedOutput, StringComparison.OrdinalIgnoreCase)) return AcquirePresetQuotedOutput;
            if (string.Equals(t, AcquirePresetWinPmemO, StringComparison.OrdinalIgnoreCase)) return AcquirePresetWinPmemO;
            if (string.Equals(t, AcquirePresetWinPmemRaw, StringComparison.OrdinalIgnoreCase)) return AcquirePresetWinPmemRaw;
            return AcquirePresetCustom;
        }

        public static string NormalizeAnalyzePreset(string raw)
        {
            string t = (raw ?? "").Trim();
            if (string.IsNullOrEmpty(t)) return AnalyzePresetDualQuoted;
            if (string.Equals(t, AnalyzePresetCustom, StringComparison.OrdinalIgnoreCase)) return AnalyzePresetCustom;
            if (string.Equals(t, AnalyzePresetInputOutputFlags, StringComparison.OrdinalIgnoreCase)) return AnalyzePresetInputOutputFlags;
            if (string.Equals(t, AnalyzePresetVolatility3OutputDir, StringComparison.OrdinalIgnoreCase)) return AnalyzePresetVolatility3OutputDir;
            return AnalyzePresetDualQuoted;
        }

        public static string NormalizeAcquireValidationMode(string raw)
        {
            string t = (raw ?? "").Trim();
            if (string.Equals(t, AcquireValidationMinSize, StringComparison.OrdinalIgnoreCase))
                return AcquireValidationMinSize;
            return AcquireValidationExistsOnly;
        }

        public static string NormalizeAnalyzeValidationMode(string raw)
        {
            string t = (raw ?? "").Trim();
            if (string.Equals(t, AnalyzeValidationRequiredPatterns, StringComparison.OrdinalIgnoreCase))
                return AnalyzeValidationRequiredPatterns;
            return AnalyzeValidationDirectoryHasFiles;
        }

        /// <summary>Effective args template for acquisition (placeholders {OutputPath}, {OutputDir}). Non-Custom presets use MemoryAcquireToolArgs as extra CLI tokens appended after the preset core (still placeholder-expanded).</summary>
        public static string ResolveAcquireArgsTemplate(string userTemplate, string presetRaw)
        {
            string preset = NormalizeAcquirePreset(presetRaw);
            string extra = (userTemplate ?? "").Trim();
            if (string.Equals(preset, AcquirePresetCustom, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrEmpty(extra))
                    return extra;
                return "\"{OutputPath}\"";
            }

            string core;
            if (string.Equals(preset, AcquirePresetQuotedOutput, StringComparison.OrdinalIgnoreCase))
                core = "\"{OutputPath}\"";
            else if (string.Equals(preset, AcquirePresetWinPmemO, StringComparison.OrdinalIgnoreCase))
                core = "-o \"{OutputPath}\"";
            else if (string.Equals(preset, AcquirePresetWinPmemRaw, StringComparison.OrdinalIgnoreCase))
                core = "--format raw -o \"{OutputPath}\"";
            else
                core = "\"{OutputPath}\"";

            if (string.IsNullOrEmpty(extra))
                return core;
            return core + " " + extra;
        }

        /// <summary>Effective args template for analysis ({InputPath}, {InputDir}, {OutputDir}, {CaseDir}).</summary>
        public static string ResolveAnalyzeArgsTemplate(string userTemplate, string presetRaw)
        {
            string preset = NormalizeAnalyzePreset(presetRaw);
            if (string.Equals(preset, AnalyzePresetCustom, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(userTemplate))
                    return userTemplate.Trim();
                return "\"{InputPath}\" \"{OutputDir}\"";
            }

            if (string.Equals(preset, AnalyzePresetInputOutputFlags, StringComparison.OrdinalIgnoreCase))
                return "-i \"{InputPath}\" -o \"{OutputDir}\"";
            if (string.Equals(preset, AnalyzePresetVolatility3OutputDir, StringComparison.OrdinalIgnoreCase))
                return "-f \"{InputPath}\" --output-dir \"{OutputDir}\"";
            return "\"{InputPath}\" \"{OutputDir}\"";
        }

        public static string AcquisitionDisabledDetail()
        {
            return "Skipped: memory acquisition is disabled in Settings (MemoryAcquireEnabled=0).";
        }

        public static string AcquisitionElevationPolicySkippedDetail()
        {
            return "Skipped: not elevated â€” MemoryAcquireSkipIfNotElevated is enabled and the collector is not running as Administrator.";
        }

        public static string AcquisitionToolPathNotConfiguredDetail()
        {
            return "Skipped: tool path missing â€” MemoryAcquireToolPath is empty; configure an external capture tool or disable acquisition.";
        }

        public static string AcquisitionToolPathFileMissingDetail()
        {
            return "Failed: tool path missing â€” configured MemoryAcquireToolPath does not exist on disk.";
        }

        public static string AcquisitionOutputEscapesMemoryDirDetail()
        {
            return "Failed: output path invalid â€” resolved output would escape the Memory folder.";
        }

        public static string AcquisitionTimeoutDetail(int timeoutSec, string iniKey)
        {
            return "Failed: timeout â€” external tool exceeded " + timeoutSec.ToString() + " s (" + iniKey + "); process was terminated.";
        }

        public static string AcquisitionToolExitNonZeroDetail(int exitCode)
        {
            return "Failed: external tool exited with code " + exitCode.ToString() + ".";
        }

        public static string AcquisitionExitZeroDumpMissingDetail()
        {
            return "Partial: tool exited successfully (0) but expected dump file was not found on disk (dump missing).";
        }

        public static string AcquisitionCompleteDetail()
        {
            return "Complete: external tool exited successfully (0) and expected dump file is present.";
        }

        public static string AcquisitionExecutionErrorDetail(string message)
        {
            return "Failed: execution error â€” " + (message ?? "");
        }

        public static string AcquisitionExistingOutputDeleteFailedDetail(string message)
        {
            return "Failed: could not delete existing output file â€” " + (message ?? "");
        }

        public static string AnalysisDisabledDetail()
        {
            return "Skipped: memory analysis handoff is disabled in Settings (MemoryAnalyzeEnabled=0).";
        }

        public static string AnalysisToolPathNotConfiguredDetail()
        {
            return "Skipped: tool path missing â€” MemoryAnalyzeToolPath is empty; configure an external analyzer or disable handoff.";
        }

        public static string AnalysisToolPathFileMissingDetail()
        {
            return "Failed: tool path missing â€” configured MemoryAnalyzeToolPath does not exist on disk.";
        }

        public static string AnalysisDumpMissingDetail()
        {
            return "Missing: no memory dump available for handoff â€” collect a dump first or verify Memory\\ output and memory_acquisition.json.";
        }

        public static string AnalysisOutputDirClearFailedDetail(string message)
        {
            return "Failed: output directory invalid â€” could not clear existing MemoryAnalysis directory: " + (message ?? "");
        }

        public static string AnalysisTimeoutDetail(int timeoutSec, string iniKey)
        {
            return "Failed: timeout â€” analyzer exceeded " + timeoutSec.ToString() + " s (" + iniKey + "); process was terminated.";
        }

        public static string AnalysisExecutionErrorDetail(string message)
        {
            return "Failed: execution error â€” " + (message ?? "");
        }

        public static string AnalysisExitZeroNoOutputFilesDetail()
        {
            return "Partial: analyzer exited successfully (0) but no output files were found under the analysis directory (output missing).";
        }

        public static string AnalysisExitNonZeroWithOutputsDetail(int exitCode)
        {
            return "Partial: analyzer exited with code " + exitCode.ToString() + " but produced output files.";
        }

        public static string AnalysisExitNonZeroNoOutputsDetail(int exitCode)
        {
            return "Failed: analyzer exited with code " + exitCode.ToString() + " and no output files were found.";
        }

        public static string AnalysisCompleteDetail()
        {
            return "Complete: analyzer exited successfully (0) and output files are present under the analysis directory.";
        }

        public static ValidationOutcome EvaluateAcquisitionOutput(string outputFullPath, string validationModeRaw, string minBytesRaw)
        {
            string mode = NormalizeAcquireValidationMode(validationModeRaw);
            var outcome = new ValidationOutcome();
            outcome.Status = "failed";

            bool exists = FileExistsSafe(outputFullPath);
            if (!exists)
            {
                outcome.Detail = "Validation failed: expected dump file is absent.";
                return outcome;
            }

            if (string.Equals(mode, AcquireValidationMinSize, StringComparison.OrdinalIgnoreCase))
            {
                long minBytes = ParseByteThreshold(minBytesRaw, 1048576L);
                long actualBytes = 0;
                try { actualBytes = new FileInfo(outputFullPath).Length; }
                catch { }

                if (actualBytes >= minBytes)
                {
                    outcome.Status = "passed";
                    outcome.Detail = "Validation passed: dump file exists and size is at least " + minBytes.ToString() + " bytes.";
                }
                else
                {
                    outcome.Detail = "Validation failed: dump file exists but size (" + actualBytes.ToString() + " bytes) is below " + minBytes.ToString() + " bytes.";
                }
                return outcome;
            }

            outcome.Status = "passed";
            outcome.Detail = "Validation passed: expected dump file exists.";
            return outcome;
        }

        public static ValidationOutcome EvaluateAnalysisOutputs(string analysisDir, string validationModeRaw, string requiredPatternsRaw)
        {
            string mode = NormalizeAnalyzeValidationMode(validationModeRaw);
            var outcome = new ValidationOutcome();
            outcome.RequiredPatterns = ParsePatternList(requiredPatternsRaw);

            List<string> files = GetAllFilesSafe(analysisDir);
            if (files.Count == 0)
            {
                outcome.Status = "failed";
                outcome.Detail = "Validation failed: analysis output directory has no files.";
                if (outcome.RequiredPatterns.Count > 0)
                    outcome.MissingPatterns.AddRange(outcome.RequiredPatterns);
                return outcome;
            }

            if (string.Equals(mode, AnalyzeValidationRequiredPatterns, StringComparison.OrdinalIgnoreCase) && outcome.RequiredPatterns.Count > 0)
            {
                for (int i = 0; i < outcome.RequiredPatterns.Count; i++)
                {
                    string pattern = outcome.RequiredPatterns[i];
                    bool matched = false;
                    for (int j = 0; j < files.Count; j++)
                    {
                        string rel = files[j];
                        string name = Path.GetFileName(rel);
                        if (WildcardMatches(rel, pattern) || WildcardMatches(name, pattern))
                        {
                            matched = true;
                            break;
                        }
                    }

                    if (matched)
                        outcome.MatchedPatterns.Add(pattern);
                    else
                        outcome.MissingPatterns.Add(pattern);
                }

                if (outcome.MissingPatterns.Count > 0)
                {
                    outcome.Status = "failed";
                    outcome.Detail = "Validation failed: required output patterns missing: " + string.Join(", ", outcome.MissingPatterns.ToArray()) + ".";
                    return outcome;
                }

                outcome.Status = "passed";
                outcome.Detail = "Validation passed: required output patterns matched.";
                return outcome;
            }

            outcome.Status = "passed";
            outcome.Detail = "Validation passed: analysis output directory contains files.";
            return outcome;
        }

        public static void ApplyAcquisitionValidation(MemoryAcquisitionRecord rec, string outputFullPath, string validationModeRaw, string minBytesRaw)
        {
            if (rec == null)
                return;

            rec.ValidationMode = NormalizeAcquireValidationMode(validationModeRaw);

            if (string.Equals(rec.Status, "skipped", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(rec.Status, "missing", StringComparison.OrdinalIgnoreCase))
            {
                rec.ValidationStatus = "not_evaluated";
                rec.ValidationDetail = "Validation not evaluated for status=" + (rec.Status ?? "") + ".";
                return;
            }

            ValidationOutcome outcome = EvaluateAcquisitionOutput(outputFullPath, rec.ValidationMode, minBytesRaw);
            rec.ValidationStatus = outcome.Status;
            rec.ValidationDetail = outcome.Detail;

            if (string.Equals(outcome.Status, "failed", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(rec.Status, "complete", StringComparison.OrdinalIgnoreCase))
                    rec.Status = "partial";
                string detail = rec.Detail;
                AppendDetail(ref detail, "[Validation] " + outcome.Detail);
                rec.Detail = detail;
            }
        }

        public static void ApplyAnalysisValidation(MemoryAnalysisRecord rec, string analysisDir, string validationModeRaw, string requiredPatternsRaw)
        {
            if (rec == null)
                return;

            rec.ValidationMode = NormalizeAnalyzeValidationMode(validationModeRaw);
            rec.RequiredOutputPatterns = ParsePatternList(requiredPatternsRaw);

            if (string.Equals(rec.Status, "skipped", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(rec.Status, "missing", StringComparison.OrdinalIgnoreCase))
            {
                rec.ValidationStatus = "not_evaluated";
                rec.ValidationDetail = "Validation not evaluated for status=" + (rec.Status ?? "") + ".";
                return;
            }

            ValidationOutcome outcome = EvaluateAnalysisOutputs(analysisDir, rec.ValidationMode, requiredPatternsRaw);
            rec.ValidationStatus = outcome.Status;
            rec.ValidationDetail = outcome.Detail;
            rec.MatchedOutputPatterns = outcome.MatchedPatterns;
            rec.MissingOutputPatterns = outcome.MissingPatterns;

            if (string.Equals(outcome.Status, "failed", StringComparison.OrdinalIgnoreCase))
            {
                bool hasOutputs = rec.OutputFileCount > 0;
                if (string.Equals(rec.Status, "complete", StringComparison.OrdinalIgnoreCase))
                    rec.Status = hasOutputs ? "partial" : "failed";
                else if (string.Equals(rec.Status, "partial", StringComparison.OrdinalIgnoreCase) && !hasOutputs)
                    rec.Status = "failed";
                string detail = rec.Detail;
                AppendDetail(ref detail, "[Validation] " + outcome.Detail);
                rec.Detail = detail;
            }
        }

        public static void ApplyAcquisitionDiagnostics(MemoryAcquisitionRecord rec)
        {
            if (rec == null)
                return;

            DiagnosticOutcome outcome = Diagnose(
                rec.Status,
                rec.ExitCode,
                rec.Detail,
                rec.StdoutTail,
                rec.StderrTail,
                rec.ValidationStatus,
                false);
            rec.DiagnosticCategory = outcome.Category;
            rec.DiagnosticDetail = outcome.Detail;
        }

        public static void ApplyAnalysisDiagnostics(MemoryAnalysisRecord rec)
        {
            if (rec == null)
                return;

            DiagnosticOutcome outcome = Diagnose(
                rec.Status,
                rec.ExitCode,
                rec.Detail,
                rec.StdoutTail,
                rec.StderrTail,
                rec.ValidationStatus,
                true);
            rec.DiagnosticCategory = outcome.Category;
            rec.DiagnosticDetail = outcome.Detail;
        }

        /// <summary>Before persisting memory_acquisition.json: if status claims output but file is gone, downgrade for auditability.</summary>
        public static void FinalizeAcquisitionRecordAgainstDisk(string caseRoot, MemoryAcquisitionRecord rec)
        {
            if (rec == null || string.IsNullOrEmpty(caseRoot)) return;

            string rel = rec.OutputRelativePath ?? "";
            if (string.IsNullOrEmpty(rel)) return;

            string full = null;
            try
            {
                full = Path.GetFullPath(Path.Combine(caseRoot, rel));
            }
            catch
            {
                return;
            }

            string st = (rec.Status ?? "").Trim();
            if (string.Equals(st, "failed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(st, "skipped", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(st, "missing", StringComparison.OrdinalIgnoreCase))
                return;

            bool diskOk = FileExistsSafe(full);
            if ((string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(st, "partial", StringComparison.OrdinalIgnoreCase)) && !diskOk)
            {
                rec.Status = "failed";
                string detail = rec.Detail;
                AppendDetail(ref detail, "[Reconciled] Sidecar indicated a dump path but the file was absent at finalize (dump missing).");
                rec.Detail = detail;
            }
        }

        /// <summary>Before persisting memory_analysis.json: if sidecar lists outputs but disk is empty, downgrade.</summary>
        public static void FinalizeAnalysisRecordAgainstDisk(string caseRoot, MemoryAnalysisRecord rec)
        {
            if (rec == null || string.IsNullOrEmpty(caseRoot)) return;

            string st = (rec.Status ?? "").Trim();
            if (string.Equals(st, "failed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(st, "skipped", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(st, "missing", StringComparison.OrdinalIgnoreCase))
                return;

            int existingListed = 0;
            if (rec.OutputFiles != null)
            {
                for (int i = 0; i < rec.OutputFiles.Count; i++)
                {
                    string rel = rec.OutputFiles[i];
                    if (string.IsNullOrWhiteSpace(rel)) continue;
                    try
                    {
                        string full = Path.GetFullPath(Path.Combine(caseRoot, rel));
                        if (File.Exists(full)) existingListed++;
                    }
                    catch { }
                }
            }

            int filesOnDisk = 0;
            string relDir = rec.OutputDirectoryRelativePath ?? "";
            if (!string.IsNullOrEmpty(relDir))
            {
                try
                {
                    string dirFull = Path.GetFullPath(Path.Combine(caseRoot, relDir));
                    if (Directory.Exists(dirFull))
                        filesOnDisk = Directory.GetFiles(dirFull, "*", SearchOption.AllDirectories).Length;
                }
                catch { }
            }

            if ((string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(st, "partial", StringComparison.OrdinalIgnoreCase)) &&
                rec.OutputFileCount > 0 && existingListed == 0 && filesOnDisk == 0)
            {
                rec.Status = "failed";
                string detail = rec.Detail;
                AppendDetail(ref detail, "[Reconciled] Sidecar listed output files but none were found on disk at finalize (output missing).");
                rec.Detail = detail;
            }
        }

        public static List<string> ParsePatternList(string raw)
        {
            var patterns = new List<string>();
            if (string.IsNullOrWhiteSpace(raw))
                return patterns;

            string[] lines = raw.Replace("\r\n", "\n").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string line = (lines[i] ?? "").Trim();
                if (string.IsNullOrEmpty(line))
                    continue;

                string[] chunks = line.Split(new char[] { '|', ';' }, StringSplitOptions.RemoveEmptyEntries);
                for (int j = 0; j < chunks.Length; j++)
                {
                    string pattern = (chunks[j] ?? "").Trim();
                    if (!string.IsNullOrEmpty(pattern) && !ContainsIgnoreCase(patterns, pattern))
                        patterns.Add(pattern);
                }
            }
            return patterns;
        }

        private static DiagnosticOutcome Diagnose(string status, int exitCode, string detail, string stdoutTail, string stderrTail, string validationStatus, bool isAnalysis)
        {
            var outcome = new DiagnosticOutcome();
            string st = (status ?? "").Trim();
            string blob = NormalizeDiagnosticBlob(detail, stdoutTail, stderrTail);

            if (string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(validationStatus, "failed", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Category = "success";
                outcome.Detail = "No obvious error signature detected.";
                return outcome;
            }

            if (string.Equals(st, "skipped", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Category = "policy_skip";
                outcome.Detail = FirstNonEmpty(detail, "Run was skipped by configuration or privilege policy.");
                return outcome;
            }

            if (string.Equals(st, "missing", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Category = isAnalysis ? "input_missing" : "output_missing";
                outcome.Detail = FirstNonEmpty(detail, "Required input or output artifact is missing.");
                return outcome;
            }

            if (exitCode == -1 || blob.IndexOf("timeout", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                outcome.Category = "timeout";
                outcome.Detail = FirstNonEmpty(detail, "External tool exceeded configured timeout.");
                return outcome;
            }

            if (string.Equals(validationStatus, "failed", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Category = "output_validation_failed";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Output validation failed.");
                return outcome;
            }

            if (RxAccessDenied.IsMatch(blob))
            {
                outcome.Category = "permission_denied";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Access denied or elevation mismatch.");
                return outcome;
            }

            if (RxToolMissing.IsMatch(blob))
            {
                outcome.Category = "tool_or_path_missing";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Tool path or referenced path was not found.");
                return outcome;
            }

            if (RxInvalidArgs.IsMatch(blob))
            {
                outcome.Category = "invalid_arguments";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "External tool rejected the command line.");
                return outcome;
            }

            if (RxDiskFull.IsMatch(blob))
            {
                outcome.Category = "disk_full";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Destination volume appears full.");
                return outcome;
            }

            if (RxRuntimeMissing.IsMatch(blob))
            {
                outcome.Category = "runtime_missing";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Required runtime or dependency is missing.");
                return outcome;
            }

            if (isAnalysis && RxProfileMissing.IsMatch(blob))
            {
                outcome.Category = "profile_or_symbols_missing";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Analyzer likely needs additional symbols, profile, or layer metadata.");
                return outcome;
            }

            if (RxPathMissing.IsMatch(blob))
            {
                outcome.Category = "path_missing";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Referenced path or output directory was not found.");
                return outcome;
            }

            if (RxOutputLocked.IsMatch(blob))
            {
                outcome.Category = "output_locked";
                outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "Output path appears locked by another process.");
                return outcome;
            }

            if (string.Equals(st, "partial", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Category = "partial_output";
                outcome.Detail = FirstNonEmpty(detail, "External tool only produced a partial result.");
                return outcome;
            }

            outcome.Category = "unknown_error";
            outcome.Detail = ExtractDiagnosticExcerpt(blob, detail, "No specific error signature detected.");
            return outcome;
        }

        private static string NormalizeDiagnosticBlob(string detail, string stdoutTail, string stderrTail)
        {
            string blob = (detail ?? "") + "\n" + (stdoutTail ?? "") + "\n" + (stderrTail ?? "");
            blob = blob.Replace('\r', ' ').Replace('\n', ' ');
            return RxWhitespace.Replace(blob, " ").Trim();
        }

        private static string ExtractDiagnosticExcerpt(string blob, string detail, string fallback)
        {
            string candidate = FirstNonEmpty(detail, blob, fallback);
            candidate = RxWhitespace.Replace((candidate ?? "").Replace('\r', ' ').Replace('\n', ' '), " ").Trim();
            if (candidate.Length > 220)
                candidate = candidate.Substring(0, 217) + "...";
            return candidate;
        }

        private static string FirstNonEmpty(params string[] values)
        {
            if (values == null) return "";
            for (int i = 0; i < values.Length; i++)
            {
                string value = values[i];
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }
            return "";
        }

        private static void AppendDetail(ref string detail, string suffix)
        {
            string prefix = (detail ?? "").Trim();
            string extra = (suffix ?? "").Trim();
            if (string.IsNullOrEmpty(extra))
                return;
            detail = string.IsNullOrEmpty(prefix) ? extra : (prefix + " " + extra);
        }

        private static long ParseByteThreshold(string raw, long fallback)
        {
            long value;
            if (long.TryParse((raw ?? "").Trim(), out value) && value > 0)
                return value;
            return fallback;
        }

        private static List<string> GetAllFilesSafe(string analysisDir)
        {
            var files = new List<string>();
            if (string.IsNullOrWhiteSpace(analysisDir) || !Directory.Exists(analysisDir))
                return files;

            string root = Path.GetFullPath(analysisDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string[] all = Directory.GetFiles(analysisDir, "*", SearchOption.AllDirectories);
            for (int i = 0; i < all.Length; i++)
            {
                try
                {
                    string full = Path.GetFullPath(all[i]);
                    string rel = full.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                        ? full.Substring(root.Length)
                        : Path.GetFileName(full);
                    files.Add(rel);
                }
                catch { }
            }
            return files;
        }

        private static bool WildcardMatches(string value, string pattern)
        {
            string candidate = value ?? "";
            string filter = pattern ?? "";
            if (string.IsNullOrEmpty(filter))
                return false;

            string regex = "^" + Regex.Escape(filter).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
            return Regex.IsMatch(candidate, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private static bool ContainsIgnoreCase(List<string> values, string candidate)
        {
            if (values == null) return false;
            for (int i = 0; i < values.Count; i++)
            {
                if (string.Equals(values[i], candidate, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static bool FileExistsSafe(string path)
        {
            try
            {
                return !string.IsNullOrEmpty(path) && File.Exists(path);
            }
            catch
            {
                return false;
            }
        }
    }
}
