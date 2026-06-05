using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    /// <summary>Orchestrates external memory analysis handoff only; does not parse dump contents in-app.</summary>
    public static class MemoryAnalysisCollector
    {
        public static void Collect(string outputDir)
        {
            if (string.IsNullOrEmpty(outputDir) || !Directory.Exists(outputDir))
                return;

            string jsonPath = Path.Combine(outputDir, ArtifactNames.MemoryAnalysisJson);
            var cfg = new ConfigManager();
            var rec = new MemoryAnalysisRecord();
            rec.StartedAtUtc = DateTime.UtcNow.ToString("o");
            rec.TimeoutSecConfigured = ParseTimeout(cfg.Get("MemoryAnalyzeTimeoutSec"));
            rec.ArgsPreset = MemoryHandoffHelper.NormalizeAnalyzePreset(cfg.Get("MemoryAnalyzeArgsPreset"));
            rec.ValidationMode = MemoryHandoffHelper.NormalizeAnalyzeValidationMode(cfg.Get("MemoryAnalyzeValidationMode"));

            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    rec.CollectorUser = id != null ? (id.Name ?? "") : "";
                    rec.CollectorWasAdmin = id != null && new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception ex)
            {
                rec.CollectorUser = "";
                rec.CollectorWasAdmin = false;
                Logger.Warning("MemoryAnalysis privilege probe: " + ex.Message);
            }

            if (cfg.Get("MemoryAnalyzeEnabled") != "1")
            {
                rec.Status = "skipped";
                rec.Detail = MemoryHandoffHelper.AnalysisDisabledDetail();
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string toolPath = (cfg.Get("MemoryAnalyzeToolPath") ?? "").Trim();
            if (string.IsNullOrEmpty(toolPath))
            {
                rec.Status = "skipped";
                rec.Detail = MemoryHandoffHelper.AnalysisToolPathNotConfiguredDetail();
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            if (!File.Exists(toolPath))
            {
                rec.Status = "failed";
                rec.ToolPath = toolPath;
                rec.Detail = MemoryHandoffHelper.AnalysisToolPathFileMissingDetail();
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string inputDump = ResolveInputDumpPath(outputDir);
            if (string.IsNullOrEmpty(inputDump) || !File.Exists(inputDump))
            {
                rec.Status = "missing";
                rec.ToolPath = toolPath;
                rec.Detail = MemoryHandoffHelper.AnalysisDumpMissingDetail();
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string outputDirName = (cfg.Get("MemoryAnalyzeOutputDirName") ?? "").Trim();
            if (string.IsNullOrEmpty(outputDirName)) outputDirName = ArtifactNames.MemoryAnalysisFolder;
            outputDirName = SanitizePathSegment(outputDirName);
            if (string.IsNullOrEmpty(outputDirName)) outputDirName = ArtifactNames.MemoryAnalysisFolder;

            string analysisDir = Path.GetFullPath(Path.Combine(outputDir, outputDirName));
            if (!IsPathUnderRoot(analysisDir, Path.GetFullPath(outputDir)))
            {
                rec.Status = "failed";
                rec.ToolPath = toolPath;
                rec.Detail = "Refused: analysis output directory escapes case root.";
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string analysisDirValidationError = ValidateAnalysisOutputDirectory(Path.GetFullPath(outputDir), analysisDir, inputDump);
            if (!string.IsNullOrEmpty(analysisDirValidationError))
            {
                rec.Status = "failed";
                rec.ToolPath = toolPath;
                rec.Detail = analysisDirValidationError;
                MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            rec.ToolPath = toolPath;
            rec.InputRelativePath = GetRelativePath(outputDir, inputDump);
            rec.OutputDirectoryRelativePath = GetRelativePath(outputDir, analysisDir);

            string argsTemplate = MemoryHandoffHelper.ResolveAnalyzeArgsTemplate(cfg.Get("MemoryAnalyzeToolArgs"), cfg.Get("MemoryAnalyzeArgsPreset"));
            rec.ToolArgs = ExpandArgs(argsTemplate, inputDump, analysisDir, outputDir);
            rec.ArgsGovernanceNote = MemoryHandoffHelper.ArgsGovernanceNote;

            try
            {
                if (Directory.Exists(analysisDir))
                {
                    try { Directory.Delete(analysisDir, true); }
                    catch (Exception ex)
                    {
                        rec.Status = "failed";
                        rec.Detail = MemoryHandoffHelper.AnalysisOutputDirClearFailedDetail(ex.Message);
                        MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
                        FinishRecord(rec, jsonPath);
                        return;
                    }
                }
                Directory.CreateDirectory(analysisDir);

                var psi = new ProcessStartInfo();
                psi.FileName = toolPath;
                psi.Arguments = rec.ToolArgs;
                psi.WorkingDirectory = outputDir;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                var sw = Stopwatch.StartNew();
                var outp = new StringBuilder();
                var errp = new StringBuilder();
                using (var proc = new Process())
                {
                    proc.StartInfo = psi;
                    proc.Start();

                    var tOut = new Thread(delegate()
                    {
                        try { outp.Append(proc.StandardOutput.ReadToEnd()); }
                        catch (Exception ex)
                        {
                            try { Logger.Warning("MemoryAnalysis stdout read: " + ex.Message); } catch { }
                        }
                    });
                    var tErr = new Thread(delegate()
                    {
                        try { errp.Append(proc.StandardError.ReadToEnd()); }
                        catch (Exception ex)
                        {
                            try { Logger.Warning("MemoryAnalysis stderr read: " + ex.Message); } catch { }
                        }
                    });
                    tOut.IsBackground = true;
                    tErr.IsBackground = true;
                    tOut.Start();
                    tErr.Start();

                    int timeoutMs = rec.TimeoutSecConfigured > 0 ? rec.TimeoutSecConfigured * 1000 : 3600000;
                    bool exited = proc.WaitForExit(timeoutMs);
                    if (!exited)
                    {
                        try { proc.Kill(); } catch { }
                        try { proc.WaitForExit(8000); } catch { }
                        rec.Status = "failed";
                        rec.Detail = MemoryHandoffHelper.AnalysisTimeoutDetail(rec.TimeoutSecConfigured, "MemoryAnalyzeTimeoutSec");
                        rec.ExitCode = -1;
                    }
                    else
                    {
                        rec.ExitCode = proc.ExitCode;
                    }

                    const int joinMs = 120000;
                    try
                    {
                        if (!tOut.Join(joinMs))
                            Logger.Warning("MemoryAnalysis: stdout drain thread did not finish within " + joinMs.ToString() + " ms.");
                        if (!tErr.Join(joinMs))
                            Logger.Warning("MemoryAnalysis: stderr drain thread did not finish within " + joinMs.ToString() + " ms.");
                    }
                    catch (Exception ex)
                    {
                        try { Logger.Warning("MemoryAnalysis drain join: " + ex.Message); } catch { }
                    }

                    rec.StdoutTail = TrimTail(outp.ToString(), 6000);
                    rec.StderrTail = TrimTail(errp.ToString(), 6000);

                    sw.Stop();
                    rec.DurationMs = sw.ElapsedMilliseconds;
                }

                CollectOutputMetadata(outputDir, analysisDir, rec);
                ApplyFinalStatus(rec);
            }
            catch (Exception ex)
            {
                rec.Status = "failed";
                rec.Detail = MemoryHandoffHelper.AnalysisExecutionErrorDetail(ex.Message);
                Logger.Error("MemoryAnalysisCollector", ex);
            }

            MemoryHandoffHelper.ApplyAnalysisValidation(rec, analysisDir, cfg.Get("MemoryAnalyzeValidationMode"), cfg.Get("MemoryAnalyzeRequiredPatterns"));
            MemoryHandoffHelper.FinalizeAnalysisRecordAgainstDisk(outputDir, rec);
            MemoryHandoffHelper.ApplyAnalysisDiagnostics(rec);
            rec.EndedAtUtc = DateTime.UtcNow.ToString("o");
            MemoryAnalysisRecord.SaveToFile(rec, jsonPath);
        }

        private static void ApplyFinalStatus(MemoryAnalysisRecord rec)
        {
            if (rec == null) return;
            if (string.Equals(rec.Status, "failed", StringComparison.OrdinalIgnoreCase) && rec.ExitCode == -1)
                return;

            if (rec.ExitCode == 0)
            {
                if (rec.OutputFileCount > 0)
                {
                    rec.Status = "complete";
                    rec.Detail = MemoryHandoffHelper.AnalysisCompleteDetail();
                }
                else
                {
                    rec.Status = "partial";
                    rec.Detail = MemoryHandoffHelper.AnalysisExitZeroNoOutputFilesDetail();
                }
                return;
            }

            if (rec.OutputFileCount > 0)
            {
                rec.Status = "partial";
                rec.Detail = MemoryHandoffHelper.AnalysisExitNonZeroWithOutputsDetail(rec.ExitCode);
            }
            else
            {
                rec.Status = "failed";
                rec.Detail = MemoryHandoffHelper.AnalysisExitNonZeroNoOutputsDetail(rec.ExitCode);
            }
        }

        private static void CollectOutputMetadata(string outputDir, string analysisDir, MemoryAnalysisRecord rec)
        {
            if (rec == null)
                return;

            rec.OutputFiles = new List<string>();
            rec.OutputFileCount = 0;
            rec.OutputTotalBytes = 0;

            if (string.IsNullOrEmpty(analysisDir) || !Directory.Exists(analysisDir))
                return;

            foreach (string file in Directory.GetFiles(analysisDir, "*", SearchOption.AllDirectories))
            {
                try
                {
                    string rel = GetRelativePath(outputDir, file);
                    rec.OutputFiles.Add(rel);
                    rec.OutputFileCount++;
                    rec.OutputTotalBytes += new FileInfo(file).Length;
                }
                catch (Exception ex)
                {
                    Logger.Warning("MemoryAnalysis output metadata: " + ex.Message);
                }
            }
        }

        private static void FinishRecord(MemoryAnalysisRecord rec, string jsonPath)
        {
            rec.EndedAtUtc = DateTime.UtcNow.ToString("o");
            if (rec.StartedAtUtc != null && rec.EndedAtUtc != null)
            {
                DateTime a, b;
                if (DateTime.TryParse(rec.StartedAtUtc, out a) && DateTime.TryParse(rec.EndedAtUtc, out b))
                    rec.DurationMs = (long)Math.Max(0, (b - a).TotalMilliseconds);
            }
            MemoryAnalysisRecord.SaveToFile(rec, jsonPath);
        }

        private static int ParseTimeout(string v)
        {
            int n;
            if (int.TryParse((v ?? "").Trim(), out n) && n > 0) return Math.Min(n, 86400);
            return 3600;
        }

        private static string ExpandArgs(string template, string inputPath, string outputDir, string caseDir)
        {
            string t = template ?? "";
            t = t.Replace("{InputPath}", inputPath);
            t = t.Replace("{inputPath}", inputPath);
            t = t.Replace("{InputDir}", Path.GetDirectoryName(inputPath) ?? "");
            t = t.Replace("{inputDir}", Path.GetDirectoryName(inputPath) ?? "");
            t = t.Replace("{OutputDir}", outputDir);
            t = t.Replace("{outputDir}", outputDir);
            t = t.Replace("{CaseDir}", caseDir);
            t = t.Replace("{caseDir}", caseDir);
            return t;
        }

        internal static string ValidateAnalysisOutputDirectory(string caseRootFull, string analysisDirFull, string inputDumpFull)
        {
            string caseRoot = SafeGetFullPath(caseRootFull);
            string analysisDir = SafeGetFullPath(analysisDirFull);
            string inputDump = SafeGetFullPath(inputDumpFull);

            if (string.IsNullOrEmpty(caseRoot) || string.IsNullOrEmpty(analysisDir))
                return "Refused: analysis output directory could not be resolved.";
            if (!IsPathUnderRoot(analysisDir, caseRoot))
                return "Refused: analysis output directory escapes case root.";
            if (string.Equals(analysisDir, caseRoot, StringComparison.OrdinalIgnoreCase))
                return "Refused: analysis output directory cannot be the case root.";

            string leafName = Path.GetFileName(analysisDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (IsReservedEvidenceDirectoryName(leafName))
                return "Refused: analysis output directory cannot reuse reserved evidence directory '" + leafName + "'.";

            if (!string.IsNullOrEmpty(inputDump))
            {
                string inputDumpDir = SafeGetFullPath(Path.GetDirectoryName(inputDump));
                if (!string.IsNullOrEmpty(inputDumpDir) && string.Equals(analysisDir, inputDumpDir, StringComparison.OrdinalIgnoreCase))
                    return "Refused: analysis output directory cannot reuse the input dump directory.";
                if (!string.IsNullOrEmpty(inputDump) && IsPathUnderRoot(inputDump, analysisDir))
                    return "Refused: analysis output directory would contain the input dump and could delete evidence before handoff.";
            }

            return null;
        }

        private static string ResolveInputDumpPath(string outputDir)
        {
            string jsonPath = Path.Combine(outputDir, ArtifactNames.MemoryAcquisitionJson);
            MemoryAcquisitionRecord acq = MemoryAcquisitionRecord.TryLoad(jsonPath);
            if (acq != null && !string.IsNullOrWhiteSpace(acq.OutputRelativePath))
            {
                try
                {
                    string candidate = Path.GetFullPath(Path.Combine(outputDir, acq.OutputRelativePath));
                    if (File.Exists(candidate) && IsPathUnderRoot(candidate, Path.GetFullPath(outputDir)))
                        return candidate;
                }
                catch { }
            }

            string memoryDir = Path.Combine(outputDir, ArtifactNames.MemoryFolder);
            if (!Directory.Exists(memoryDir))
                return null;

            string[] patterns = new string[] { "*.raw", "*.dmp" };
            foreach (string pattern in patterns)
            {
                string candidate = Directory.GetFiles(memoryDir, pattern, SearchOption.TopDirectoryOnly)
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                    .FirstOrDefault();
                if (!string.IsNullOrEmpty(candidate))
                    return candidate;
            }
            return null;
        }

        private static string TrimTail(string s, int maxChars)
        {
            if (string.IsNullOrEmpty(s) || maxChars <= 0) return "";
            if (s.Length <= maxChars) return s;
            return s.Substring(s.Length - maxChars);
        }

        private static string SanitizePathSegment(string name)
        {
            string v = name ?? "";
            foreach (char c in Path.GetInvalidFileNameChars())
            {
                v = v.Replace(c.ToString(), "_");
            }
            v = v.Replace("/", "_").Replace("\\", "_").Trim();
            return v;
        }

        private static bool IsReservedEvidenceDirectoryName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return true;

            switch (name.Trim())
            {
                case ArtifactNames.MemoryFolder:
                case ArtifactNames.ExecutionArtifactsFolder:
                case "EventLogs":
                case "Registry":
                case "Browsers":
                case "JumpLists":
                case "Prefetch":
                    return true;
                default:
                    return false;
            }
        }

        private static string SafeGetFullPath(string path)
        {
            try
            {
                return string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path);
            }
            catch
            {
                return null;
            }
        }

        private static bool IsPathUnderRoot(string candidateFull, string rootFull)
        {
            try
            {
                string a = Path.GetFullPath(candidateFull).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string b = Path.GetFullPath(rootFull).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return a.StartsWith(b + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string GetRelativePath(string root, string path)
        {
            if (string.IsNullOrEmpty(path))
                return path;

            string pathNorm = Path.GetFullPath(path);
            if (string.IsNullOrEmpty(root))
                return Path.GetFileName(pathNorm);

            string rootNorm = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
            if (pathNorm.StartsWith(rootNorm, StringComparison.OrdinalIgnoreCase))
                return pathNorm.Substring(rootNorm.Length).TrimStart(Path.DirectorySeparatorChar, '/', '\\');
            return Path.GetFileName(pathNorm);
        }
    }
}
