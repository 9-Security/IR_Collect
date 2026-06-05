using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    /// <summary>Orchestrates external memory acquisition only; does not parse dump contents.</summary>
    public static class MemoryAcquisitionCollector
    {
        public static void Collect(string outputDir)
        {
            if (string.IsNullOrEmpty(outputDir) || !Directory.Exists(outputDir))
                return;

            string jsonPath = Path.Combine(outputDir, ArtifactNames.MemoryAcquisitionJson);
            var cfg = new ConfigManager();
            var rec = new MemoryAcquisitionRecord();
            rec.StartedAtUtc = DateTime.UtcNow.ToString("o");
            rec.TimeoutSecConfigured = ParseTimeout(cfg.Get("MemoryAcquireTimeoutSec"));
            rec.ConfigRequiresAdmin = cfg.Get("MemoryAcquireRequiresAdmin") == "1";
            rec.ConfigSkipIfNotElevated = cfg.Get("MemoryAcquireSkipIfNotElevated") != "0";
            rec.ArgsPreset = MemoryHandoffHelper.NormalizeAcquirePreset(cfg.Get("MemoryAcquireArgsPreset"));
            rec.ValidationMode = MemoryHandoffHelper.NormalizeAcquireValidationMode(cfg.Get("MemoryAcquireValidationMode"));

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
                Logger.Warning("MemoryAcquisition privilege probe: " + ex.Message);
            }

            if (cfg.Get("MemoryAcquireEnabled") != "1")
            {
                rec.Status = "skipped";
                rec.Detail = MemoryHandoffHelper.AcquisitionDisabledDetail();
                MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            if (rec.ConfigSkipIfNotElevated && !rec.CollectorWasAdmin)
            {
                rec.Status = "skipped";
                rec.Detail = MemoryHandoffHelper.AcquisitionElevationPolicySkippedDetail();
                MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string toolPath = (cfg.Get("MemoryAcquireToolPath") ?? "").Trim();
            if (string.IsNullOrEmpty(toolPath))
            {
                rec.Status = "skipped";
                rec.Detail = MemoryHandoffHelper.AcquisitionToolPathNotConfiguredDetail();
                MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            if (!File.Exists(toolPath))
            {
                rec.Status = "failed";
                rec.ToolPath = toolPath;
                rec.Detail = MemoryHandoffHelper.AcquisitionToolPathFileMissingDetail();
                MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string outputName = (cfg.Get("MemoryAcquireOutputName") ?? "").Trim();
            if (string.IsNullOrEmpty(outputName)) outputName = "memory.raw";
            outputName = SanitizeFileName(outputName);
            string memoryDir = Path.Combine(outputDir, ArtifactNames.MemoryFolder);
            if (!Directory.Exists(memoryDir)) Directory.CreateDirectory(memoryDir);

            string outputFull = Path.GetFullPath(Path.Combine(memoryDir, outputName));
            if (!IsPathUnderRoot(outputFull, Path.GetFullPath(memoryDir)))
            {
                rec.Status = "failed";
                rec.ToolPath = toolPath;
                rec.Detail = MemoryHandoffHelper.AcquisitionOutputEscapesMemoryDirDetail();
                MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                FinishRecord(rec, jsonPath);
                return;
            }

            string argsTemplate = MemoryHandoffHelper.ResolveAcquireArgsTemplate(cfg.Get("MemoryAcquireToolArgs"), cfg.Get("MemoryAcquireArgsPreset"));
            rec.ToolPath = toolPath;
            rec.ToolArgs = ExpandArgs(argsTemplate, outputFull, memoryDir);
            rec.ArgsGovernanceNote = MemoryHandoffHelper.ArgsGovernanceNote;
            rec.OutputRelativePath = ArtifactNames.MemoryFolder + "\\" + outputName;

            try
            {
                if (File.Exists(outputFull))
                {
                    try { File.Delete(outputFull); }
                    catch (Exception ex)
                    {
                        rec.Status = "failed";
                        rec.Detail = MemoryHandoffHelper.AcquisitionExistingOutputDeleteFailedDetail(ex.Message);
                        MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
                        FinishRecord(rec, jsonPath);
                        return;
                    }
                }

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
                        try
                        {
                            outp.Append(proc.StandardOutput.ReadToEnd());
                        }
                        catch (Exception ex)
                        {
                            try { Logger.Warning("MemoryAcquisition stdout read: " + ex.Message); } catch { }
                        }
                    });
                    var tErr = new Thread(delegate()
                    {
                        try
                        {
                            errp.Append(proc.StandardError.ReadToEnd());
                        }
                        catch (Exception ex)
                        {
                            try { Logger.Warning("MemoryAcquisition stderr read: " + ex.Message); } catch { }
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
                        try { proc.Kill(); }
                        catch { }
                        proc.WaitForExit(8000);
                        rec.Status = "failed";
                        rec.Detail = MemoryHandoffHelper.AcquisitionTimeoutDetail(rec.TimeoutSecConfigured, "MemoryAcquireTimeoutSec");
                        rec.ExitCode = -1;
                    }
                    else
                    {
                        rec.ExitCode = proc.ExitCode;
                        if (proc.ExitCode != 0)
                        {
                            rec.Status = "failed";
                            rec.Detail = MemoryHandoffHelper.AcquisitionToolExitNonZeroDetail(proc.ExitCode);
                        }
                        else if (File.Exists(outputFull))
                        {
                            rec.Status = "complete";
                            rec.Detail = MemoryHandoffHelper.AcquisitionCompleteDetail();
                        }
                        else
                        {
                            rec.Status = "partial";
                            rec.Detail = MemoryHandoffHelper.AcquisitionExitZeroDumpMissingDetail();
                        }
                    }

                    const int joinMs = 120000;
                    try
                    {
                        if (!tOut.Join(joinMs))
                            Logger.Warning("MemoryAcquisition: stdout drain thread did not finish within " + joinMs.ToString() + " ms.");
                        if (!tErr.Join(joinMs))
                            Logger.Warning("MemoryAcquisition: stderr drain thread did not finish within " + joinMs.ToString() + " ms.");
                    }
                    catch (Exception ex)
                    {
                        try { Logger.Warning("MemoryAcquisition drain join: " + ex.Message); } catch { }
                    }

                    rec.StdoutTail = TrimTail(outp.ToString(), 6000);
                    rec.StderrTail = TrimTail(errp.ToString(), 6000);

                    sw.Stop();
                    rec.DurationMs = sw.ElapsedMilliseconds;

                    if (File.Exists(outputFull))
                    {
                        try
                        {
                            FileInfo fi = new FileInfo(outputFull);
                            rec.OutputFileSizeBytes = fi.Length;
                            rec.OutputSha256 = ComputeSha256(outputFull);
                        }
                        catch (Exception ex)
                        {
                            rec.Detail = (rec.Detail ?? "") + " Output post-process warning: " + ex.Message;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                rec.Status = "failed";
                rec.Detail = MemoryHandoffHelper.AcquisitionExecutionErrorDetail(ex.Message);
                Logger.Error("MemoryAcquisitionCollector", ex);
            }

            MemoryHandoffHelper.ApplyAcquisitionValidation(rec, outputFull, cfg.Get("MemoryAcquireValidationMode"), cfg.Get("MemoryAcquireMinFileBytes"));
            MemoryHandoffHelper.FinalizeAcquisitionRecordAgainstDisk(outputDir, rec);
            MemoryHandoffHelper.ApplyAcquisitionDiagnostics(rec);
            rec.EndedAtUtc = DateTime.UtcNow.ToString("o");
            MemoryAcquisitionRecord.SaveToFile(rec, jsonPath);
        }

        private static void FinishRecord(MemoryAcquisitionRecord rec, string jsonPath)
        {
            rec.EndedAtUtc = DateTime.UtcNow.ToString("o");
            if (rec.StartedAtUtc != null && rec.EndedAtUtc != null)
            {
                DateTime a, b;
                if (DateTime.TryParse(rec.StartedAtUtc, out a) && DateTime.TryParse(rec.EndedAtUtc, out b))
                    rec.DurationMs = (long)Math.Max(0, (b - a).TotalMilliseconds);
            }
            MemoryAcquisitionRecord.SaveToFile(rec, jsonPath);
        }

        private static int ParseTimeout(string v)
        {
            int n;
            if (int.TryParse((v ?? "").Trim(), out n) && n > 0) return Math.Min(n, 86400);
            return 3600;
        }

        private static string ExpandArgs(string template, string outputFullPath, string memoryDir)
        {
            string t = template ?? "";
            t = t.Replace("{OutputPath}", outputFullPath);
            t = t.Replace("{outputPath}", outputFullPath);
            t = t.Replace("{OutputDir}", memoryDir);
            t = t.Replace("{outputDir}", memoryDir);
            return t;
        }

        private static string TrimTail(string s, int maxChars)
        {
            if (string.IsNullOrEmpty(s) || maxChars <= 0) return "";
            if (s.Length <= maxChars) return s;
            return s.Substring(s.Length - maxChars);
        }

        private static string ComputeSha256(string path)
        {
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "");
                }
            }
            catch
            {
                return "";
            }
        }

        private static string SanitizeFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
            {
                name = name.Replace(c.ToString(), "_");
            }
            return name;
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
    }
}
