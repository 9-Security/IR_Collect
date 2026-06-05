using System;
using System.IO;
using System.IO.Compression;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Linq;
using IR_Collect.Collectors;
using IR_Collect.Utils;

namespace IR_Collect
{
    public static class Collector
    {
        public sealed class CollectionResult
        {
            public string ZipPath { get; set; }
            public System.Collections.Generic.List<string> FailedSteps { get; set; }
            public CollectionCoverageReport CoverageReport { get; set; }

            public bool HasErrors
            {
                get { return GetFailedStepNames().Count > 0; }
            }

            public bool HasCoverageGaps
            {
                get
                {
                    return CoverageReport != null &&
                        ((CoverageReport.PartialSteps > 0) || (CoverageReport.MissingSteps > 0));
                }
            }

            public string BuildFailureSummary()
            {
                var failed = GetFailedStepNames();
                if (failed.Count == 0) return "";
                return string.Join(", ", failed.ToArray());
            }

            private System.Collections.Generic.List<string> GetFailedStepNames()
            {
                var failed = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (FailedSteps != null)
                {
                    foreach (string step in FailedSteps.Where(s => !string.IsNullOrWhiteSpace(s)))
                        failed.Add(step);
                }

                if (CoverageReport != null && CoverageReport.Steps != null)
                {
                    foreach (CollectionCoverageStep step in CoverageReport.Steps)
                    {
                        if (step == null || string.IsNullOrWhiteSpace(step.Step))
                            continue;
                        if (string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase))
                            failed.Add(step.Step);
                    }
                }

                return failed.ToList();
            }
        }

        public static string RunCollection()
        {
            return RunCollectionDetailed(null, null).ZipPath;
        }

        public static string RunCollection(string evidenceId)
        {
            return RunCollectionDetailed(evidenceId, null).ZipPath;
        }

        /// <param name="reportProgress">Optional; called with current step name (e.g. for GUI status).</param>
        public static string RunCollection(string evidenceId, Action<string> reportProgress)
        {
            return RunCollectionDetailed(evidenceId, reportProgress).ZipPath;
        }

        public static CollectionResult RunCollectionDetailed(string evidenceId, Action<string> reportProgress)
        {
            Action<string> report = reportProgress ?? (s => { });
            var failedSteps = new System.Collections.Generic.List<string>();
            var cfgProfile = new ConfigManager();
            string collectionModeProfile = CollectionModeProfileHelper.GetActive(cfgProfile);
            Console.WriteLine("Collection mode profile: " + collectionModeProfile);
            Console.WriteLine("Collecting System Info...");
            report("Collecting System Info...");
            
            string finalEvidenceId = NormalizeEvidenceId(evidenceId);
            string outputDir = "IR_Output_" + finalEvidenceId;
            
            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            File.WriteAllText(Path.Combine(outputDir, ArtifactNames.SystemInfoTxt), "Hostname: " + Environment.MachineName + "\r\nOS: " + Environment.OSVersion, new System.Text.UTF8Encoding(false));

            report("Collecting System Info...");
            RunCollectorStep("System Info", delegate { IR_Collect.Collectors.SystemCollector.Collect(outputDir); }, failedSteps);
            
            report("Collecting Persistence...");
            RunCollectorStep("Persistence", delegate { IR_Collect.Collectors.PersistenceCollector.Collect(outputDir); }, failedSteps);

            report("Collecting Execution Artifacts...");
            RunCollectorStep("Execution Artifacts", delegate { IR_Collect.Collectors.ExecutionArtifactCollector.Collect(outputDir); }, failedSteps);

            report("Collecting Event Logs...");
            RunCollectorStep("Event Logs", delegate { IR_Collect.Collectors.LogCollector.Collect(outputDir); }, failedSteps);

            report("Collecting USN Journal...");
            string sysDrive = Path.GetPathRoot(Environment.SystemDirectory).Substring(0, 1);
            RunCollectorStep("USN Journal", delegate { IR_Collect.Collectors.UsnCollector.Collect(outputDir, sysDrive); }, failedSteps);

            report("Collecting MFT...");
            try 
            {
                Console.WriteLine("Starting MFT Dump...");
                string mftFile = IR_Collect.MFT.MftDumper.DumpMft(sysDrive, outputDir);
                Console.WriteLine("MFT Dumped to: " + mftFile);
                
                // Quick Parse Demo
                var parseResult = IR_Collect.MFT.MftParser.ParseWithDiagnostics(mftFile, 5000); // Parse first 5000 entries for preview
                var entries = parseResult.Entries;
                if (parseResult.SkippedRecords > 0)
                {
                    Console.WriteLine("MFT parse warning: skipped " + parseResult.SkippedRecords + " malformed records.");
                    failedSteps.Add("MFT");
                }
                
                using (StreamWriter sw = new StreamWriter(Path.Combine(outputDir, ArtifactNames.MftPreviewCsv), false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("Record,InUse,IsDir,FileName,FullPath,Size,StdCreated,StdModified,StdMftModified,StdAccessed,FnCreated,FnModified,FnMftModified,FnAccessed");
                    foreach (var e in entries)
                    {
                        sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}",
                            e.RecordNumber,
                            e.InUse,
                            e.IsDirectory,
                            IR_Collect.Utils.CsvUtils.EscapeField(e.FileName),
                            IR_Collect.Utils.CsvUtils.EscapeField(e.FullPath),
                            e.Size,
                            e.StdCreated,
                            e.StdModified,
                            e.StdMftModified,
                            e.StdAccessed,
                            e.FnCreated,
                            e.FnModified,
                            e.FnMftModified,
                            e.FnAccessed
                        ));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("MFT Collection Error: " + ex.Message);
                Logger.Error("MFT Collection", ex);
                failedSteps.Add("MFT");
            }
            


            report("Collecting Recent Files...");
            RunCollectorStep("Recent Files", delegate { UserActivityCollector.CollectRecentFiles(outputDir); }, failedSteps);
            report("Collecting Recent Modifications (7d)...");
            RunCollectorStep("Recent Modifications", delegate { UserActivityCollector.CollectRecentModifications(outputDir); }, failedSteps);
            report("Collecting Browser History...");
            RunCollectorStep("Browser History", delegate { BrowserCollector.CollectBrowserHistory(outputDir); }, failedSteps);
            report("Collecting Registry Hives...");
            RunCollectorStep("Registry Hives", delegate { RegistryCollector.CollectRegistryHives(outputDir); }, failedSteps);
            report("Collecting Registry Activity...");
            RunCollectorStep("Registry Activity", delegate { RegistryActivityCollector.Collect(outputDir); }, failedSteps);
            report("Collecting Jump Lists...");
            RunCollectorStep("Jump Lists", delegate { JumpListsCollector.Collect(outputDir); }, failedSteps);
            report("Collecting Installed Software...");
            RunCollectorStep("Installed Software", delegate { SoftwareCollector.Collect(outputDir); }, failedSteps);
            report("Collecting Prefetch...");
            RunCollectorStep("Prefetch", delegate { PrefetchCollector.Collect(outputDir); }, failedSteps);
            report("Collecting File Integrity...");
            RunCollectorStep("Integrity", delegate { IntegrityCollector.Collect(outputDir); }, failedSteps);

            report("Building Activity Timeline...");
            try
            {
                ActivityTimelineBuilder.Build(outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Activity Timeline Build Error: " + ex.Message);
                Logger.Error("Activity Timeline Build", ex);
                failedSteps.Add("Activity Timeline");
            }

            report("Memory acquisition...");
            try
            {
                MemoryAcquisitionCollector.Collect(outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Memory acquisition error: " + ex.Message);
                Logger.Error("Memory acquisition", ex);
                failedSteps.Add("Memory acquisition");
            }

            report("Memory analysis handoff...");
            try
            {
                MemoryAnalysisCollector.Collect(outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Memory analysis handoff error: " + ex.Message);
                Logger.Error("Memory analysis handoff", ex);
                failedSteps.Add("Memory analysis handoff");
            }

            CollectionCoverageReport coverageReport = null;
            try
            {
                coverageReport = BuildCollectionCoverageReport(outputDir, finalEvidenceId, failedSteps, collectionModeProfile);
                CollectionCoverageSerializer.SaveToFile(coverageReport, Path.Combine(outputDir, ArtifactNames.CollectionCoverageJson));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Collection coverage report error: " + ex.Message);
                Logger.Warning("CollectionCoverageReport: " + ex.Message);
                failedSteps.Add("Collection Coverage");
            }

            report("Packaging...");
            GC.Collect();
            GC.WaitForPendingFinalizers();

            var cfg = new ConfigManager();

            int delaySec = 3;
            try
            {
                int n;
                if (int.TryParse(cfg.Get("PostCollectDelaySeconds"), out n) && n >= 0)
                    delaySec = Math.Min(n, 30);
            }
            catch (Exception ex) { Logger.Warning("PostCollectDelaySeconds read: " + ex.Message); }

            if (delaySec > 0)
            {
                Console.WriteLine("Waiting for file locks to release (" + delaySec + "s)...");
                System.Threading.Thread.Sleep(delaySec * 1000);
            }

            // Package Output
            string zipPath = finalEvidenceId + ".zip";
            Console.WriteLine("Packaging data to: " + zipPath);
            PackDir(outputDir, zipPath);
            if (!File.Exists(zipPath))
                throw new IOException("Packaging failed: zip file was not created: " + zipPath);

            string shaPath = zipPath + ".sha256";
            string sha256 = ComputeSha256(zipPath);
            if (!string.IsNullOrEmpty(sha256))
            {
                File.WriteAllText(shaPath, sha256, new System.Text.UTF8Encoding(false));
                Console.WriteLine("SHA256: " + sha256);
            }
            else
            {
                Console.WriteLine("SHA256 failed for: " + zipPath);
                failedSteps.Add("SHA256");
            }

            bool hasCoverageFailures = CoverageReportHasFailedSteps(coverageReport);
            bool hasCoverageGaps = CoverageReportHasGaps(coverageReport);
            if (failedSteps.Count > 0 || hasCoverageFailures)
                Console.WriteLine("Collection completed with errors. Output: " + zipPath);
            else if (hasCoverageGaps)
                Console.WriteLine("Collection completed with coverage gaps. Output: " + zipPath);
            else
                Console.WriteLine("Collection Complete. Output: " + zipPath);

            bool deleteOutputDir = true;
            try
            {
                string v = cfg.Get("DeleteOutputDirAfterZip");
                if (v == "0" || string.Equals(v, "false", StringComparison.OrdinalIgnoreCase))
                    deleteOutputDir = false;
            }
            catch (Exception ex) { Logger.Warning("DeleteOutputDirAfterZip config read failed: " + ex.Message); }
            if (deleteOutputDir && !string.IsNullOrEmpty(outputDir) && Directory.Exists(outputDir))
            {
                try
                {
                    Directory.Delete(outputDir, true);
                    Console.WriteLine("Temporary directory removed: " + outputDir);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Could not remove temporary directory (files may be in use): " + ex.Message);
                    Logger.Warning("DeleteOutputDir: " + ex.Message);
                }
            }
            return new CollectionResult
            {
                ZipPath = zipPath,
                FailedSteps = failedSteps.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                CoverageReport = coverageReport
            };
        }

        /// <summary>Output directory name (under current working directory unless otherwise rooted) used before ZIP packaging.</summary>
        public static string GetCollectionOutputDirectoryName(string evidenceId)
        {
            return "IR_Output_" + NormalizeEvidenceId(evidenceId);
        }

        private static CollectionCoverageReport BuildCollectionCoverageReport(string outputDir, string evidenceId, System.Collections.Generic.List<string> failedSteps, string collectionModeProfile)
        {
            var report = new CollectionCoverageReport();
            report.GeneratedAt = DateTime.UtcNow.ToString("o");
            report.Host = Environment.MachineName;
            report.EvidenceId = evidenceId ?? "";
            report.CollectionModeProfile = CollectionModeProfileHelper.Normalize(collectionModeProfile);
            report.Steps = new System.Collections.Generic.List<CollectionCoverageStep>();
            PopulateCollectionRuntimeContext(report);

            report.Steps.Add(BuildSystemCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildPersistenceCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildExecutionArtifactsCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildEventLogCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildUsnCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildMftCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildRecentFilesCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildRecentModificationCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildBrowserCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildRegistryCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildJumpListCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildInstalledSoftwareCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildPrefetchCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildIntegrityCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildTimelineCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildMemoryAcquisitionCoverageStep(outputDir, failedSteps));
            report.Steps.Add(BuildMemoryAnalysisCoverageStep(outputDir, failedSteps));

            foreach (CollectionCoverageStep step in report.Steps)
            {
                string status = step != null ? (step.Status ?? "") : "";
                if (string.Equals(status, "complete", StringComparison.OrdinalIgnoreCase))
                    report.CompletedSteps++;
                else if (string.Equals(status, "partial", StringComparison.OrdinalIgnoreCase))
                    report.PartialSteps++;
                else if (string.Equals(status, "skipped", StringComparison.OrdinalIgnoreCase))
                    report.SkippedSteps++;
                else if (string.Equals(status, "missing", StringComparison.OrdinalIgnoreCase))
                    report.MissingSteps++;
                else
                    report.FailedSteps++;
            }

            if (report.FailedSteps > 0)
                report.OverallStatus = "failed";
            else if (report.PartialSteps > 0 || report.MissingSteps > 0)
                report.OverallStatus = "partial";
            else
                report.OverallStatus = "complete";

            return report;
        }

        private static CollectionCoverageStep BuildSystemCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "System Info");

            AddFileCoverage(outputDir, ArtifactNames.SystemInfoTxt, "system_info.txt", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.SystemInfoFullTxt, "system_info_full.txt", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ProcessListCsv, "process_list.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.LogonSessionsCsv, "logon_sessions.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.NetworkResourcesCsv, "network_resources.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ServerConnectionsCsv, "server_connections.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.StoredCredentialsTxt, "stored_credentials.txt", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.KerberosTicketsTxt, "kerberos_tickets.txt", present, missing);

            int networkCount = CountFiles(outputDir, new string[] { "network_connections.txt", "arp_table.txt", "dns_cache.txt", "network_config.txt" });
            if (networkCount > 0) present.Add("network artifacts (" + networkCount + "/4)");
            else missing.Add("network artifacts");

            string detail = "system info, process inventory, live logon/network identity artifacts, credential artifacts, and network artifacts";
            return CreateCoverageStep("System Info", failed, present, missing, detail);
        }

        private static CollectionCoverageStep BuildPersistenceCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Persistence");

            AddFileCoverage(outputDir, ArtifactNames.AutorunsRegistryCsv, "autoruns_registry.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ServicesCsv, "services.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ScheduledTasksXml, "scheduled_tasks.xml", present, missing);

            return CreateCoverageStep("Persistence", failed, present, missing, "autoruns, services, and scheduled task definitions");
        }

        private static CollectionCoverageStep BuildExecutionArtifactsCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Execution Artifacts");

            AddFileCoverage(outputDir, ArtifactNames.BamDamCsv, "bam_dam.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.BitsJobsCsv, "bits_jobs.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.WmiPersistenceCsv, "wmi_persistence.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ShimCacheCsv, "shimcache.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.ShimCacheEntriesCsv, "shimcache_entries.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.AmcacheProgramsCsv, "amcache_programs.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.AmcacheFilesCsv, "amcache_files.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.SrumNetworkUsageCsv, "srum_network_usage.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.SrumAppUsageCsv, "srum_app_usage.csv", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.AmcacheHive, "ExecutionArtifacts\\Amcache.hve", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.SrumDb, "ExecutionArtifacts\\SRUDB.dat", present, missing);

            return CreateCoverageStep("Execution Artifacts", failed, present, missing, "BAM/DAM, BITS, WMI persistence, structured Amcache/ShimCache/SRUM CSV, and raw Amcache/SRUM artifacts");
        }

        private static CollectionCoverageStep BuildEventLogCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Event Logs");

            string logsDir = Path.Combine(outputDir, "EventLogs");
            var evtxFiles = GetPatternFiles(logsDir, "*.evtx");
            var filteredFiles = GetPatternFiles(logsDir, ArtifactNames.EventLogFilteredGlob);
            int evtxCount = evtxFiles.Count;
            int filteredCount = filteredFiles.Count;

            if (evtxCount > 0) present.Add("EventLogs/*.evtx (" + evtxCount + ")");
            else missing.Add("EventLogs/*.evtx");

            if (filteredCount > 0) present.Add("EventLogs/*" + ArtifactNames.EventLogFilteredSuffix + " (" + filteredCount + ")");
            else missing.Add("EventLogs/*" + ArtifactNames.EventLogFilteredSuffix);

            var evtxLabels = evtxFiles
                .Select(path => Path.GetFileNameWithoutExtension(path) ?? "")
                .Where(label => !string.IsNullOrWhiteSpace(label))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(label => label, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var filteredLabels = filteredFiles
                .Select(path => ArtifactNames.GetEventLogLabelFromFileName(Path.GetFileName(path) ?? ""))
                .Where(label => !string.IsNullOrWhiteSpace(label))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(label => label, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var missingFilteredLabels = evtxLabels
                .Except(filteredLabels, StringComparer.OrdinalIgnoreCase)
                .OrderBy(label => label, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var missingRawLabels = filteredLabels
                .Except(evtxLabels, StringComparer.OrdinalIgnoreCase)
                .OrderBy(label => label, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (string label in missingFilteredLabels)
                missing.Add(Path.Combine("EventLogs", label + ArtifactNames.EventLogFilteredSuffix));
            foreach (string label in missingRawLabels)
                missing.Add(Path.Combine("EventLogs", label + ".evtx"));

            string detail = "raw EVTX plus filtered CSV views";
            if (missingFilteredLabels.Count > 0)
                detail += "; missing filtered CSV for: " + string.Join(", ", missingFilteredLabels.ToArray());
            if (missingRawLabels.Count > 0)
                detail += "; missing raw EVTX for: " + string.Join(", ", missingRawLabels.ToArray());

            return CreateCoverageStep("Event Logs", failed, present, missing.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), detail);
        }

        private static CollectionCoverageStep BuildUsnCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "USN Journal");
            AddFileCoverage(outputDir, ArtifactNames.UsnJournalCsv, "usn_journal.csv", present, missing);
            return CreateCoverageStep("USN Journal", failed, present, missing, "USN journal CSV export");
        }

        private static CollectionCoverageStep BuildMftCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "MFT");
            AddFileCoverage(outputDir, ArtifactNames.MftDumpBin, "MFT_Dump.bin", present, missing);
            AddFileCoverage(outputDir, ArtifactNames.MftPreviewCsv, "mft_preview.csv", present, missing);
            return CreateCoverageStep("MFT", failed, present, missing, "raw MFT dump plus preview CSV");
        }

        private static CollectionCoverageStep BuildRecentFilesCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Recent Files");
            AddFileCoverage(outputDir, ArtifactNames.RecentFilesCsv, "recent_files.csv", present, missing);
            return CreateCoverageStep("Recent Files", failed, present, missing, "recent files CSV");
        }

        private static CollectionCoverageStep BuildRecentModificationCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Recent Modifications");
            AddFileCoverage(outputDir, ArtifactNames.Filesystem7DaysCsv, "filesystem_7days.csv", present, missing);
            return CreateCoverageStep("Recent Modifications", failed, present, missing, "recently modified filesystem CSV");
        }

        private static CollectionCoverageStep BuildBrowserCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Browser History");

            int browserCount = CountPattern(Path.Combine(outputDir, "Browsers"), "*");
            if (browserCount > 0) present.Add("Browsers/* (" + browserCount + ")");
            else missing.Add("Browsers/*");

            return CreateCoverageStep("Browser History", failed, present, missing, "copied browser databases and sidecars");
        }

        private static CollectionCoverageStep BuildRegistryCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool registryFailed = ContainsFailedStep(failedSteps, "Registry Hives");
            bool activityFailed = ContainsFailedStep(failedSteps, "Registry Activity");
            bool failed = registryFailed || activityFailed;

            int hiveCount = CountPattern(Path.Combine(outputDir, "Registry"), "*");
            if (hiveCount > 0) present.Add("Registry/* (" + hiveCount + ")");
            else missing.Add("Registry/*");

            AddFileCoverage(outputDir, ArtifactNames.ActivityTimelineCsv, "activity_timeline.csv", present, missing);
            return CreateCoverageStep("Registry", failed, present, missing, "registry hives plus registry/activity timeline CSV");
        }

        private static CollectionCoverageStep BuildJumpListCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Jump Lists");

            AddFileCoverage(outputDir, ArtifactNames.JumpListsCsv, "jump_lists.csv", present, missing);
            int jumpListCount = CountPattern(Path.Combine(outputDir, "JumpLists"), "*");
            if (jumpListCount > 0) present.Add("JumpLists/* (" + jumpListCount + ")");
            else missing.Add("JumpLists/*");

            return CreateCoverageStep("Jump Lists", failed, present, missing, "jump list CSV plus copied destination files");
        }

        private static CollectionCoverageStep BuildInstalledSoftwareCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Installed Software");
            AddFileCoverage(outputDir, ArtifactNames.InstalledSoftwareCsv, "installed_software.csv", present, missing);
            return CreateCoverageStep("Installed Software", failed, present, missing, "installed software inventory CSV");
        }

        private static CollectionCoverageStep BuildPrefetchCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Prefetch");

            int prefetchCount = CountPattern(Path.Combine(outputDir, "Prefetch"), "*.pf");
            if (prefetchCount > 0) present.Add("Prefetch/*.pf (" + prefetchCount + ")");
            else missing.Add("Prefetch/*.pf");

            return CreateCoverageStep("Prefetch", failed, present, missing, "copied prefetch files");
        }

        private static CollectionCoverageStep BuildIntegrityCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Integrity");
            AddFileCoverage(outputDir, ArtifactNames.FileIntegrityCsv, "file_integrity.csv", present, missing);
            return CreateCoverageStep("Integrity", failed, present, missing, "integrity baseline CSV");
        }

        private static CollectionCoverageStep BuildTimelineCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            bool failed = ContainsFailedStep(failedSteps, "Activity Timeline");
            AddFileCoverage(outputDir, ArtifactNames.ActivityTimelineCsv, "activity_timeline.csv", present, missing);
            return CreateCoverageStep("Unified Timeline", failed, present, missing, "activity timeline synthesized from collected artifacts");
        }

        private static CollectionCoverageStep BuildMemoryAcquisitionCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            string jsonPath = Path.Combine(outputDir, ArtifactNames.MemoryAcquisitionJson);
            MemoryAcquisitionRecord rec = MemoryAcquisitionRecord.TryLoad(jsonPath);
            if (rec == null)
            {
                bool failed = ContainsFailedStep(failedSteps, "Memory acquisition");
                var step = new CollectionCoverageStep();
                step.Step = "Memory acquisition";
                if (File.Exists(jsonPath))
                {
                    step.Status = "failed";
                    step.Detail = "memory_acquisition.json is present but could not be parsed.";
                }
                else
                {
                    step.Status = failed ? "failed" : "missing";
                    step.Detail = failed
                        ? "memory_acquisition.json was not written (collection step may have aborted before sidecar)."
                        : "memory_acquisition.json not found after collection.";
                }
                step.ArtifactsPresent = present;
                step.ArtifactsMissing = missing;
                step.ArtifactCount = 0;
                return step;
            }

            if (File.Exists(jsonPath))
                present.Add(ArtifactNames.MemoryAcquisitionJson);

            string relOut = rec.OutputRelativePath ?? "";
            string combinedFull = null;
            if (!string.IsNullOrEmpty(relOut))
            {
                try
                {
                    combinedFull = Path.GetFullPath(Path.Combine(outputDir, relOut));
                }
                catch { }
            }

            bool dumpPresent = !string.IsNullOrEmpty(combinedFull) && File.Exists(combinedFull);
            if (!string.IsNullOrEmpty(relOut))
            {
                if (dumpPresent)
                    present.Add(relOut);
                else
                    missing.Add(relOut);
            }

            var s = new CollectionCoverageStep();
            s.Step = "Memory acquisition";
            string st = (rec.Status ?? "").Trim().ToLowerInvariant();
            if (st != "complete" && st != "partial" && st != "failed" && st != "skipped" && st != "missing")
                st = "failed";

            string detail = string.IsNullOrEmpty(rec.Detail)
                ? "See memory_acquisition.json for tool path, timing, and hashes."
                : rec.Detail;
            if (!string.IsNullOrEmpty(relOut) && !dumpPresent)
            {
                if (string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase))
                {
                    st = "failed";
                    detail = detail + " [Coverage] Sidecar reported complete but expected dump is absent: " + relOut + ".";
                }
                else if (string.Equals(st, "partial", StringComparison.OrdinalIgnoreCase))
                {
                    detail = detail + " [Coverage] Expected dump absent on disk: " + relOut + ".";
                }
            }

            s.Status = st;
            s.Detail = detail;
            s.ArtifactsPresent = present;
            s.ArtifactsMissing = missing;
            s.ArtifactCount = present.Count;
            return s;
        }

        private static CollectionCoverageStep BuildMemoryAnalysisCoverageStep(string outputDir, System.Collections.Generic.List<string> failedSteps)
        {
            var present = new System.Collections.Generic.List<string>();
            var missing = new System.Collections.Generic.List<string>();
            string jsonPath = Path.Combine(outputDir, ArtifactNames.MemoryAnalysisJson);
            MemoryAnalysisRecord rec = MemoryAnalysisRecord.TryLoad(jsonPath);
            if (rec == null)
            {
                bool failed = ContainsFailedStep(failedSteps, "Memory analysis handoff");
                var step = new CollectionCoverageStep();
                step.Step = "Memory analysis handoff";
                if (File.Exists(jsonPath))
                {
                    step.Status = "failed";
                    step.Detail = "memory_analysis.json is present but could not be parsed.";
                }
                else
                {
                    step.Status = failed ? "failed" : "missing";
                    step.Detail = failed
                        ? "memory_analysis.json was not written (analysis handoff may have aborted before sidecar)."
                        : "memory_analysis.json not found after collection.";
                }
                step.ArtifactsPresent = present;
                step.ArtifactsMissing = missing;
                step.ArtifactCount = 0;
                return step;
            }

            if (File.Exists(jsonPath))
                present.Add(ArtifactNames.MemoryAnalysisJson);

            string outputDirRel = rec.OutputDirectoryRelativePath ?? "";
            string outputDirFull = null;
            if (!string.IsNullOrEmpty(outputDirRel))
            {
                try { outputDirFull = Path.GetFullPath(Path.Combine(outputDir, outputDirRel)); }
                catch { }
            }

            if (!string.IsNullOrEmpty(outputDirRel))
            {
                if (!string.IsNullOrEmpty(outputDirFull) && Directory.Exists(outputDirFull))
                    present.Add(outputDirRel + "\\");
                else
                    missing.Add(outputDirRel + "\\");
            }

            if (rec.OutputFiles != null)
            {
                foreach (string rel in rec.OutputFiles.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        string full = Path.GetFullPath(Path.Combine(outputDir, rel));
                        if (File.Exists(full))
                            present.Add(rel);
                        else
                            missing.Add(rel);
                    }
                    catch
                    {
                        missing.Add(rel);
                    }
                }
            }

            var s = new CollectionCoverageStep();
            s.Step = "Memory analysis handoff";
            string st = (rec.Status ?? "").Trim().ToLowerInvariant();
            if (st != "complete" && st != "partial" && st != "failed" && st != "skipped" && st != "missing")
                st = "failed";

            string detail = string.IsNullOrEmpty(rec.Detail)
                ? "See memory_analysis.json for external tool command, timing, and generated output files."
                : rec.Detail;

            int outputFileCount = rec.OutputFiles != null
                ? rec.OutputFiles.Count(v => !string.IsNullOrWhiteSpace(v))
                : 0;
            bool outputDirectoryExists = !string.IsNullOrEmpty(outputDirFull) && Directory.Exists(outputDirFull);
            if ((string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(st, "partial", StringComparison.OrdinalIgnoreCase)) &&
                (!outputDirectoryExists || outputFileCount <= 0))
            {
                if (string.Equals(st, "complete", StringComparison.OrdinalIgnoreCase))
                {
                    st = "failed";
                    detail = detail + " [Coverage] Sidecar reported complete but analysis outputs are absent.";
                }
                else
                {
                    detail = detail + " [Coverage] Analysis outputs are absent on disk.";
                }
            }

            s.Status = st;
            s.Detail = detail;
            s.ArtifactsPresent = present.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            s.ArtifactsMissing = missing.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            s.ArtifactCount = s.ArtifactsPresent.Count;
            return s;
        }

        private static CollectionCoverageStep CreateCoverageStep(string stepName, bool failed, System.Collections.Generic.List<string> present, System.Collections.Generic.List<string> missing, string detail)
        {
            var step = new CollectionCoverageStep();
            step.Step = stepName;
            step.Detail = detail ?? "";
            step.ArtifactsPresent = present ?? new System.Collections.Generic.List<string>();
            step.ArtifactsMissing = missing ?? new System.Collections.Generic.List<string>();
            step.ArtifactCount = step.ArtifactsPresent.Count;
            step.Status = DetermineCoverageStatus(failed, step.ArtifactsPresent.Count, step.ArtifactsMissing.Count);
            return step;
        }

        private static void PopulateCollectionRuntimeContext(CollectionCoverageReport report)
        {
            if (report == null)
                return;

            try
            {
                report.CollectorUser = WindowsIdentity.GetCurrent() != null ? (WindowsIdentity.GetCurrent().Name ?? "") : "";
            }
            catch (Exception ex)
            {
                Logger.Warning("PopulateCollectionRuntimeContext user: " + ex.Message);
                report.CollectorUser = "";
            }

            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    report.IsAdministrator = id != null && new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("PopulateCollectionRuntimeContext admin: " + ex.Message);
                report.IsAdministrator = false;
            }

            try
            {
                string status;
                report.BackupPrivilegeEnabled = IR_Collect.MFT.NativeMethods.EnableBackupPrivilege(out status);
                report.BackupPrivilegeStatus = status ?? "";
            }
            catch (Exception ex)
            {
                Logger.Warning("PopulateCollectionRuntimeContext backup privilege: " + ex.Message);
                report.BackupPrivilegeEnabled = false;
                report.BackupPrivilegeStatus = ex.Message ?? "unknown error";
            }

            if (report.IsAdministrator)
                report.CollectorPrivilegeState = report.BackupPrivilegeEnabled ? "Administrator+SeBackupPrivilege" : "Administrator";
            else
                report.CollectorPrivilegeState = "StandardUser";
        }

        private static string DetermineCoverageStatus(bool failed, int presentCount, int missingCount)
        {
            if (failed)
                return "failed";
            if (presentCount <= 0)
                return missingCount > 0 ? "missing" : "failed";
            return missingCount > 0 ? "partial" : "complete";
        }

        private static bool ContainsFailedStep(System.Collections.Generic.List<string> failedSteps, string stepName)
        {
            return failedSteps != null && failedSteps.Any(s => string.Equals(s, stepName, StringComparison.OrdinalIgnoreCase));
        }

        private static void AddFileCoverage(string outputDir, string relativePath, string label, System.Collections.Generic.List<string> present, System.Collections.Generic.List<string> missing)
        {
            string fullPath = Path.Combine(outputDir, relativePath);
            if (File.Exists(fullPath)) present.Add(label);
            else missing.Add(label);
        }

        private static int CountFiles(string outputDir, string[] relativePaths)
        {
            if (relativePaths == null) return 0;
            int count = 0;
            foreach (string relativePath in relativePaths)
            {
                try
                {
                    if (File.Exists(Path.Combine(outputDir, relativePath))) count++;
                }
                catch { }
            }
            return count;
        }

        private static int CountPattern(string directory, string pattern)
        {
            try
            {
                if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory)) return 0;
                return Directory.GetFiles(directory, pattern ?? "*", SearchOption.TopDirectoryOnly).Length;
            }
            catch
            {
                return 0;
            }
        }

        private static System.Collections.Generic.List<string> GetPatternFiles(string directory, string pattern)
        {
            try
            {
                if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
                    return new System.Collections.Generic.List<string>();
                return Directory.GetFiles(directory, pattern ?? "*", SearchOption.TopDirectoryOnly).ToList();
            }
            catch
            {
                return new System.Collections.Generic.List<string>();
            }
        }

        private static bool CoverageReportHasFailedSteps(CollectionCoverageReport report)
        {
            return report != null && report.Steps != null &&
                report.Steps.Any(step => step != null && string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase));
        }

        private static bool CoverageReportHasGaps(CollectionCoverageReport report)
        {
            return report != null && (report.PartialSteps > 0 || report.MissingSteps > 0);
        }

        internal static void PackDir(string sourceDir, string zipFile)
        {
            try
            {
                if (File.Exists(zipFile)) File.Delete(zipFile);
                ZipFile.CreateFromDirectory(sourceDir, zipFile, CompressionLevel.Optimal, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Packaging failed: " + ex.Message);
                Logger.Error("PackDir", ex);
                throw new IOException("Packaging failed: " + ex.Message, ex);
            }
        }

        private const int MaxEvidenceIdLength = 64;

        private static string NormalizeEvidenceId(string evidenceId)
        {
            string id = evidenceId;
            if (string.IsNullOrWhiteSpace(id))
            {
                id = GenerateEvidenceId();
            }
            id = SanitizeFileName(id.Trim());
            if (id.Length > MaxEvidenceIdLength) id = id.Substring(0, MaxEvidenceIdLength);
            var allowed = new System.Text.StringBuilder(id.Length);
            foreach (char ch in id)
            {
                if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_') allowed.Append(ch);
                else allowed.Append('_');
            }
            return allowed.ToString();
        }

        private static string GenerateEvidenceId()
        {
            string letters = RandomLetters(2);
            string ts = DateTime.Now.ToString("yyyyMMddHHmm");
            return letters + "-" + ts;
        }

        private static string RandomLetters(int count)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            var rnd = new Random(Guid.NewGuid().GetHashCode());
            char[] chars = new char[count];
            for (int i = 0; i < count; i++)
            {
                chars[i] = alphabet[rnd.Next(0, alphabet.Length)];
            }
            return new string(chars);
        }

        private static string SanitizeFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
            {
                name = name.Replace(c.ToString(), "_");
            }
            return name;
        }

        private static string ComputeSha256(string path)
        {
            try
            {
                if (!File.Exists(path)) return "";
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("SHA256 failed: " + ex.Message);
                return "";
            }
        }

        private static void RunCollectorStep(string stepName, Action action, System.Collections.Generic.List<string> failedSteps)
        {
            try
            {
                if (action != null) action();
            }
            catch (Exception ex)
            {
                Console.WriteLine(stepName + " Error: " + ex.Message);
                Logger.Error(stepName, ex);
                if (failedSteps != null) failedSteps.Add(stepName);
            }
        }


        /// <summary>Run external command via cmd. Paths/args with " or &amp; are escaped via EscapeArgForCmd.</summary>
        public static class CommandHelper
        {
            private sealed class CommandResult
            {
                public string Output;
                public string Error;
                public int ExitCode;
            }

            /// <summary>Escape one argument for cmd.exe so that space, ", and &amp; do not break parsing. Call when building args that contain paths.</summary>
            public static string EscapeArgForCmd(string arg)
            {
                if (arg == null) return "\"\"";
                // Windows path/identifier arguments cannot legally contain a double-quote.
                // Strip any stray '"' defensively: cmd.exe treats '"' as a quote toggle, so an
                // embedded quote could break out of the wrapping below and expose the tail to the
                // shell. Removing it cannot corrupt a real path (the char is illegal in paths).
                string sanitized = arg.IndexOf('"') >= 0 ? arg.Replace("\"", "") : arg;
                // Quote when the value contains a space or any cmd metacharacter.
                if (sanitized.IndexOfAny(new char[] { ' ', '&', '^', '|', '<', '>', '(', ')', '%', '!', '"' }) < 0)
                    return sanitized;
                // Inside double quotes cmd.exe does NOT process & | < > ^ ( ), so the value is passed
                // through verbatim. The previous `^&` / `\"` escaping was wrong: caret is literal
                // inside quotes (it injected a stray '^'), and `\"` ends cmd's quote state early.
                return "\"" + sanitized + "\"";
            }

            public static string Run(string fileName, string args)
            {
                CommandResult result = RunCore(fileName, args);
                if (result.ExitCode != 0)
                {
                    string detail = !string.IsNullOrWhiteSpace(result.Error) ? result.Error : result.Output;
                    string message = string.Format("{0} exited with code {1}", fileName, result.ExitCode);
                    if (!string.IsNullOrWhiteSpace(detail))
                    {
                        detail = detail.Replace("\r", " ").Replace("\n", " ").Trim();
                        if (detail.Length > 240) detail = detail.Substring(0, 237) + "...";
                        message += ": " + detail;
                    }
                    Logger.Warning("CommandHelper.Run " + fileName + ": " + message);
                    throw new InvalidOperationException(message);
                }
                return result.Output ?? "";
            }

            /// <summary>Upper bound for any single external command. Prevents a hung child
            /// (e.g. wmic blocked on a slow domain, fsutil on a giant journal) from stalling
            /// the whole collection indefinitely.</summary>
            private const int CommandTimeoutMs = 300000; // 5 minutes

            private static CommandResult RunCore(string fileName, string args)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = "cmd.exe";
                    // Force UTF-8 (cp65001) before running the command
                    psi.Arguments = string.Format("/c chcp 65001 > nul && {0} {1}", fileName, args);
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    // Important: Set encoding to UTF8 to read the 65001 output correctly
                    psi.StandardOutputEncoding = System.Text.Encoding.UTF8;
                    psi.StandardErrorEncoding = System.Text.Encoding.UTF8;

                    using (Process p = Process.Start(psi))
                    {
                        // Drain stderr on a background thread while reading stdout on this thread.
                        // Reading one stream fully before the other can deadlock if the child fills
                        // the second pipe's buffer (~4 KB) while we are still blocked on the first.
                        var errSb = new System.Text.StringBuilder();
                        var errThread = new System.Threading.Thread(delegate()
                        {
                            try { errSb.Append(p.StandardError.ReadToEnd()); }
                            catch { /* pipe closed / process gone */ }
                        });
                        errThread.IsBackground = true;
                        errThread.Start();

                        string output;
                        try { output = p.StandardOutput.ReadToEnd(); }
                        catch { output = ""; }

                        if (!p.WaitForExit(CommandTimeoutMs))
                        {
                            try { p.Kill(); } catch { /* may already be exiting */ }
                            errThread.Join(2000);
                            string msg = string.Format("{0} timed out after {1} ms", fileName, CommandTimeoutMs);
                            Logger.Warning("CommandHelper.Run " + fileName + ": " + msg);
                            throw new TimeoutException(msg);
                        }
                        // Ensure the process is fully reaped and the stderr drain has finished.
                        p.WaitForExit();
                        errThread.Join(2000);

                        return new CommandResult
                        {
                            Output = output,
                            Error = errSb.ToString(),
                            ExitCode = p.ExitCode
                        };
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warning("CommandHelper.Run " + fileName + ": " + ex.Message);
                    throw;
                }
            }

            public static void RunToFile(string fileName, string args, string outputFile)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = "cmd.exe";
                    psi.Arguments = string.Format("/c chcp 65001 > nul && {0} {1}", fileName, args);
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.StandardOutputEncoding = System.Text.Encoding.UTF8;
                    psi.StandardErrorEncoding = System.Text.Encoding.UTF8;

                    using (Process p = Process.Start(psi))
                    {
                        var errSb = new System.Text.StringBuilder();
                        var errThread = new System.Threading.Thread(delegate()
                        {
                            try { errSb.Append(p.StandardError.ReadToEnd()); } catch { }
                        });
                        errThread.IsBackground = true;
                        errThread.Start();

                        // Stream stdout straight to the file in chunks so a huge result (e.g. a busy
                        // volume's USN journal CSV — potentially GB) is never buffered whole in memory.
                        using (var writer = new StreamWriter(outputFile, false, new System.Text.UTF8Encoding(false)))
                        {
                            char[] buffer = new char[65536];
                            int read;
                            while ((read = p.StandardOutput.Read(buffer, 0, buffer.Length)) > 0)
                                writer.Write(buffer, 0, read);
                        }

                        if (!p.WaitForExit(CommandTimeoutMs))
                        {
                            try { p.Kill(); } catch { }
                            errThread.Join(2000);
                            throw new TimeoutException(string.Format("{0} timed out after {1} ms", fileName, CommandTimeoutMs));
                        }
                        p.WaitForExit();
                        errThread.Join(2000);

                        if (p.ExitCode != 0)
                        {
                            string detail = errSb.ToString();
                            string message = string.Format("{0} exited with code {1}", fileName, p.ExitCode);
                            if (!string.IsNullOrWhiteSpace(detail))
                            {
                                detail = detail.Replace("\r", " ").Replace("\n", " ").Trim();
                                if (detail.Length > 240) detail = detail.Substring(0, 237) + "...";
                                message += ": " + detail;
                            }
                            throw new InvalidOperationException(message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // All-or-nothing (matches the prior Run()+WriteAllText behavior): never leave a
                    // partial output file behind on timeout / non-zero exit / any error.
                    TryDeleteFile(outputFile);
                    Logger.Warning("CommandHelper.RunToFile " + fileName + ": " + ex.Message);
                    throw;
                }
            }

            private static void TryDeleteFile(string path)
            {
                try { if (!string.IsNullOrEmpty(path) && File.Exists(path)) File.Delete(path); } catch { }
            }
            
            public static void RunWmicToFile(string wmicArgs, string outputFile)
            {
                 // Filter empty lines for WMIC
                 string output = Run("wmic", wmicArgs);
                 // Simple cleaning: Remove empty lines
                 var sb = new System.Text.StringBuilder();
                 using (StringReader sr = new StringReader(output)) {
                    string line;
                    while((line = sr.ReadLine()) != null) {
                        if (!string.IsNullOrWhiteSpace(line)) sb.AppendLine(line.Trim());
                    }
                 }
                 File.WriteAllText(outputFile, sb.ToString(), new System.Text.UTF8Encoding(false));
            }

            public static void RunCommand(string fileName, string args)
            {
                Run(fileName, args);
            }
        }
    }
}
