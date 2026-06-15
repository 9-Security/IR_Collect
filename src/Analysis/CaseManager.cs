using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using IR_Collect.Utils;
using IR_Collect.Analysis.Correlation;
using IR_Collect;

namespace IR_Collect.Analysis
{
    public class CaseData
    {
        public string Hostname { get; set; }
        public string CaseID { get; set; }
        public string SourceZip { get; set; }
        public string ExtractPath { get; set; }
        public string CachePath { get; set; }
        public Dictionary<string, string> Artifacts { get; set; }
        public List<IR_Collect.MFT.MftParser.MftEntry> MftEntries { get; set; }
        public IR_Collect.Analysis.Correlation.FactStore FactStore { get; set; }
        /// <summary>True 表示該案卷的 Fact Store 正在背景建置中，UI 應略過或顯示「建置中」。</summary>
        public bool FactStoreBuilding { get; set; }
        public List<string> LoadWarnings { get; set; }
        public List<string> RebuiltEventLogLabels { get; set; }
        public CollectionCoverageReport CollectionCoverage { get; set; }
        public string FactStoreFreshnessStatus { get; set; }
        public string FactStoreFreshnessDetail { get; set; }
        public AnalystWorkflowState AnalystWorkflow { get; set; }
        public string AnalystWorkflowPath { get; set; }
        /// <summary>External memory acquisition sidecar (collection-only; no dump parsing).</summary>
        public MemoryAcquisitionRecord MemoryAcquisitionMeta { get; set; }
        /// <summary>External memory analysis handoff sidecar (output orchestration only; no in-app memory verdicts).</summary>
        public MemoryAnalysisRecord MemoryAnalysisMeta { get; set; }
        /// <summary>Phase 5.2: SHA-256 manifest of the input files as received (folder intake only).</summary>
        public List<EvidenceFile> EvidenceFiles { get; set; }
        /// <summary>Phase 5.2: rollup digest over the evidence manifest (one hash for the whole input set).</summary>
        public string EvidenceDigest { get; set; }

        public CaseData()
        {
            MftEntries = new List<IR_Collect.MFT.MftParser.MftEntry>();
            Artifacts = new Dictionary<string, string>();
            LoadWarnings = new List<string>();
            RebuiltEventLogLabels = new List<string>();
            FactStoreFreshnessStatus = "not_present";
            FactStoreFreshnessDetail = "fact_store.db is not present in this case.";
            AnalystWorkflow = new AnalystWorkflowState();
        }
    }

     public static class CaseManager
     {
        private const string MissingFilteredEventLogWarning = "EVTX event logs are present without filtered CSV. Raw evidence is preserved, but event-derived facts/timeline/export will be limited.";
        private const string MissingOriginalEventLogWarning = "Filtered event CSV is present without original EVTX. Event-derived analysis is available, but raw event record preservation is incomplete.";
        private const string OfflineEventLogRebuildWarningPrefix = "Offline Event Log filtered CSV reconstruction was incomplete:";
         private sealed class ZipExtractionResult
         {
            public int ExtractedFiles;
            public int FailedEntries;
            public int RejectedEntries;
        }

        public sealed class EventLogRebuildResult
        {
            public int TotalLogs { get; set; }
            public int RebuiltLogs { get; set; }
            public int FailedLogs { get; set; }
            public int SkippedLogs { get; set; }
            public int EffectiveDaysBack { get; set; }
            public int MaxEventsPerLog { get; set; }
            public List<string> RebuiltLabels { get; set; }
            public List<string> FailedLabels { get; set; }
            public string Detail { get; set; }

            public EventLogRebuildResult()
            {
                RebuiltLabels = new List<string>();
                FailedLabels = new List<string>();
                Detail = "";
            }
        }

        private static readonly object _lock = new object();
        private static readonly List<CaseData> _cases = new List<CaseData>();

        /// <summary>True if <paramref name="itemFullPath"/> is under <paramref name="rootDirectory"/> (prefix-safe; avoids C:\foo matching C:\foobar).</summary>
        internal static bool IsPathUnderRoot(string itemFullPath, string rootDirectory)
        {
            if (string.IsNullOrEmpty(itemFullPath) || string.IsNullOrEmpty(rootDirectory)) return false;
            try
            {
                string root = Path.GetFullPath(rootDirectory);
                string full = Path.GetFullPath(itemFullPath);
                if (!root.EndsWith(Path.DirectorySeparatorChar.ToString()))
                    root += Path.DirectorySeparatorChar;
                return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>已載入的案件清單（執行緒安全快照）。</summary>
        public static List<CaseData> LoadedCases
        {
            get { lock (_lock) { return new List<CaseData>(_cases); } }
        }

        /// <summary>從 config.ini 讀取 MftMaxEntries，預設 100000，上限 500000（記憶體優化）。</summary>
        private static int GetMftMaxEntries()
        {
            try
            {
                var cfg = new ConfigManager();
                int n;
                if (int.TryParse(cfg.Get("MftMaxEntries"), out n) && n > 0)
                    return Math.Min(Math.Max(n, 1000), 500000);
            }
            catch (Exception ex)
            {
                Logger.Warning("GetMftMaxEntries: " + ex.Message);
            }
            return 100000;
        }

        public static CaseData LoadCase(string zipPath)
        {
             if (string.IsNullOrWhiteSpace(zipPath))
                 throw new ArgumentException("zipPath is null or empty.", "zipPath");
             if (!File.Exists(zipPath))
                 throw new FileNotFoundException("Case zip not found.", zipPath);
             try { zipPath = Path.GetFullPath(zipPath); } catch (Exception ex) { Logger.Warning("LoadCase GetFullPath: " + ex.Message); }

             // 1. Unpack
             string caseId = "Case_" + Path.GetFileNameWithoutExtension(zipPath) + "_" + DateTime.Now.Ticks;
             string cacheDir = Path.Combine(Path.GetTempPath(), caseId);
             
             if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true);
             Directory.CreateDirectory(cacheDir);

             try
             {
                 ExtractZipSafely(zipPath, cacheDir);
             }
             catch (Exception ex)
             {
                 TryDeleteDirectory(cacheDir);
                 Logger.Error("LoadCase extract " + zipPath, ex);
                 throw;
             }

             // 2. Parse Info
             CaseData newCase = new CaseData();
             newCase.CaseID = caseId;
             newCase.SourceZip = zipPath;
             newCase.CachePath = cacheDir;
             
             // Detect nested single directory
             string[] subDirs = Directory.GetDirectories(cacheDir);
             string[] rootFiles = Directory.GetFiles(cacheDir);
             if (rootFiles.Length == 0 && subDirs.Length == 1)
             {
                 newCase.ExtractPath = subDirs[0];
             }
             else
             {
                 newCase.ExtractPath = cacheDir;
             }
             
             string sysInfoPath = Path.Combine(newCase.ExtractPath, ArtifactNames.SystemInfoTxt);
             if (File.Exists(sysInfoPath) && new FileInfo(sysInfoPath).Length <= 5L * 1024 * 1024)
             {
                 string[] lines = File.ReadAllLines(sysInfoPath, System.Text.Encoding.UTF8);
                 foreach(var line in lines)
                 {
                     if (line.StartsWith("Hostname:")) newCase.Hostname = line.Substring(9).Trim();
                 }
             }
             if (string.IsNullOrEmpty(newCase.Hostname)) newCase.Hostname = Path.GetFileNameWithoutExtension(zipPath);

                          // 3. Scan extracted files once for MFT/artifacts (reduces repeated full-tree walks)
             int mftMax = GetMftMaxEntries();
              string mftBinPath = null;
              string mftPreviewPath = null;
              string factStoreDbPath = null;
              foreach (string f in Directory.EnumerateFiles(cacheDir, "*", SearchOption.AllDirectories))
              {
                 string fullPath = Path.GetFullPath(f);
                 if (!IsPathUnderRoot(fullPath, cacheDir)) continue;

                 string name = Path.GetFileName(f);
                 if (mftBinPath == null && string.Equals(name, ArtifactNames.MftDumpBin, StringComparison.OrdinalIgnoreCase))
                 {
                     mftBinPath = fullPath;
                     continue;
                 }
                  if (mftPreviewPath == null && string.Equals(name, ArtifactNames.MftPreviewCsv, StringComparison.OrdinalIgnoreCase))
                  {
                      mftPreviewPath = fullPath;
                      continue;
                  }
                  if (factStoreDbPath == null && string.Equals(name, ArtifactNames.FactStoreDb, StringComparison.OrdinalIgnoreCase))
                  {
                      factStoreDbPath = fullPath;
                  }
                  if (string.Equals(name, ArtifactNames.SystemInfoTxt, StringComparison.OrdinalIgnoreCase)) continue;

                  string ext = Path.GetExtension(f).ToLowerInvariant();
                  if (ext == ".csv" || ext == ".txt" || ext == ".evtx" || ext == ".xml" || ext == ".sqlite" || ext == ".hve" || ext == ".log" || ext == ".jrs" || name.Contains("History") ||
                      ext == ".automaticdestinations-ms" || ext == ".customdestinations-ms" ||
                       ext == ".hiv" || ext == ".dat" || ext == ".reg" || name.StartsWith("NTUSER") || name.StartsWith("UsrClass") ||
                       ext == ".raw" || ext == ".dmp" ||
                       string.Equals(name, ArtifactNames.FactStoreDb, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(name, ArtifactNames.CollectionCoverageJson, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(name, ArtifactNames.MemoryAcquisitionJson, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(name, ArtifactNames.MemoryAnalysisJson, StringComparison.OrdinalIgnoreCase))
                   {
                       string rel = GetRelativePath(cacheDir, fullPath);
                       if (rel != null && rel.IndexOf("..", StringComparison.Ordinal) < 0)
                           newCase.Artifacts[rel] = fullPath;
                   }
                  else
                  {
                      string rel = GetRelativePath(cacheDir, fullPath);
                      if (!string.IsNullOrEmpty(rel) &&
                          rel.StartsWith(ArtifactNames.MemoryAnalysisFolder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                          rel.IndexOf("..", StringComparison.Ordinal) < 0)
                      {
                          newCase.Artifacts[rel] = fullPath;
                      }
                  }
              }

              string coverageReportPath = ResolveArtifactPath(newCase, ArtifactNames.CollectionCoverageJson);
              if (!string.IsNullOrEmpty(coverageReportPath) && File.Exists(coverageReportPath))
              {
                  try
                  {
                      newCase.CollectionCoverage = CollectionCoverageSerializer.LoadFromFile(coverageReportPath);
                  }
                  catch (Exception ex)
                  {
                      Logger.Warning("LoadCase collection_coverage.json: " + (ex.Message ?? ""));
                      AddLoadWarning(newCase, "collection_coverage.json could not be loaded: " + (ex.Message ?? ""));
                  }
              }

              string memoryAcqPath = ResolveArtifactPath(newCase, ArtifactNames.MemoryAcquisitionJson);
              if (!string.IsNullOrEmpty(memoryAcqPath) && File.Exists(memoryAcqPath))
              {
                  try
                  {
                      newCase.MemoryAcquisitionMeta = MemoryAcquisitionRecord.TryLoad(memoryAcqPath);
                      if (newCase.MemoryAcquisitionMeta == null)
                          AddLoadWarning(newCase, "memory_acquisition.json could not be parsed.");
                  }
                  catch (Exception ex)
                  {
                      Logger.Warning("LoadCase memory_acquisition.json: " + (ex.Message ?? ""));
                      AddLoadWarning(newCase, "memory_acquisition.json could not be loaded: " + (ex.Message ?? ""));
                  }
              }

              string memoryAnalysisPath = ResolveArtifactPath(newCase, ArtifactNames.MemoryAnalysisJson);
              if (!string.IsNullOrEmpty(memoryAnalysisPath) && File.Exists(memoryAnalysisPath))
              {
                  try
                  {
                      newCase.MemoryAnalysisMeta = MemoryAnalysisRecord.TryLoad(memoryAnalysisPath);
                      if (newCase.MemoryAnalysisMeta == null)
                          AddLoadWarning(newCase, "memory_analysis.json could not be parsed.");
                  }
                  catch (Exception ex)
                  {
                      Logger.Warning("LoadCase memory_analysis.json: " + (ex.Message ?? ""));
                      AddLoadWarning(newCase, "memory_analysis.json could not be loaded: " + (ex.Message ?? ""));
                  }
              }

              try
              {
                  newCase.AnalystWorkflowPath = AnalystWorkflowStore.ResolvePath(newCase.SourceZip, newCase.ExtractPath);
                  newCase.AnalystWorkflow = AnalystWorkflowStore.LoadFromFile(newCase.AnalystWorkflowPath);
              }
              catch (Exception ex)
              {
                  Logger.Warning("LoadCase analyst workflow: " + (ex.Message ?? ""));
                  AddLoadWarning(newCase, "analyst workflow sidecar could not be loaded: " + (ex.Message ?? ""));
                  newCase.AnalystWorkflow = new AnalystWorkflowState();
              }

              TryRebuildFilteredEventLogsFromEvtx(newCase);

              try
              {
                  string shellMsg;
                  ShellBagsParser.TryEnsureShellBagsCsv(newCase.ExtractPath, false, out shellMsg);
                  string shellCsv = Path.Combine(newCase.ExtractPath, "Registry", ArtifactNames.ShellBagsCsv);
                  if (File.Exists(shellCsv))
                      RegisterArtifact(newCase, Path.GetFullPath(shellCsv));
              }
              catch (Exception ex)
              {
                  Logger.Warning("LoadCase shellbags.csv: " + (ex.Message ?? ""));
              }

              bool hasBrowserSqliteArtifacts = newCase.Artifacts.Keys.Any(k => ArtifactNames.IsBrowserHistoryMainArtifact(Path.GetFileName(k)));
              bool hasFilteredEventLogs = newCase.Artifacts.Keys.Any(k => k.EndsWith(ArtifactNames.EventLogFilteredSuffix, StringComparison.OrdinalIgnoreCase));
              bool hasEvtxEventLogs = newCase.Artifacts.Keys.Any(k => k.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase));
              if (!FactStorePersistence.HasSqliteSupport() && hasBrowserSqliteArtifacts)
                  newCase.LoadWarnings.Add("Browser history SQLite artifacts were collected, but System.Data.SQLite.dll is unavailable; in-app browser parsing is limited.");
              if (hasEvtxEventLogs && !hasFilteredEventLogs)
                  AddLoadWarning(newCase, MissingFilteredEventLogWarning);
              else if (!hasEvtxEventLogs && hasFilteredEventLogs)
                  AddLoadWarning(newCase, MissingOriginalEventLogWarning);
              // 4. Load MFT Data (with configurable limit for memory safety)
              if (!string.IsNullOrEmpty(mftBinPath))
              {
                  var parseResult = IR_Collect.MFT.MftParser.ParseWithDiagnostics(mftBinPath, mftMax);
                  newCase.MftEntries = parseResult.Entries;
                  if (parseResult.SkippedRecords > 0)
                      newCase.LoadWarnings.Add("MFT parse skipped " + parseResult.SkippedRecords + " malformed record(s).");
                  if (newCase.MftEntries.Count >= mftMax)
                  {
                      newCase.LoadWarnings.Add("MFT load was capped at " + mftMax + " entries. Increase config.ini MftMaxEntries to load more.");
                      Logger.Info("MFT loaded (capped at " + mftMax + "). Set config.ini MftMaxEntries to load more.");
                  }
              }
              else if (!string.IsNullOrEmpty(mftPreviewPath))
              {
                  LoadMftFromPreviewCsv(newCase, mftPreviewPath, mftMax);
              }

               if (!string.IsNullOrEmpty(factStoreDbPath) && File.Exists(factStoreDbPath))
               {
                   try
                   {
                       int skippedFactRows;
                       newCase.FactStore = FactStorePersistence.LoadFromSqlite(factStoreDbPath, newCase.CaseID, newCase.Hostname, out skippedFactRows);
                       if (skippedFactRows > 0)
                           AddLoadWarning(newCase, "fact_store.db: " + skippedFactRows + " unreadable fact row(s) were skipped. Rebuild Fact Store to refresh the cache.");
                       AugmentFactStoreWithRebuiltEventLogs(newCase);
                       FactProvenanceHelper.ApplyCaseMetadata(newCase, newCase.FactStore != null ? newCase.FactStore.Facts : null);
                       if (newCase.FactStore != null)
                           newCase.FactStore.BuildEntityIndex();
                       EvaluateFactStoreFreshness(newCase, factStoreDbPath, mftBinPath, mftPreviewPath);
                   }
                   catch (Exception ex)
                   {
                       Logger.Warning("LoadCase fact_store.db: " + (ex.Message ?? ""));
                       newCase.LoadWarnings.Add("fact_store.db could not be loaded: " + (ex.Message ?? ""));
                       newCase.FactStoreFreshnessStatus = "load_failed";
                       newCase.FactStoreFreshnessDetail = "fact_store.db exists but could not be loaded.";
                   }
               }
              else
              {
                  newCase.FactStoreFreshnessStatus = "not_present";
                  newCase.FactStoreFreshnessDetail = "fact_store.db is not present in this case.";
              }

              lock (_lock) { _cases.Add(newCase); }
              return newCase;
         }

        // Parse mft_preview.csv (the bounded CSV written during collection) into MftEntries. Shared by
        // LoadCase (ZIP intake) and LoadCaseFromFolder (folder intake).
        private static void LoadMftFromPreviewCsv(CaseData newCase, string mftPreviewPath, int mftMax)
        {
            using (StreamReader sr = new StreamReader(mftPreviewPath, System.Text.Encoding.UTF8))
            {
                string line;
                bool header = true;
                int csvCount = 0;
                while ((line = sr.ReadLine()) != null && csvCount < mftMax)
                {
                    if (header) { header = false; continue; }
                    try
                    {
                        var parts = CorrelationCsvHelper.SplitCsvLine(line);
                        if (parts.Length >= 14)
                        {
                            var entry = new IR_Collect.MFT.MftParser.MftEntry();
                            entry.FileName = parts[3];
                            entry.FullPath = parts[4];
                            long size;
                            if (long.TryParse(parts[5], out size)) entry.Size = size;
                            DateTime dt;
                            if (DateTime.TryParse(parts[6], out dt)) entry.StdCreated = dt;
                            if (DateTime.TryParse(parts[7], out dt)) entry.StdModified = dt;
                            if (DateTime.TryParse(parts[8], out dt)) entry.StdMftModified = dt;
                            if (DateTime.TryParse(parts[9], out dt)) entry.StdAccessed = dt;
                            if (DateTime.TryParse(parts[10], out dt)) entry.FnCreated = dt;
                            if (DateTime.TryParse(parts[11], out dt)) entry.FnModified = dt;
                            if (DateTime.TryParse(parts[12], out dt)) entry.FnMftModified = dt;
                            if (DateTime.TryParse(parts[13], out dt)) entry.FnAccessed = dt;
                            entry.Created = entry.StdCreated.Year > 1980 ? entry.StdCreated : entry.FnCreated;
                            entry.Modified = entry.StdModified.Year > 1980 ? entry.StdModified : entry.FnModified;
                            newCase.MftEntries.Add(entry);
                            csvCount++;
                        }
                        else if (parts.Length >= 5)
                        {
                            var entry = new IR_Collect.MFT.MftParser.MftEntry();
                            entry.FileName = parts[3];
                            DateTime dt;
                            if (DateTime.TryParse(parts[4], out dt)) entry.Created = dt;
                            newCase.MftEntries.Add(entry);
                            csvCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning("MFT preview CSV parse: " + (ex.Message ?? ""));
                    }
                }
                if (csvCount >= mftMax)
                {
                    newCase.LoadWarnings.Add("MFT preview load was capped at " + mftMax + " entries. Increase config.ini MftMaxEntries to load more.");
                    Logger.Info("MFT CSV loaded (capped at " + mftMax + "). Set config.ini MftMaxEntries to load more.");
                }
            }
        }

        /// <summary>
        /// Phase 3.1 (analysis layer): build a CaseData from an arbitrary folder of already-collected
        /// artifacts - another tool's triage output, or an unzipped IR_Collect case - WITHOUT extracting a
        /// ZIP and WITHOUT touching the live host. Mirrors the post-extraction steps of LoadCase (the two
        /// should be unified in a later pass). The folder is treated read-only: it is never deleted, only
        /// derived CSVs (filtered EVTX / ShellBags) may be written alongside, exactly as LoadCase does.
        /// </summary>
        public static CaseData LoadCaseFromFolder(string folder)
        {
            if (string.IsNullOrWhiteSpace(folder))
                throw new ArgumentException("folder is null or empty.", "folder");
            if (!Directory.Exists(folder))
                throw new DirectoryNotFoundException("Artifact folder not found: " + folder);
            string root;
            try { root = Path.GetFullPath(folder); } catch { root = folder; }

            string leaf = new DirectoryInfo(root).Name;
            CaseData newCase = new CaseData();
            newCase.CaseID = "Folder_" + leaf + "_" + DateTime.Now.Ticks;
            newCase.SourceZip = null;
            newCase.CachePath = root;

            // Detect a single nested directory (e.g. folder\IR_Output_X\...).
            string[] subDirs = Directory.GetDirectories(root);
            string[] rootFiles = Directory.GetFiles(root);
            newCase.ExtractPath = (rootFiles.Length == 0 && subDirs.Length == 1) ? subDirs[0] : root;

            string sysInfoPath = Path.Combine(newCase.ExtractPath, ArtifactNames.SystemInfoTxt);
            if (File.Exists(sysInfoPath) && new FileInfo(sysInfoPath).Length <= 5L * 1024 * 1024)
            {
                foreach (var line in File.ReadAllLines(sysInfoPath, System.Text.Encoding.UTF8))
                    if (line.StartsWith("Hostname:")) newCase.Hostname = line.Substring(9).Trim();
            }
            if (string.IsNullOrEmpty(newCase.Hostname)) newCase.Hostname = leaf;

            // Phase 5.2: hash the input files AS RECEIVED (before we derive any CSVs) so an analysis
            // report can be cryptographically tied to exactly the evidence it consumed.
            try
            {
                EvidenceManifestResult em = EvidenceManifest.HashFolder(newCase.ExtractPath);
                newCase.EvidenceFiles = em.Files;
                newCase.EvidenceDigest = em.Digest;
            }
            catch (Exception ex) { Logger.Warning("LoadCaseFromFolder evidence hash: " + (ex.Message ?? "")); }

            // Phase 3.1b: derive Amcache/ShimCache/SRUM CSVs from any RAW hive/ESE files present, so the
            // scan below registers them and the normalizers produce facts (foreign triage folders ship raw
            // artifacts, not our CSVs). Best-effort; writes nothing for artifacts that need elevation.
            try { RawArtifactCsvDeriver.DeriveInto(newCase.ExtractPath, newCase.LoadWarnings); }
            catch (Exception ex) { Logger.Warning("LoadCaseFromFolder derive: " + (ex.Message ?? "")); }

            int mftMax = GetMftMaxEntries();
            string mftBinPath = null, mftPreviewPath = null, factStoreDbPath = null;
            foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                string fullPath;
                try { fullPath = Path.GetFullPath(f); } catch { continue; }
                if (!IsPathUnderRoot(fullPath, root)) continue;
                string name = Path.GetFileName(f);
                if (mftBinPath == null && string.Equals(name, ArtifactNames.MftDumpBin, StringComparison.OrdinalIgnoreCase)) { mftBinPath = fullPath; continue; }
                if (mftPreviewPath == null && string.Equals(name, ArtifactNames.MftPreviewCsv, StringComparison.OrdinalIgnoreCase)) { mftPreviewPath = fullPath; continue; }
                if (factStoreDbPath == null && string.Equals(name, ArtifactNames.FactStoreDb, StringComparison.OrdinalIgnoreCase)) factStoreDbPath = fullPath;
                if (string.Equals(name, ArtifactNames.SystemInfoTxt, StringComparison.OrdinalIgnoreCase)) continue;

                string ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext == ".csv" || ext == ".txt" || ext == ".evtx" || ext == ".xml" || ext == ".sqlite" || ext == ".hve" || ext == ".log" || ext == ".jrs" || name.Contains("History") ||
                    ext == ".automaticdestinations-ms" || ext == ".customdestinations-ms" ||
                    ext == ".hiv" || ext == ".dat" || ext == ".reg" || name.StartsWith("NTUSER") || name.StartsWith("UsrClass") ||
                    ext == ".raw" || ext == ".dmp" ||
                    string.Equals(name, ArtifactNames.FactStoreDb, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(name, ArtifactNames.CollectionCoverageJson, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(name, ArtifactNames.MemoryAcquisitionJson, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(name, ArtifactNames.MemoryAnalysisJson, StringComparison.OrdinalIgnoreCase))
                {
                    string rel = GetRelativePath(root, fullPath);
                    if (rel != null && rel.IndexOf("..", StringComparison.Ordinal) < 0)
                        newCase.Artifacts[rel] = fullPath;
                }
            }

            // Optional sidecars (best-effort, same as LoadCase).
            string coveragePath = ResolveArtifactPath(newCase, ArtifactNames.CollectionCoverageJson);
            if (!string.IsNullOrEmpty(coveragePath) && File.Exists(coveragePath))
            {
                try { newCase.CollectionCoverage = CollectionCoverageSerializer.LoadFromFile(coveragePath); }
                catch (Exception ex) { AddLoadWarning(newCase, "collection_coverage.json could not be loaded: " + (ex.Message ?? "")); }
            }
            string memAcq = ResolveArtifactPath(newCase, ArtifactNames.MemoryAcquisitionJson);
            if (!string.IsNullOrEmpty(memAcq) && File.Exists(memAcq))
            {
                try { newCase.MemoryAcquisitionMeta = MemoryAcquisitionRecord.TryLoad(memAcq); } catch { }
            }
            string memAna = ResolveArtifactPath(newCase, ArtifactNames.MemoryAnalysisJson);
            if (!string.IsNullOrEmpty(memAna) && File.Exists(memAna))
            {
                try { newCase.MemoryAnalysisMeta = MemoryAnalysisRecord.TryLoad(memAna); } catch { }
            }

            try
            {
                newCase.AnalystWorkflowPath = AnalystWorkflowStore.ResolvePath(newCase.SourceZip, newCase.ExtractPath);
                newCase.AnalystWorkflow = AnalystWorkflowStore.LoadFromFile(newCase.AnalystWorkflowPath);
            }
            catch (Exception ex)
            {
                Logger.Warning("LoadCaseFromFolder analyst workflow: " + (ex.Message ?? ""));
                newCase.AnalystWorkflow = new AnalystWorkflowState();
            }

            TryRebuildFilteredEventLogsFromEvtx(newCase);

            try
            {
                string shellMsg;
                ShellBagsParser.TryEnsureShellBagsCsv(newCase.ExtractPath, false, out shellMsg);
                string shellCsv = Path.Combine(newCase.ExtractPath, "Registry", ArtifactNames.ShellBagsCsv);
                if (File.Exists(shellCsv)) RegisterArtifact(newCase, Path.GetFullPath(shellCsv));
            }
            catch (Exception ex) { Logger.Warning("LoadCaseFromFolder shellbags.csv: " + (ex.Message ?? "")); }

            if (!string.IsNullOrEmpty(mftBinPath))
            {
                var pr = IR_Collect.MFT.MftParser.ParseWithDiagnostics(mftBinPath, mftMax);
                newCase.MftEntries = pr.Entries;
                if (pr.SkippedRecords > 0) newCase.LoadWarnings.Add("MFT parse skipped " + pr.SkippedRecords + " malformed record(s).");
            }
            else if (!string.IsNullOrEmpty(mftPreviewPath))
            {
                LoadMftFromPreviewCsv(newCase, mftPreviewPath, mftMax);
            }

            if (!string.IsNullOrEmpty(factStoreDbPath) && File.Exists(factStoreDbPath))
            {
                try
                {
                    int skipped;
                    newCase.FactStore = FactStorePersistence.LoadFromSqlite(factStoreDbPath, newCase.CaseID, newCase.Hostname, out skipped);
                    AugmentFactStoreWithRebuiltEventLogs(newCase);
                    FactProvenanceHelper.ApplyCaseMetadata(newCase, newCase.FactStore != null ? newCase.FactStore.Facts : null);
                    if (newCase.FactStore != null) newCase.FactStore.BuildEntityIndex();
                }
                catch (Exception ex) { AddLoadWarning(newCase, "fact_store.db could not be loaded: " + (ex.Message ?? "")); }
            }

            lock (_lock) { _cases.Add(newCase); }
            return newCase;
        }

        private static void TryRebuildFilteredEventLogsFromEvtx(CaseData c)
        {
            if (c == null || c.Artifacts == null || string.IsNullOrEmpty(c.ExtractPath) || !Directory.Exists(c.ExtractPath))
                return;

            RebuildFilteredEventLogs(c, false);
        }

        public static EventLogRebuildResult RebuildFilteredEventLogs(CaseData c, bool overwriteExisting)
        {
            var result = new EventLogRebuildResult();
            if (c == null || c.Artifacts == null || string.IsNullOrEmpty(c.ExtractPath) || !Directory.Exists(c.ExtractPath))
            {
                result.Detail = "Case data is unavailable.";
                return result;
            }

            var evtxFiles = ResolveEvtxEventLogArtifacts(c);
            result.TotalLogs = evtxFiles.Count;
            result.EffectiveDaysBack = EventLogFilteredCsvExporter.NormalizeConfiguredDaysBack(EventLogFilteredCsvExporter.GetConfiguredDaysBack());
            result.MaxEventsPerLog = EventLogFilteredCsvExporter.GetConfiguredMaxEvents();

            if (evtxFiles.Count == 0)
            {
                result.Detail = "No EVTX artifacts are available for this host.";
                return result;
            }

            foreach (var kvp in evtxFiles)
            {
                string logLabel = kvp.Key;
                string evtxPath = kvp.Value;
                string csvPath = Path.Combine(Path.GetDirectoryName(evtxPath) ?? c.ExtractPath, logLabel + ArtifactNames.EventLogFilteredSuffix);

                if (!overwriteExisting && File.Exists(csvPath) && new FileInfo(csvPath).Length > 0)
                {
                    RegisterArtifact(c, csvPath);
                    result.SkippedLogs++;
                    continue;
                }

                int count;
                string windowDescription;
                string error;
                if (EventLogFilteredCsvExporter.TryExportFromEvtxFile(evtxPath, csvPath, result.EffectiveDaysBack, result.MaxEventsPerLog, out count, out windowDescription, out error))
                {
                    RegisterArtifact(c, csvPath);
                    if (!c.RebuiltEventLogLabels.Any(x => string.Equals(x, logLabel, StringComparison.OrdinalIgnoreCase)))
                        c.RebuiltEventLogLabels.Add(logLabel);
                    result.RebuiltLogs++;
                    result.RebuiltLabels.Add(logLabel);
                    Logger.Info("EventLog filtered CSV rebuild " + logLabel + ": " + count + " events (" + (windowDescription ?? "") + ").");
                }
                else
                {
                    result.FailedLogs++;
                    result.FailedLabels.Add(logLabel);
                    Logger.Warning("EventLog filtered CSV rebuild " + logLabel + " failed: " + (error ?? "unknown error"));
                }
            }

            if (result.RebuiltLogs > 0)
                RemoveLoadWarning(c, MissingFilteredEventLogWarning);

            RemoveLoadWarningsWithPrefix(c, OfflineEventLogRebuildWarningPrefix);
            if (result.FailedLogs > 0)
                AddLoadWarning(c, OfflineEventLogWarning(result.RebuiltLogs, evtxFiles.Count));

            result.Detail = overwriteExisting
                ? "Filtered CSVs were rebuilt using the current EventLogDays/EventLogMaxEvents settings."
                : "Missing filtered CSVs were rebuilt when possible.";
            return result;
        }

        public static void RefreshFactStoreFreshness(CaseData c)
        {
            if (c == null)
                return;

            string factStoreDbPath = ResolveArtifactPath(c, ArtifactNames.FactStoreDb);
            string mftBinPath = ResolveArtifactPath(c, ArtifactNames.MftDumpBin);
            string mftPreviewPath = ResolveArtifactPath(c, ArtifactNames.MftPreviewCsv);
            EvaluateFactStoreFreshness(c, factStoreDbPath, mftBinPath, mftPreviewPath);
        }

        private static Dictionary<string, string> ResolveEvtxEventLogArtifacts(CaseData c)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (c == null || c.Artifacts == null)
                return result;

            foreach (var kvp in c.Artifacts)
            {
                if (string.IsNullOrEmpty(kvp.Key) || string.IsNullOrEmpty(kvp.Value))
                    continue;
                if (!kvp.Key.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase) || !File.Exists(kvp.Value))
                    continue;
                if (kvp.Key.IndexOf("EventLogs", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                string logLabel = Path.GetFileNameWithoutExtension(kvp.Value);
                if (string.IsNullOrEmpty(logLabel))
                    continue;

                result[logLabel] = kvp.Value;
            }

            return result;
        }

        private static void RegisterArtifact(CaseData c, string fullPath)
        {
            if (c == null || c.Artifacts == null || string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
                return;

            string relativeRoot = !string.IsNullOrEmpty(c.CachePath) ? c.CachePath : c.ExtractPath;
            string rel = GetRelativePath(relativeRoot, fullPath);
            if (string.IsNullOrEmpty(rel) || rel.IndexOf("..", StringComparison.Ordinal) >= 0)
                return;

            c.Artifacts[rel] = fullPath;
        }

        private static void AddLoadWarning(CaseData c, string message)
        {
            if (c == null || string.IsNullOrWhiteSpace(message))
                return;

            if (!c.LoadWarnings.Any(x => string.Equals(x, message, StringComparison.OrdinalIgnoreCase)))
                c.LoadWarnings.Add(message);
        }

        private static void RemoveLoadWarning(CaseData c, string message)
        {
            if (c == null || c.LoadWarnings == null || string.IsNullOrWhiteSpace(message))
                return;

            c.LoadWarnings.RemoveAll(x => string.Equals(x, message, StringComparison.OrdinalIgnoreCase));
        }

        private static void RemoveLoadWarningsWithPrefix(CaseData c, string prefix)
        {
            if (c == null || c.LoadWarnings == null || string.IsNullOrWhiteSpace(prefix))
                return;

            c.LoadWarnings.RemoveAll(x => !string.IsNullOrEmpty(x) && x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        private static void EvaluateFactStoreFreshness(CaseData c, string factStoreDbPath, string mftBinPath, string mftPreviewPath)
        {
            if (c == null)
                return;
            if (string.IsNullOrEmpty(factStoreDbPath) || !File.Exists(factStoreDbPath))
            {
                c.FactStoreFreshnessStatus = "not_present";
                c.FactStoreFreshnessDetail = "fact_store.db is not present in this case.";
                return;
            }

            DateTime dbWriteUtc;
            try
            {
                dbWriteUtc = File.GetLastWriteTimeUtc(factStoreDbPath);
            }
            catch (Exception ex)
            {
                Logger.Warning("EvaluateFactStoreFreshness GetLastWriteTimeUtc: " + ex.Message);
                c.FactStoreFreshnessStatus = "unknown";
                c.FactStoreFreshnessDetail = "fact_store.db freshness could not be determined.";
                return;
            }

            var newerArtifacts = new List<string>();
            foreach (string sourcePath in EnumerateFactStoreSourcePaths(c, mftBinPath, mftPreviewPath))
            {
                if (string.IsNullOrEmpty(sourcePath) || !File.Exists(sourcePath)) continue;
                try
                {
                    if (File.GetLastWriteTimeUtc(sourcePath) > dbWriteUtc.AddSeconds(1))
                        newerArtifacts.Add(GetRelativePath(c.CachePath ?? c.ExtractPath ?? "", sourcePath));
                }
                catch (Exception ex)
                {
                    Logger.Warning("EvaluateFactStoreFreshness source " + sourcePath + ": " + ex.Message);
                }
            }

            if (newerArtifacts.Count == 0)
            {
                c.FactStoreFreshnessStatus = "current";
                c.FactStoreFreshnessDetail = "fact_store.db is not older than the currently loaded source artifacts.";
                return;
            }

            c.FactStoreFreshnessStatus = "stale";
            string sample = string.Join(", ", newerArtifacts.Take(4).ToArray());
            if (newerArtifacts.Count > 4)
                sample += " +" + (newerArtifacts.Count - 4).ToString() + " more";
            c.FactStoreFreshnessDetail = "fact_store.db is older than newer source artifacts: " + sample + ".";

            string warning = "fact_store.db appears stale relative to newer source artifacts. Rebuild Fact Store to refresh cached facts.";
            if (c.RebuiltEventLogLabels != null && c.RebuiltEventLogLabels.Count > 0)
                warning += " Rebuilt EventLog CSVs were applied in memory, but the on-disk SQLite cache is still older.";
            AddLoadWarning(c, warning);
        }

        private static string OfflineEventLogWarning(int rebuilt, int total)
        {
            return OfflineEventLogRebuildWarningPrefix + " " + rebuilt + "/" + total + " logs rebuilt from EVTX. Event-derived analysis remains limited for the remaining logs.";
        }

        private static IEnumerable<string> EnumerateFactStoreSourcePaths(CaseData c, string mftBinPath, string mftPreviewPath)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in new string[]
            {
                ResolveArtifactPath(c, ArtifactNames.ProcessListCsv),
                ResolveArtifactPath(c, ArtifactNames.LogonSessionsCsv),
                ResolveArtifactPath(c, ArtifactNames.NetworkResourcesCsv),
                ResolveArtifactPath(c, ArtifactNames.ServerConnectionsCsv),
                ResolveArtifactPath(c, ArtifactNames.StoredCredentialsTxt),
                ResolveArtifactPath(c, ArtifactNames.KerberosTicketsTxt),
                ResolveArtifactPath(c, ArtifactNames.MemoryAcquisitionJson),
                ResolveArtifactPath(c, ArtifactNames.MemoryAnalysisJson),
                ResolveArtifactPath(c, ArtifactNames.AutorunsRegistryCsv),
                ResolveArtifactPath(c, ArtifactNames.ServicesCsv),
                ResolveArtifactPath(c, ArtifactNames.ActivityTimelineCsv),
                ResolveArtifactPath(c, ArtifactNames.BamDamCsv),
                ResolveArtifactPath(c, ArtifactNames.BitsJobsCsv),
                ResolveArtifactPath(c, ArtifactNames.JumpListsCsv),
                ResolveArtifactPath(c, ArtifactNames.WmiPersistenceCsv),
                ResolveArtifactPath(c, ArtifactNames.AmcacheProgramsCsv),
                ResolveArtifactPath(c, ArtifactNames.AmcacheFilesCsv),
                ResolveArtifactPath(c, ArtifactNames.ShimCacheEntriesCsv),
                ResolveArtifactPath(c, ArtifactNames.SrumNetworkUsageCsv),
                ResolveArtifactPath(c, ArtifactNames.SrumAppUsageCsv),
                ResolveArtifactPath(c, ArtifactNames.ScheduledTasksXml),
                ResolveArtifactPath(c, ArtifactNames.UsnJournalCsv),
                ResolveArtifactPath(c, ArtifactNames.ShellBagsCsv),
                !string.IsNullOrEmpty(mftBinPath) ? mftBinPath : ResolveArtifactPath(c, ArtifactNames.MftDumpBin),
                !string.IsNullOrEmpty(mftPreviewPath) ? mftPreviewPath : ResolveArtifactPath(c, ArtifactNames.MftPreviewCsv)
            })
            {
                if (string.IsNullOrEmpty(path) || !seen.Add(path)) continue;
                yield return path;
            }

            if (c != null && c.Artifacts != null)
            {
                foreach (var kvp in c.Artifacts)
                {
                    if (!ArtifactNames.IsEventLogFilteredCsv(kvp.Key)) continue;
                    if (string.IsNullOrEmpty(kvp.Value) || !seen.Add(kvp.Value)) continue;
                    yield return kvp.Value;
                }
            }
        }

        private static void AugmentFactStoreWithRebuiltEventLogs(CaseData c)
        {
            if (c == null || c.FactStore == null || c.RebuiltEventLogLabels == null || c.RebuiltEventLogLabels.Count == 0)
                return;

            var existingSources = new HashSet<string>(
                c.FactStore.Facts.Where(f => !string.IsNullOrEmpty(f.Source)).Select(f => f.Source),
                StringComparer.OrdinalIgnoreCase);

            var augmentedFacts = new List<IR_Collect.Analysis.Correlation.Fact>();
            bool addedAny = false;
            foreach (string logLabel in c.RebuiltEventLogLabels.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string sourceName = IR_Collect.Analysis.Correlation.Normalizers.EventLogNormalizer.SourcePrefix + ":" + logLabel;
                if (existingSources.Contains(sourceName))
                    continue;

                string csvPath = ResolveRebuiltEventLogCsvPath(c, logLabel);
                if (string.IsNullOrEmpty(csvPath) || !File.Exists(csvPath))
                    continue;

                var facts = IR_Collect.Analysis.Correlation.Normalizers.EventLogNormalizer.ToFacts(csvPath, logLabel);
                if (facts.Count <= 0)
                    continue;

                augmentedFacts.AddRange(facts);
                existingSources.Add(sourceName);
                addedAny = true;
            }

            if (addedAny)
            {
                // Thread-safe append: builds new Facts/EntityIndex and swaps them atomically, so a
                // concurrent UI/correlation reader never sees a half-mutated store.
                c.FactStore.AppendFacts(augmentedFacts);
                Logger.Info("LoadCase augmented fact_store.db with rebuilt EventLog facts for " + c.RebuiltEventLogLabels.Count + " log(s).");
            }
        }

        private static string ResolveRebuiltEventLogCsvPath(CaseData c, string logLabel)
        {
            if (c == null || string.IsNullOrWhiteSpace(logLabel))
                return null;

            string targetFile = logLabel + ArtifactNames.EventLogFilteredSuffix;
            if (c.Artifacts != null)
            {
                foreach (var kvp in c.Artifacts)
                {
                    if (string.IsNullOrEmpty(kvp.Key) || string.IsNullOrEmpty(kvp.Value))
                        continue;
                    if (!string.Equals(Path.GetFileName(kvp.Value), targetFile, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (File.Exists(kvp.Value))
                        return kvp.Value;
                }
            }

            string eventLogsDir = Path.Combine(c.ExtractPath ?? "", "EventLogs");
            string candidate = Path.Combine(eventLogsDir, targetFile);
            return File.Exists(candidate) ? candidate : null;
        }

        public static Dictionary<string, List<string>> FindCommonFiles()
        {
            // Find files that exist on > 1 host
            // Returns FileName -> List of Hostnames
            
            Dictionary<string, List<string>> fileMap = new Dictionary<string, List<string>>();
            List<CaseData> snapshot;
            lock (_lock) { snapshot = new List<CaseData>(_cases); }
            
            foreach(var c in snapshot)
            {
                if (c.MftEntries == null) continue;
                // Distinct filenames per host to avoid duplicates
                var uniqueFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach(var e in c.MftEntries)
                {
                    if (!string.IsNullOrEmpty(e.FileName)) uniqueFiles.Add(e.FileName);
                }

                string hostName = c.Hostname ?? "host";
                foreach(var f in uniqueFiles)
                {
                    if (!fileMap.ContainsKey(f)) fileMap[f] = new List<string>();
                    fileMap[f].Add(hostName);
                }
            }

            // Filter only files appearing in > 1 case
            var result = new Dictionary<string, List<string>>();
            foreach(var kvp in fileMap)
            {
                if (kvp.Value.Count > 1)
                {
                    result[kvp.Key] = kvp.Value;
                }
            }
            return result;
        }

        /// <summary>移除單一案件並刪除其 Temp 解壓目錄（若在 %TEMP% 下）。</summary>
        public static bool RemoveCase(CaseData c)
        {
            if (c == null) return true;
            try
            {
                DeleteTempCaseDirectory(c);
                lock (_lock) { _cases.Remove(c); }
                return true;
            }
            catch (Exception ex)
            {
                Logger.Warning("RemoveCase cleanup failed: " + ex.Message);
                return false;
            }
        }

        public static int CleanupAll()
        {
            List<CaseData> snapshot;
            lock (_lock) { snapshot = new List<CaseData>(_cases); }
            int failedDeletes = 0;

            foreach(var c in snapshot)
            {
                try 
                {
                    DeleteTempCaseDirectory(c);
                }
                catch (Exception ex)
                {
                    failedDeletes++;
                    Logger.Warning("Cleanup extract path: " + (c.ExtractPath ?? "") + " - " + ex.Message);
                }
            }
            lock (_lock) { _cases.Clear(); }
            return failedDeletes;
        }

        /// <summary>Extract zip without path traversal (Zip Slip). Validates each entry stays under destDir.</summary>
        internal static void ExtractZipSafely(string zipPath, string destDir)
        {
            string destFull = Path.GetFullPath(destDir);
            if (!destFull.EndsWith(Path.DirectorySeparatorChar.ToString())) destFull += Path.DirectorySeparatorChar;
            var result = new ZipExtractionResult();
            using (var archive = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.FullName)) continue;
                    string normalizedEntry = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    if (Path.IsPathRooted(normalizedEntry))
                    {
                        result.RejectedEntries++;
                        Logger.Warning("LoadCase: skipping zip entry (rooted path): " + entry.FullName);
                        continue;
                    }
                    string[] entryParts = normalizedEntry.Split(new char[] { Path.DirectorySeparatorChar, '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
                    bool hasTraversal = false;
                    foreach (string part in entryParts)
                    {
                        if (part == "..")
                        {
                            hasTraversal = true;
                            break;
                        }
                    }
                    if (hasTraversal)
                    {
                        result.RejectedEntries++;
                        Logger.Warning("LoadCase: skipping zip entry (path traversal segment): " + entry.FullName);
                        continue;
                    }
                    string destPath = Path.Combine(destDir, normalizedEntry);
                    string destPathFull = Path.GetFullPath(destPath);
                    if (!destPathFull.StartsWith(destFull, StringComparison.OrdinalIgnoreCase))
                    {
                        result.RejectedEntries++;
                        Logger.Warning("LoadCase: skipping zip entry (path traversal): " + entry.FullName);
                        continue;
                    }
                    if (entry.FullName.EndsWith("/") || entry.FullName.EndsWith("\\"))
                    {
                        if (!Directory.Exists(destPathFull)) Directory.CreateDirectory(destPathFull);
                        continue;
                    }
                    string dir = Path.GetDirectoryName(destPathFull);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    try
                    {
                        entry.ExtractToFile(destPathFull, true);
                        result.ExtractedFiles++;
                    }
                    catch (Exception ex)
                    {
                        result.FailedEntries++;
                        Logger.Warning("Extract " + entry.FullName + ": " + ex.Message);
                    }
                }
            }
            if (result.ExtractedFiles <= 0)
            {
                throw new InvalidDataException("Case zip extraction failed: archive did not contain any file entries.");
            }
            if (result.RejectedEntries > 0 || result.FailedEntries > 0)
            {
                throw new InvalidDataException(string.Format("Case zip extraction incomplete. Extracted {0} file(s), rejected {1} entr{2}, failed {3} entr{4}.",
                    result.ExtractedFiles,
                    result.RejectedEntries,
                    result.RejectedEntries == 1 ? "y" : "ies",
                    result.FailedEntries,
                    result.FailedEntries == 1 ? "y" : "ies"));
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

        public static string ResolveArtifactPath(CaseData c, string fileName)
        {
            if (c == null || string.IsNullOrEmpty(fileName)) return null;

            try
            {
                if (c.Artifacts != null)
                {
                    string exact;
                    if (c.Artifacts.TryGetValue(fileName, out exact) && !string.IsNullOrEmpty(exact) && File.Exists(exact))
                        return exact;
                }

                if (!string.IsNullOrEmpty(c.ExtractPath))
                {
                    string candidate = Path.Combine(c.ExtractPath, fileName);
                    string full = Path.GetFullPath(candidate);
                    string baseFull = Path.GetFullPath(c.ExtractPath).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
                    if (full.StartsWith(baseFull, StringComparison.OrdinalIgnoreCase) && File.Exists(full))
                        return full;
                }

                if (c.Artifacts != null)
                {
                    foreach (var kvp in c.Artifacts)
                    {
                        string keyName = Path.GetFileName(kvp.Key ?? "");
                        string valueName = Path.GetFileName(kvp.Value ?? "");
                        if (string.Equals(keyName, fileName, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(valueName, fileName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!string.IsNullOrEmpty(kvp.Value) && File.Exists(kvp.Value))
                                return kvp.Value;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("ResolveArtifactPath: " + ex.Message);
            }

            return null;
        }

        private static void DeleteTempCaseDirectory(CaseData c)
        {
            if (c == null) return;
            string candidate = !string.IsNullOrEmpty(c.CachePath) ? c.CachePath : c.ExtractPath;
            if (string.IsNullOrEmpty(candidate) || !Directory.Exists(candidate)) return;
            string tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
            string fullCandidate = Path.GetFullPath(candidate);
            if (!fullCandidate.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase)) return;
            if (fullCandidate.Length <= tempRoot.Length + 5) return;
            Directory.Delete(fullCandidate, true);
        }

        private static void TryDeleteDirectory(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            catch (Exception ex)
            {
                Logger.Warning("TryDeleteDirectory " + (path ?? "") + ": " + ex.Message);
            }
        }
    }
}
