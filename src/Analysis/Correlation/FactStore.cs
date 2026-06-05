using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using IR_Collect.Analysis;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation
{
    /// <summary>
    /// 統一事實儲存：從單一 Case 建出所有 Fact（目前僅記憶體）+ 實體索引。
    /// </summary>
    public class FactStore
    {
        public List<Fact> Facts { get; private set; }
        /// <summary>EntityKey (e.g. "path:c:\...") → set of Facts mentioning that entity (HashSet for O(1) add/lookup).</summary>
        public Dictionary<string, HashSet<Fact>> EntityIndex { get; private set; }
        public string CaseId { get; set; }
        public string Hostname { get; set; }

        /// <summary>
        /// Serializes mutations to <see cref="Facts"/> / <see cref="EntityIndex"/>. Mutations build NEW
        /// collections and publish them by atomic reference swap (a published collection is never mutated
        /// in place), so concurrent UI/correlation readers that grabbed the previous reference keep
        /// iterating a stable snapshot and never hit "collection was modified" (InvalidOperationException).
        /// </summary>
        private readonly object _sync = new object();

        public FactStore()
        {
            Facts = new List<Fact>();
            EntityIndex = new Dictionary<string, HashSet<Fact>>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 從已載入的 Case 建立 Fact Store；不修改 Case 本身，僅讀取其 ExtractPath 與 Artifacts。
        /// </summary>
        public static FactStore BuildFromCase(CaseData c)
        {
            var store = new FactStore();
            if (c == null) return store;

            store.CaseId = c.CaseID;
            store.Hostname = c.Hostname ?? "";
            string basePath = c.ExtractPath ?? "";

            if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath))
                return store;

            // Pre-allocate to reduce list reallocations (rough estimate)
            int estimatedFacts = 20000;
            store.Facts = new List<Fact>(estimatedFacts);

            string processPath = ResolvePath(c, basePath, ArtifactNames.ProcessListCsv);
            if (!string.IsNullOrEmpty(processPath))
            {
                var processFacts = Normalizers.ProcessNormalizer.ToFacts(processPath);
                store.Facts.AddRange(processFacts);
            }

            string logonSessionsPath = ResolvePath(c, basePath, ArtifactNames.LogonSessionsCsv);
            if (!string.IsNullOrEmpty(logonSessionsPath))
            {
                var logonSessionFacts = Normalizers.LogonSessionNormalizer.ToFacts(logonSessionsPath);
                store.Facts.AddRange(logonSessionFacts);
            }

            string networkResourcesPath = ResolvePath(c, basePath, ArtifactNames.NetworkResourcesCsv);
            if (!string.IsNullOrEmpty(networkResourcesPath))
            {
                var networkResourceFacts = Normalizers.NetworkResourceNormalizer.ToFacts(networkResourcesPath);
                store.Facts.AddRange(networkResourceFacts);
            }

            string serverConnectionsPath = ResolvePath(c, basePath, ArtifactNames.ServerConnectionsCsv);
            if (!string.IsNullOrEmpty(serverConnectionsPath))
            {
                var serverConnectionFacts = Normalizers.ServerConnectionNormalizer.ToFacts(serverConnectionsPath);
                store.Facts.AddRange(serverConnectionFacts);
            }

            string storedCredentialsPath = ResolvePath(c, basePath, ArtifactNames.StoredCredentialsTxt);
            if (!string.IsNullOrEmpty(storedCredentialsPath))
            {
                var storedCredentialFacts = Normalizers.StoredCredentialNormalizer.ToFacts(storedCredentialsPath);
                store.Facts.AddRange(storedCredentialFacts);
            }

            string kerberosTicketsPath = ResolvePath(c, basePath, ArtifactNames.KerberosTicketsTxt);
            if (!string.IsNullOrEmpty(kerberosTicketsPath))
            {
                var kerberosFacts = Normalizers.KerberosTicketCacheNormalizer.ToFacts(kerberosTicketsPath);
                store.Facts.AddRange(kerberosFacts);
            }

            string memoryAcquisitionPath = ResolvePath(c, basePath, ArtifactNames.MemoryAcquisitionJson);
            if (!string.IsNullOrEmpty(memoryAcquisitionPath))
            {
                var memoryAcquisitionFacts = Normalizers.MemoryAcquisitionNormalizer.ToFacts(memoryAcquisitionPath);
                store.Facts.AddRange(memoryAcquisitionFacts);
            }

            string memoryAnalysisPath = ResolvePath(c, basePath, ArtifactNames.MemoryAnalysisJson);
            if (!string.IsNullOrEmpty(memoryAnalysisPath))
            {
                var memoryAnalysisFacts = Normalizers.MemoryAnalysisNormalizer.ToFacts(memoryAnalysisPath);
                store.Facts.AddRange(memoryAnalysisFacts);
            }

            string autorunPath = ResolvePath(c, basePath, ArtifactNames.AutorunsRegistryCsv);
            if (!string.IsNullOrEmpty(autorunPath))
            {
                var autorunFacts = Normalizers.AutorunNormalizer.ToFacts(autorunPath);
                store.Facts.AddRange(autorunFacts);
            }

            string servicesPath = ResolvePath(c, basePath, ArtifactNames.ServicesCsv);
            if (!string.IsNullOrEmpty(servicesPath))
            {
                var serviceFacts = Normalizers.ServiceNormalizer.ToFacts(servicesPath);
                store.Facts.AddRange(serviceFacts);
            }

            string activityPath = ResolvePath(c, basePath, ArtifactNames.ActivityTimelineCsv);
            if (!string.IsNullOrEmpty(activityPath))
            {
                var activityFacts = Normalizers.ActivityTimelineNormalizer.ToFacts(activityPath);
                store.Facts.AddRange(activityFacts);
            }

            string bamDamPath = ResolvePath(c, basePath, ArtifactNames.BamDamCsv);
            if (!string.IsNullOrEmpty(bamDamPath))
            {
                var bamFacts = Normalizers.BamDamNormalizer.ToFacts(bamDamPath);
                store.Facts.AddRange(bamFacts);
            }

            string bitsPath = ResolvePath(c, basePath, ArtifactNames.BitsJobsCsv);
            if (!string.IsNullOrEmpty(bitsPath))
            {
                var bitsFacts = Normalizers.BitsJobNormalizer.ToFacts(bitsPath);
                store.Facts.AddRange(bitsFacts);
            }

            string jumpListsPath = ResolvePath(c, basePath, ArtifactNames.JumpListsCsv);
            if (!string.IsNullOrEmpty(jumpListsPath))
            {
                var jumpFacts = Normalizers.JumpListNormalizer.ToFacts(jumpListsPath);
                store.Facts.AddRange(jumpFacts);
            }

            string wmiPath = ResolvePath(c, basePath, ArtifactNames.WmiPersistenceCsv);
            if (!string.IsNullOrEmpty(wmiPath))
            {
                var wmiFacts = Normalizers.WmiPersistenceNormalizer.ToFacts(wmiPath);
                store.Facts.AddRange(wmiFacts);
            }

            string amcacheProgramsPath = ResolvePath(c, basePath, ArtifactNames.AmcacheProgramsCsv);
            string amcacheFilesPath = ResolvePath(c, basePath, ArtifactNames.AmcacheFilesCsv);
            if (!string.IsNullOrEmpty(amcacheProgramsPath) || !string.IsNullOrEmpty(amcacheFilesPath))
            {
                var amcacheFacts = Normalizers.AmcacheNormalizer.ToFacts(amcacheProgramsPath, amcacheFilesPath);
                store.Facts.AddRange(amcacheFacts);
            }

            string shimcacheEntriesPath = ResolvePath(c, basePath, ArtifactNames.ShimCacheEntriesCsv);
            if (!string.IsNullOrEmpty(shimcacheEntriesPath))
            {
                var shimcacheFacts = Normalizers.ShimCacheEntryNormalizer.ToFacts(shimcacheEntriesPath);
                store.Facts.AddRange(shimcacheFacts);
            }

            string srumNetworkPath = ResolvePath(c, basePath, ArtifactNames.SrumNetworkUsageCsv);
            if (!string.IsNullOrEmpty(srumNetworkPath))
            {
                var srumNetworkFacts = Normalizers.SrumNetworkNormalizer.ToFacts(srumNetworkPath);
                store.Facts.AddRange(srumNetworkFacts);
            }

            string srumAppPath = ResolvePath(c, basePath, ArtifactNames.SrumAppUsageCsv);
            if (!string.IsNullOrEmpty(srumAppPath))
            {
                var srumAppFacts = Normalizers.SrumAppNormalizer.ToFacts(srumAppPath);
                store.Facts.AddRange(srumAppFacts);
            }

            if (c.MftEntries != null && c.MftEntries.Count > 0)
            {
                int mftLimit = 50000;
                try
                {
                    var cfg = new ConfigManager();
                    int n;
                    if (int.TryParse(cfg.Get("MftMaxEntries"), out n) && n > 0)
                        mftLimit = Math.Min(Math.Max(n, 1000), 500000);
                }
                catch (Exception ex) { IR_Collect.Utils.Logger.Warning("MftMaxEntries config read failed: " + ex.Message); }
                var mftFacts = Normalizers.MftNormalizer.ToFacts(c.MftEntries, mftLimit);
                store.Facts.AddRange(mftFacts);
            }

            string scheduledTasksPath = ResolvePath(c, basePath, ArtifactNames.ScheduledTasksXml);
            if (!string.IsNullOrEmpty(scheduledTasksPath))
            {
                var taskFacts = Normalizers.ScheduledTaskNormalizer.ToFacts(scheduledTasksPath);
                store.Facts.AddRange(taskFacts);
            }

            string usnJournalPath = ResolvePath(c, basePath, ArtifactNames.UsnJournalCsv);
            if (!string.IsNullOrEmpty(usnJournalPath))
            {
                var usnFacts = Normalizers.UsnNormalizer.ToFacts(usnJournalPath, 50000);
                store.Facts.AddRange(usnFacts);
            }

            string shellBagsPath = ResolvePath(c, basePath, ArtifactNames.ShellBagsCsv);
            if (!string.IsNullOrEmpty(shellBagsPath))
            {
                var shellFacts = Normalizers.ShellBagsNormalizer.ToFacts(shellBagsPath);
                store.Facts.AddRange(shellFacts);
            }

            foreach (var kvp in ResolveEventLogFilteredCsvPaths(c, basePath))
            {
                var eventLogFacts = Normalizers.EventLogNormalizer.ToFacts(kvp.Value, kvp.Key);
                store.Facts.AddRange(eventLogFacts);
            }

            FactProvenanceHelper.ApplyCaseMetadata(c, store.Facts);
            store.BuildEntityIndex();
            return store;
        }

        /// <summary>從 Facts 建立實體索引（EntityKey → HashSet of Facts，O(1) add 避免重複）。
        /// 建一個新索引後以原子參考交換發布，避免讀取端在重建途中讀到半清空的索引。</summary>
        public void BuildEntityIndex()
        {
            lock (_sync)
            {
                EntityIndex = BuildIndexFor(Facts);
            }
        }

        /// <summary>
        /// 執行緒安全地附加 facts：建立新的 Facts list 與新的 EntityIndex，於同一 lock 內一起原子交換，
        /// 讓已在讀舊集合的關聯／UI 端不會看到半變動狀態。請用本方法取代對已發布 FactStore 的
        /// <c>Facts.AddRange</c> + <c>BuildEntityIndex</c> 就地變更。
        /// </summary>
        public void AppendFacts(IEnumerable<Fact> additional)
        {
            if (additional == null) return;
            lock (_sync)
            {
                var current = Facts;
                var newFacts = current != null ? new List<Fact>(current) : new List<Fact>();
                newFacts.AddRange(additional);
                var newIndex = BuildIndexFor(newFacts);
                Facts = newFacts;          // atomic reference swap
                EntityIndex = newIndex;    // atomic reference swap
            }
        }

        private static Dictionary<string, HashSet<Fact>> BuildIndexFor(List<Fact> facts)
        {
            var index = new Dictionary<string, HashSet<Fact>>(StringComparer.OrdinalIgnoreCase);
            if (facts == null) return index;
            foreach (Fact f in facts)
            {
                FactTimeMetadata.ApplyDefaultsIfMissing(f);
                if (f.EntityRefs == null) continue;
                foreach (EntityRef er in f.EntityRefs)
                {
                    string key = er.ToEntityKey();
                    if (string.IsNullOrEmpty(key)) continue;
                    HashSet<Fact> set;
                    if (!index.TryGetValue(key, out set))
                    {
                        set = new HashSet<Fact>();
                        index[key] = set;
                    }
                    set.Add(f);
                }
            }
            return index;
        }

        /// <summary>依實體類型與值查詢（例如 type=Path, value=c:\windows\system32\cmd.exe）。</summary>
        public List<Fact> GetByEntity(string type, string value)
        {
            if (string.IsNullOrEmpty(value)) return new List<Fact>();
            string norm = value.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(norm)) return new List<Fact>();
            string key = (type ?? "Path").Trim() + ":" + norm;
            var index = EntityIndex; // snapshot the reference; mutations swap it atomically
            if (index == null) return new List<Fact>();
            HashSet<Fact> set;
            return index.TryGetValue(key, out set) ? new List<Fact>(set) : new List<Fact>();
        }

        /// <summary>
        /// Normalize a fact (or filter-bound) time to UTC for consistent comparison/bucketing.
        /// Sources that emit naive timestamps do so from collector-local wall-clock, so Unspecified
        /// is treated as Local; genuinely-UTC sources (MFT FromFileTimeUtc, ShellBags) carry Kind=Utc
        /// and pass through. MinValue/MaxValue are sentinels and pass through unchanged. This mirrors
        /// FactStorePersistence.NormalizeFactTimeForJson so in-memory correlation and exported facts agree.
        /// Without this, MFT/ShellBags (UTC ticks) and EventLog/Process/Activity (local ticks) would be
        /// compared on different bases and miscorrelate by the host's UTC offset.
        /// </summary>
        public static DateTime ToComparableUtc(DateTime t)
        {
            if (t == DateTime.MinValue || t == DateTime.MaxValue) return t;
            try
            {
                if (t.Kind == DateTimeKind.Unspecified)
                    return DateTime.SpecifyKind(t, DateTimeKind.Local).ToUniversalTime();
                if (t.Kind == DateTimeKind.Local)
                    return t.ToUniversalTime();
                return t;
            }
            catch { return t; }
        }

        /// <summary>依時間範圍查詢。時間以 UTC 基準比較，避免不同來源（本機/UTC kind）錯位。</summary>
        public List<Fact> GetByTimeRange(DateTime t1, DateTime t2)
        {
            var facts = Facts; // snapshot the reference; mutations swap it atomically
            if (facts == null) return new List<Fact>();
            DateTime u1 = ToComparableUtc(t1);
            DateTime u2 = ToComparableUtc(t2);
            return facts.Where(f => { DateTime ft = ToComparableUtc(f.Time); return ft >= u1 && ft <= u2; })
                        .OrderByDescending(f => ToComparableUtc(f.Time)).ToList();
        }

        private static string ResolvePath(CaseData c, string basePath, string fileName)
        {
            string resolved = CaseManager.ResolveArtifactPath(c, fileName);
            if (!string.IsNullOrEmpty(resolved) && File.Exists(resolved))
                return resolved;
            string combined = Path.Combine(basePath, fileName);
            return File.Exists(combined) ? combined : null;
        }

        /// <summary>傳回 logLabel -> 完整路徑，僅包含 *_filtered.csv 的 Event Log CSV。</summary>
        private static Dictionary<string, string> ResolveEventLogFilteredCsvPaths(CaseData c, string basePath)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (c.Artifacts != null)
            {
                foreach (var kvp in c.Artifacts)
                {
                    if (!ArtifactNames.IsEventLogFilteredCsv(kvp.Key) || !File.Exists(kvp.Value)) continue;
                    if (kvp.Key.IndexOf("EventLogs", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    string fileName = Path.GetFileName(kvp.Value);
                    string logLabel = ArtifactNames.GetEventLogLabelFromFileName(fileName);
                    if (string.IsNullOrEmpty(logLabel)) continue;
                    result[logLabel] = kvp.Value;
                }
            }
            string eventLogsDir = Path.Combine(basePath, "EventLogs");
            if (Directory.Exists(eventLogsDir))
            {
                foreach (var f in Directory.GetFiles(eventLogsDir, ArtifactNames.EventLogFilteredGlob))
                {
                    string logLabel = ArtifactNames.GetEventLogLabelFromFileName(Path.GetFileName(f));
                    if (string.IsNullOrEmpty(logLabel) || result.ContainsKey(logLabel)) continue;
                    result[logLabel] = f;
                }
            }
            return result;
        }

        public int Count { get { return Facts == null ? 0 : Facts.Count; } }
    }
}
