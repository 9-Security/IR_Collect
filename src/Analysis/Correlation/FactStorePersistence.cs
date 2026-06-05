using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using IR_Collect.Analysis;
using IR_Collect.Utils;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation
{
    [DataContract]
    public sealed class FullLogHostSummary
    {
        [DataMember(Name = "host")]
        public string Host { get; set; }
        [DataMember(Name = "case_id")]
        public string CaseId { get; set; }
        [DataMember(Name = "collection_mode_profile")]
        public string CollectionModeProfile { get; set; }
        [DataMember(Name = "fact_count")]
        public int FactCount { get; set; }
        [DataMember(Name = "fact_source_counts")]
        public Dictionary<string, int> FactSourceCounts { get; set; }
        [DataMember(Name = "load_warnings")]
        public List<string> LoadWarnings { get; set; }
        [DataMember(Name = "collection_coverage_status")]
        public string CollectionCoverageStatus { get; set; }
        [DataMember(Name = "fact_store_freshness_status")]
        public string FactStoreFreshnessStatus { get; set; }
        [DataMember(Name = "fact_store_freshness_detail")]
        public string FactStoreFreshnessDetail { get; set; }
        [DataMember(Name = "analyst_workflow")]
        public AnalystWorkflowState AnalystWorkflow { get; set; }
        [DataMember(Name = "guided_hunt")]
        public GuidedHuntResult GuidedHunt { get; set; }
        [DataMember(Name = "memory_acquisition")]
        public MemoryAcquisitionRecord MemoryAcquisition { get; set; }
        [DataMember(Name = "memory_analysis")]
        public MemoryAnalysisRecord MemoryAnalysis { get; set; }
    }

    [DataContract]
    public sealed class FullLogExportPayload
    {
        [DataMember(Name = "generated_at")]
        public string GeneratedAt { get; set; }
        [DataMember(Name = "export_schema")]
        public string ExportSchema { get; set; }
        [DataMember(Name = "analysis_mode")]
        public string AnalysisMode { get; set; }
        [DataMember(Name = "host_count")]
        public int HostCount { get; set; }
        [DataMember(Name = "fact_count")]
        public int FactCount { get; set; }
        [DataMember(Name = "fact_source_counts")]
        public Dictionary<string, int> FactSourceCounts { get; set; }
        [DataMember(Name = "entity_type_counts")]
        public Dictionary<string, int> EntityTypeCounts { get; set; }
        [DataMember(Name = "load_warnings")]
        public List<string> LoadWarnings { get; set; }
        [DataMember(Name = "parser_notes")]
        public List<string> ParserNotes { get; set; }
        [DataMember(Name = "hosts")]
        public List<FullLogHostSummary> Hosts { get; set; }
        [DataMember(Name = "facts")]
        public List<Fact> Facts { get; set; }
    }

    /// <summary>
    /// Phase B3: Fact Store 持久化 — SQLite（拆欄 Id/Time/Source/EntityKey + JSON Details）與完整 LOG JSON 匯出。
    /// SQLite 以執行期載入 System.Data.SQLite.dll，無編譯期依賴；未提供 DLL 時僅略過寫入/讀取。
    /// </summary>
    public static class FactStorePersistence
    {
        public const int SchemaVersion = 3;
        private const string TableName = "Facts";

        public static bool HasSqliteSupport()
        {
            return GetSqliteAssembly() != null && _connType != null;
        }

        /// <summary>將 FactStore 寫入 SQLite。若無 System.Data.SQLite.dll 則傳回 false。</summary>
        public static bool SaveToSqlite(FactStore store, string dbPath)
        {
            if (store == null || store.Facts == null || string.IsNullOrEmpty(dbPath)) return false;
            try
            {
                string dir = Path.GetDirectoryName(dbPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                object conn = CreateSqliteConnection(dbPath);
                if (conn == null) return false;
                try
                {
                    CreateTable(conn, dbPath);
                    object trans = BeginTransaction(conn, dbPath);
                    if (trans == null) return false;
                    try
                    {
                        ExecuteNonQuery(conn, "DELETE FROM " + TableName);
                        var serializer = new DataContractJsonSerializer(typeof(Fact));
                        foreach (Fact f in store.Facts)
                        {
                            string entityKey = GetPrimaryEntityKey(f);
                            string timeStr = f.Time.ToString("o");
                            string json = SerializeFactToJson(f, serializer);
                            InsertRow(conn, dbPath, f.Id ?? "", timeStr, f.Source ?? "", entityKey ?? "", json);
                        }
                        CommitTransaction(trans, dbPath);
                    }
                    finally { var tr = trans as IDisposable; if (tr != null) tr.Dispose(); }
                }
                finally
                {
                    CloseConnection(conn, dbPath);
                }
                return true;
            }
            catch (Exception ex)
            {
                Logger.Warning("FactStorePersistence.SaveToSqlite: " + ex.Message);
                return false;
            }
        }

        /// <summary>自 SQLite 讀出 FactStore。若檔案不存在或無 DLL 則傳回 null。</summary>
        public static FactStore LoadFromSqlite(string dbPath, string caseId = "", string hostname = "")
        {
            int skippedRows;
            return LoadFromSqlite(dbPath, caseId, hostname, out skippedRows);
        }

        /// <summary>
        /// 自 SQLite 讀出 FactStore，並回報略過的不可讀 fact 列數。
        /// Fail-soft: 單一損毀的 fact 列（或缺少/無法解析 SchemaVersion 的列）會被略過並計數，
        /// 不會丟棄整個案卷。僅在「整個 DB 的 schema 版本不支援」或「有資料但無任何列可讀」時才硬性失敗，
        /// 提示分析師重建 Fact Store，與 MFT/CSV 解析的 log-and-continue 行為一致。
        /// </summary>
        public static FactStore LoadFromSqlite(string dbPath, string caseId, string hostname, out int skippedRows)
        {
            skippedRows = 0;
            if (string.IsNullOrEmpty(dbPath) || !File.Exists(dbPath)) return null;
            try
            {
                object conn = CreateSqliteConnection(dbPath);
                if (conn == null) return null;
                try
                {
                    var rows = ExecuteQuery(conn, dbPath, "SELECT Id, Time, Source, EntityKey, DetailsJson, SchemaVersion FROM " + TableName);
                    return BuildStoreFromRows(rows, caseId, hostname, dbPath, out skippedRows);
                }
                finally
                {
                    CloseConnection(conn, dbPath);
                }
            }
            catch (InvalidDataException)
            {
                // Hard-fail signals (unsupported schema / total corruption) propagate unchanged.
                throw;
            }
            catch (Exception ex)
            {
                Logger.Warning("FactStorePersistence.LoadFromSqlite: " + ex.Message);
                throw new InvalidDataException("Unable to load fact_store.db: " + ex.Message, ex);
            }
        }

        /// <summary>將多個 FactStore 的 Facts 匯出為單一 JSON 檔（完整 LOG 規格）。</summary>
        public static void ExportFullLogJson(IEnumerable<FactStore> stores, string filePath)
        {
            if (stores == null || string.IsNullOrEmpty(filePath)) return;
            var storeList = stores.Where(s => s != null).ToList();
            var facts = EnumerateFacts(storeList).ToList();
            var payload = BuildFullLogPayload(
                facts,
                BuildHostSummariesFromStores(storeList),
                new List<string>());
            WriteJsonPayload(payload, typeof(FullLogExportPayload), filePath);
        }

        /// <summary>將多個 Case 的 Facts 匯出為單一 JSON 檔（完整 LOG 規格，含 host 摘要與 load warnings）。</summary>
        public static void ExportFullLogJson(IEnumerable<CaseData> cases, string filePath)
        {
            if (cases == null || string.IsNullOrEmpty(filePath)) return;

            var caseList = cases.Where(c => c != null).ToList();
            var facts = new List<Fact>();
            foreach (CaseData c in caseList)
            {
                if (c.FactStore == null || c.FactStore.Facts == null) continue;
                facts.AddRange(c.FactStore.Facts);
            }

            var payload = BuildFullLogPayload(
                facts,
                BuildHostSummariesFromCases(caseList),
                BuildAggregatedLoadWarnings(caseList));
            WriteJsonPayload(payload, typeof(FullLogExportPayload), filePath);
        }

        /// <summary>將 Fact 清單匯出為單一 JSON 檔。會正規化無法序列化的 DateTime（如 MinValue）以避免 DataContractJsonSerializer 拋錯。</summary>
        public static void ExportFullLogJson(List<Fact> facts, string filePath)
        {
            if (facts == null || string.IsNullOrEmpty(filePath)) return;
            var payload = BuildFullLogPayload(
                facts,
                new List<FullLogHostSummary>(),
                new List<string>());
            WriteJsonPayload(payload, typeof(FullLogExportPayload), filePath);
        }

        /// <summary>複製 Fact 並將 Time 正規化為可序列化範圍（1970–2099 UTC），避免 JSON 轉 UTC 時超出範圍拋錯。</summary>
        private static Fact CopyFactWithSafeTime(Fact f, DateTime safeEpoch)
        {
            if (f == null) return null;
            FactTimeMetadata.ApplyDefaultsIfMissing(f);
            DateTime t = NormalizeFactTimeForJson(f.Time, safeEpoch);
            var copy = new Fact(f.Id, t, f.Source, f.Action);
            copy.TimeKind = f.TimeKind;
            copy.TimeConfidence = f.TimeConfidence;
            copy.SourceFile = f.SourceFile;
            copy.CollectionStep = f.CollectionStep;
            copy.CollectionStatus = f.CollectionStatus;
            copy.CollectionPrivilege = f.CollectionPrivilege;
            copy.ParseLevel = f.ParseLevel;
            copy.FallbackUsed = f.FallbackUsed;
            copy.ParserNote = f.ParserNote;
            copy.Details = f.Details;
            copy.RawRef = f.RawRef;
            if (f.EntityRefs != null)
            {
                copy.EntityRefs = new List<EntityRef>();
                foreach (var er in f.EntityRefs)
                    copy.EntityRefs.Add(new EntityRef(er.Type, er.Value));
            }
            return copy;
        }

        internal static DateTime NormalizeFactTimeForJson(DateTime t, DateTime safeEpoch)
        {
            if (t == DateTime.MinValue || t == DateTime.MaxValue || t.Year < 1970 || t.Year > 2099)
                return safeEpoch;
            try
            {
                if (t.Kind == DateTimeKind.Unspecified)
                    return DateTime.SpecifyKind(t, DateTimeKind.Local).ToUniversalTime();
                if (t.Kind == DateTimeKind.Local)
                    return t.ToUniversalTime();
                return t;
            }
            catch
            {
                return safeEpoch;
            }
        }

        private static string GetPrimaryEntityKey(Fact f)
        {
            if (f == null || f.EntityRefs == null || f.EntityRefs.Count == 0) return "";
            return f.EntityRefs[0].ToEntityKey() ?? "";
        }

        private static bool IsSupportedSchemaVersion(int rowSchemaVersion)
        {
            return rowSchemaVersion >= 1 && rowSchemaVersion <= SchemaVersion;
        }

        private static IEnumerable<Fact> EnumerateFacts(IEnumerable<FactStore> stores)
        {
            foreach (FactStore store in stores)
            {
                if (store == null || store.Facts == null) continue;
                foreach (Fact fact in store.Facts)
                    yield return fact;
            }
        }

        private static FullLogExportPayload BuildFullLogPayload(IEnumerable<Fact> facts, List<FullLogHostSummary> hosts, List<string> loadWarnings)
        {
            var safeEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var copiedFacts = new List<Fact>();

            if (facts != null)
            {
                foreach (Fact fact in facts)
                {
                    Fact copy = CopyFactWithSafeTime(fact, safeEpoch);
                    if (copy == null) continue;
                    copiedFacts.Add(copy);
                }
            }

            var payload = new FullLogExportPayload();
            payload.GeneratedAt = DateTime.UtcNow.ToString("o");
            payload.ExportSchema = "full_log_v3";
            payload.AnalysisMode = "facts_only";
            payload.Hosts = hosts ?? new List<FullLogHostSummary>();
            payload.HostCount = payload.Hosts.Count;
            payload.Facts = copiedFacts;
            payload.FactCount = copiedFacts.Count;
            payload.FactSourceCounts = BuildFactSourceCounts(copiedFacts);
            payload.EntityTypeCounts = BuildEntityTypeCounts(copiedFacts);
            payload.LoadWarnings = loadWarnings ?? new List<string>();
            payload.ParserNotes = BuildExportParserNotes(copiedFacts, payload.LoadWarnings, payload.Hosts);
            return payload;
        }

        private static void WriteJsonPayload(object payload, Type payloadType, string filePath)
        {
            if (payload == null || payloadType == null || string.IsNullOrEmpty(filePath)) return;

            string dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            var serializer = new DataContractJsonSerializer(
                payloadType,
                new DataContractJsonSerializerSettings { UseSimpleDictionaryFormat = true });

            using (var fs = File.Create(filePath))
            {
                serializer.WriteObject(fs, payload);
            }
        }

        private static Dictionary<string, int> BuildFactSourceCounts(IEnumerable<Fact> facts)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (facts == null) return counts;

            foreach (Fact fact in facts)
            {
                string key = fact != null ? (fact.Source ?? "") : "";
                if (string.IsNullOrWhiteSpace(key)) key = "Unknown";
                int count;
                counts[key] = counts.TryGetValue(key, out count) ? (count + 1) : 1;
            }

            return counts;
        }

        private static Dictionary<string, int> BuildEntityTypeCounts(IEnumerable<Fact> facts)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (facts == null) return counts;

            foreach (Fact fact in facts)
            {
                if (fact == null || fact.EntityRefs == null) continue;
                foreach (EntityRef entity in fact.EntityRefs)
                {
                    string key = entity != null ? (entity.Type ?? "") : "";
                    if (string.IsNullOrWhiteSpace(key)) key = "Unknown";
                    int count;
                    counts[key] = counts.TryGetValue(key, out count) ? (count + 1) : 1;
                }
            }

            return counts;
        }

        private static List<FullLogHostSummary> BuildHostSummariesFromStores(IEnumerable<FactStore> stores)
        {
            var hosts = new List<FullLogHostSummary>();
            if (stores == null) return hosts;

            foreach (FactStore store in stores)
            {
                if (store == null) continue;
                hosts.Add(new FullLogHostSummary
                {
                    Host = store.Hostname ?? "",
                    CaseId = store.CaseId ?? "",
                    FactCount = store.Facts != null ? store.Facts.Count : 0,
                    FactSourceCounts = BuildFactSourceCounts(store.Facts),
                    LoadWarnings = new List<string>(),
                    CollectionCoverageStatus = "",
                    FactStoreFreshnessStatus = "",
                    FactStoreFreshnessDetail = "",
                    AnalystWorkflow = new AnalystWorkflowState(),
                    GuidedHunt = null
                });
            }

            return hosts;
        }

        private static List<FullLogHostSummary> BuildHostSummariesFromCases(IEnumerable<CaseData> cases)
        {
            var hosts = new List<FullLogHostSummary>();
            if (cases == null) return hosts;

            foreach (CaseData c in cases)
            {
                if (c == null) continue;
                hosts.Add(new FullLogHostSummary
                {
                    Host = c.Hostname ?? "",
                    CaseId = c.CaseID ?? "",
                    FactCount = c.FactStore != null ? c.FactStore.Count : 0,
                    FactSourceCounts = BuildFactSourceCounts(c.FactStore != null ? c.FactStore.Facts : null),
                    LoadWarnings = c.LoadWarnings != null ? new List<string>(c.LoadWarnings) : new List<string>(),
                    CollectionCoverageStatus = c.CollectionCoverage != null ? (c.CollectionCoverage.OverallStatus ?? "") : "",
                    CollectionModeProfile = c.CollectionCoverage != null && !string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile)
                        ? CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile)
                        : "",
                    FactStoreFreshnessStatus = c.FactStoreFreshnessStatus ?? "",
                    FactStoreFreshnessDetail = c.FactStoreFreshnessDetail ?? "",
                    AnalystWorkflow = c.AnalystWorkflow ?? new AnalystWorkflowState(),
                    GuidedHunt = GuidedHuntPack.Evaluate(c),
                    MemoryAcquisition = c.MemoryAcquisitionMeta,
                    MemoryAnalysis = c.MemoryAnalysisMeta
                });
            }

            return hosts;
        }

        private static List<string> BuildAggregatedLoadWarnings(IEnumerable<CaseData> cases)
        {
            var warnings = new List<string>();
            if (cases == null) return warnings;

            foreach (CaseData c in cases)
            {
                if (c == null || c.LoadWarnings == null || c.LoadWarnings.Count == 0) continue;
                string host = string.IsNullOrWhiteSpace(c.Hostname) ? "host" : c.Hostname;
                foreach (string warning in c.LoadWarnings)
                {
                    if (string.IsNullOrWhiteSpace(warning)) continue;
                    warnings.Add(host + ": " + warning);
                }
            }

            return warnings;
        }

        private static List<string> BuildExportParserNotes(IEnumerable<Fact> facts, IEnumerable<string> loadWarnings, IEnumerable<FullLogHostSummary> hosts = null)
        {
            var notes = new List<string>();
            notes.Add("This export preserves observed facts only. Any guided_hunt content remains a separate explainable overlay and does not modify exported facts.");
            notes.Add("TimeKind and TimeConfidence describe whether a timestamp comes from an event record, metadata, observation, or remains unknown.");
            notes.Add("SourceFile identifies the originating artifact file when known; RawRef points back to the original row or record when available.");
            notes.Add("CollectionStep, CollectionStatus, CollectionPrivilege, ParseLevel, and FallbackUsed provide fact-level provenance for downstream review.");

            var factList = facts != null ? facts.Where(f => f != null).ToList() : new List<Fact>();
            if (factList.Any(f => !string.IsNullOrWhiteSpace(f.ParserNote)))
                notes.Add("ParserNote is present only when a fact needed extra parsing context, such as message-derived paths, ambiguous autorun values, missing process paths, or USN rows without full paths.");
            notes.AddRange(ParserNoteSummaryBuilder.BuildFactParserNoteLines(factList, 10));
            if (factList.Any(f => (f.Source ?? "").StartsWith("EventLog", StringComparison.OrdinalIgnoreCase)))
                notes.Add("EventLog facts are primarily derived from filtered CSV plus structured EventData fields exported from event XML.");
            if (factList.Any(f => string.Equals(f.Source, "ScheduledTask", StringComparison.OrdinalIgnoreCase)))
                notes.Add("ScheduledTask facts describe task definitions, not task execution times; corroborate with Event Logs for runtime activity.");
            if (factList.Any(f => string.Equals(f.Source, "Service", StringComparison.OrdinalIgnoreCase)))
                notes.Add("Service facts describe service configuration observed at collection time; they do not prove install time, start time, or execution without corroborating artifacts.");
            if (factList.Any(f => string.Equals(f.Source, "StoredCredential", StringComparison.OrdinalIgnoreCase)))
                notes.Add("StoredCredential facts represent credentials currently listed by cmdkey at collection time; target-server parsing is heuristic because cmdkey output is text-formatted.");
            if (factList.Any(f => string.Equals(f.Source, "KerberosTicketCache", StringComparison.OrdinalIgnoreCase)))
                notes.Add("KerberosTicketCache facts represent cached tickets observed by klist; timeline uses ticket Start Time when parseable, otherwise ObservedAtUtc.");
            if (factList.Any(f => string.Equals(f.Source, "Autorun", StringComparison.OrdinalIgnoreCase)))
                notes.Add("Autorun facts represent persistence entries observed at collection time; registry values may include raw command strings when no executable path could be normalized.");
            if (factList.Any(f => string.Equals(f.Source, "MFT", StringComparison.OrdinalIgnoreCase)))
                notes.Add("MFT facts are file-system metadata observations, not direct execution events.");
            if (factList.Any(f => string.Equals(f.Source, "USN", StringComparison.OrdinalIgnoreCase)))
                notes.Add("USN facts reflect journal rows as collected; some rows may only correlate at FileName level when the original output lacked full paths.");
            if (factList.Any(f => string.Equals(f.Source, "Amcache", StringComparison.OrdinalIgnoreCase)))
                notes.Add("Amcache facts are reconstructed from registry hive branches; field names differ by OS build and parser notes flag partial rows.");
            if (factList.Any(f => string.Equals(f.Source, "ShimCache", StringComparison.OrdinalIgnoreCase)))
                notes.Add("ShimCache facts are entry-level execution candidates reconstructed from binary cache data and should be corroborated with stronger execution artifacts.");
            if (factList.Any(f => string.Equals(f.Source, "SRUMNetwork", StringComparison.OrdinalIgnoreCase) || string.Equals(f.Source, "SRUMApp", StringComparison.OrdinalIgnoreCase)))
                notes.Add("SRUM facts come from stable core tables only; provider/table availability depends on local ESE/OLE DB support and Windows version.");
            if (loadWarnings != null && loadWarnings.Any(w => !string.IsNullOrWhiteSpace(w)))
                notes.Add("Load warnings are preserved separately and should be reviewed before drawing conclusions from missing or capped artifacts.");
            notes.Add("Host summaries may include collection_coverage_status and fact_store_freshness_status so downstream analysis can distinguish collection gaps from stale caches.");
            if (hosts != null && hosts.Any(h => h != null && !string.IsNullOrWhiteSpace(h.CollectionModeProfile)))
            notes.Add("Host summaries may include collection_mode_profile when the intake case recorded collection_coverage.json from a profile-aware collector build.");
            notes.Add("Host summaries may also include analyst_workflow so bookmarks, notes, tags, and hypotheses can travel with exported review packs.");
            if (hosts != null && hosts.Any(h => h != null && h.GuidedHunt != null && h.GuidedHunt.Enabled))
                notes.Add("Host summaries may include guided_hunt results: ATT&CK-mapped, explainable rule hits and hypothesis templates layered on top of facts without modifying the Fact Store.");
            if (hosts != null && hosts.Any(h => h != null && (h.MemoryAcquisition != null || h.MemoryAnalysis != null)))
                notes.Add(MemoryHandoffHelper.CoverageVsSidecarGuidance);

            return notes;
        }

        private static string SerializeFactToJson(Fact f, DataContractJsonSerializer serializer)
        {
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, f);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        /// <summary>
        /// Build a FactStore from raw query rows, fail-soft. Internal so it can be unit-tested
        /// without a live SQLite DLL. Skips (and counts) individual unreadable rows; throws
        /// InvalidDataException only for an unsupported DB-wide schema version or total corruption.
        /// </summary>
        internal static FactStore BuildStoreFromRows(List<Dictionary<string, object>> rows, string caseId, string hostname, string dbPathForLog, out int skippedRows)
        {
            skippedRows = 0;
            var store = new FactStore();
            store.CaseId = caseId;
            store.Hostname = hostname;
            var serializer = new DataContractJsonSerializer(typeof(Fact));
            int rowCount = 0;
            if (rows != null)
            {
                foreach (var row in rows)
                {
                    rowCount++;
                    object schemaObj;
                    int rowSchemaVersion;
                    if (row == null || !row.TryGetValue("SchemaVersion", out schemaObj) || schemaObj == null
                        || !int.TryParse(schemaObj.ToString(), out rowSchemaVersion))
                    {
                        // Missing/unparseable version on a single row: skip it, keep the rest.
                        skippedRows++;
                        continue;
                    }
                    if (!IsSupportedSchemaVersion(rowSchemaVersion))
                    {
                        // Schema version is a DB-wide property: an unsupported version means the whole
                        // cache is from an incompatible build. Fail hard so the caller prompts a rebuild
                        // rather than silently loading half of it.
                        throw new InvalidDataException("fact_store.db schema version " + rowSchemaVersion + " is not supported; rebuild Fact Store.");
                    }
                    Fact f = DeserializeFactFromRow(row, serializer);
                    if (f == null)
                    {
                        skippedRows++;
                        continue;
                    }
                    store.Facts.Add(f);
                }
            }
            // Distinguish a legitimately empty cache from total corruption.
            if (rowCount > 0 && store.Facts.Count == 0)
                throw new InvalidDataException("fact_store.db contains " + rowCount + " row(s) but none were readable; rebuild Fact Store.");
            store.BuildEntityIndex();
            if (skippedRows > 0)
                Logger.Warning("FactStorePersistence: skipped " + skippedRows + " unreadable fact row(s)" + (string.IsNullOrEmpty(dbPathForLog) ? "" : " in " + dbPathForLog));
            return store;
        }

        private static Fact DeserializeFactFromRow(Dictionary<string, object> row, DataContractJsonSerializer serializer)
        {
            object jsonObj;
            if (!row.TryGetValue("DetailsJson", out jsonObj) || jsonObj == null) return null;
            string json = jsonObj.ToString();
            if (string.IsNullOrEmpty(json)) return null;
            try
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    var f = (Fact)serializer.ReadObject(ms);
                    if (f != null && row.ContainsKey("Id")) f.Id = row["Id"] != null ? row["Id"].ToString() : null;
                    if (f != null && row.ContainsKey("Time"))
                    {
                        string t = row["Time"] != null ? row["Time"].ToString() : null;
                        if (!string.IsNullOrEmpty(t))
                        {
                            DateTime dt;
                            if (DateTime.TryParse(t, null, System.Globalization.DateTimeStyles.RoundtripKind, out dt)) f.Time = dt;
                        }
                    }
                    if (f != null && row.ContainsKey("Source")) f.Source = row["Source"] != null ? (row["Source"].ToString() ?? f.Source) : f.Source;
                    FactTimeMetadata.ApplyDefaultsIfMissing(f);
                    return f;
                }
            }
            catch (Exception ex) { Logger.Warning("FactStorePersistence LoadFromSqlite: " + (ex.Message ?? "")); return null; }
        }

        #region SQLite via reflection (no compile-time reference) — cached MethodInfo

        private static Assembly _sqliteAssembly;

        // Cached types and methods to avoid per-call GetType/GetMethod overhead
        private static Type _connType;
        private static Type _cmdType;
        private static Type _paramType;
        private static System.Reflection.MethodInfo _miOpen;
        private static System.Reflection.MethodInfo _miClose;
        private static System.Reflection.MethodInfo _miExecNonQuery;
        private static System.Reflection.MethodInfo _miExecReader;
        private static System.Reflection.MethodInfo _miBeginTrans;
        private static System.Reflection.MethodInfo _miAddParam;
        private static System.Reflection.MethodInfo _miReaderRead;
        private static System.Reflection.MethodInfo _miReaderGetName;
        private static System.Reflection.MethodInfo _miReaderGetValue;
        private static System.Reflection.MethodInfo _miReaderFieldCount;
        private static System.Reflection.PropertyInfo _piParameters;

        /// <summary>
        /// True only if <paramref name="path"/> carries a valid, Authenticode-trusted signature.
        /// Fail-safe: any error or a non-trusted status returns false (do not load). Logs the signer
        /// for audit, and explains a rejection so the operator knows SQLite features were disabled.
        /// </summary>
        internal static bool IsTrustedSqliteModule(string path)
        {
            try
            {
                string signer;
                string status = IR_Collect.SignatureHelper.GetSignatureStatus(path, out signer);
                if (string.Equals(status, "Signed-Trusted", StringComparison.Ordinal))
                {
                    Logger.Info("System.Data.SQLite.dll signature trusted (signer: " + signer + ").");
                    return true;
                }
                Logger.Warning("System.Data.SQLite.dll present but signature status is '" + status + "' (signer: " + signer +
                    "). Refusing to load it to avoid DLL planting / stale-engine risk; SQLite features disabled. Use the official signed System.Data.SQLite build.");
                return false;
            }
            catch (Exception ex)
            {
                Logger.Warning("System.Data.SQLite.dll signature check failed: " + (ex.Message ?? "") + "; refusing to load.");
                return false;
            }
        }

        private static Assembly GetSqliteAssembly()
        {
            if (_sqliteAssembly != null) return _sqliteAssembly;
            string baseDir = AppDomain.CurrentDomain.BaseDirectory ?? "";
            string path = Path.Combine(baseDir, "System.Data.SQLite.dll");
            if (!File.Exists(path)) return null;
            // Anti-DLL-planting / anti-stale-engine gate: we LoadFrom a DLL sitting next to the exe and
            // then parse UNTRUSTED SQLite files (copied browser History/places.sqlite) with it, so a
            // planted or obviously-unofficial DLL is a real RCE vector. Only load one carrying a valid,
            // Authenticode-trusted signature; otherwise refuse (SQLite features degrade gracefully, same
            // as the DLL being absent). The official System.Data.SQLite build is signed, so this does not
            // break legitimate use.
            if (!IsTrustedSqliteModule(path)) return null;
            try
            {
                _sqliteAssembly = Assembly.LoadFrom(path);
                _connType  = _sqliteAssembly.GetType("System.Data.SQLite.SQLiteConnection");
                _cmdType   = _sqliteAssembly.GetType("System.Data.SQLite.SQLiteCommand");
                _paramType = _sqliteAssembly.GetType("System.Data.SQLite.SQLiteParameter");

                if (_connType != null)
                {
                    _miOpen       = _connType.GetMethod("Open");
                    _miClose      = _connType.GetMethod("Close");
                    _miBeginTrans = _connType.GetMethod("BeginTransaction", Type.EmptyTypes);
                }
                if (_cmdType != null)
                {
                    _miExecNonQuery = _cmdType.GetMethod("ExecuteNonQuery");
                    _miExecReader   = _cmdType.GetMethod("ExecuteReader", Type.EmptyTypes);
                    _piParameters   = _cmdType.GetProperty("Parameters");
                }
                return _sqliteAssembly;
            }
            catch (Exception ex) { Logger.Warning("GetSqliteAssembly: " + (ex.Message ?? "")); _sqliteAssembly = null; return null; }
        }

        private static object CreateSqliteConnection(string dbPath)
        {
            if (GetSqliteAssembly() == null || _connType == null) return null;
            try
            {
                object conn = Activator.CreateInstance(_connType, "Data Source=" + dbPath);
                _miOpen.Invoke(conn, null);
                return conn;
            }
            catch (Exception ex) { Logger.Warning("CreateSqliteConnection: " + (ex.Message ?? "")); return null; }
        }

        private static void CloseConnection(object conn, string dbPath)
        {
            try
            {
                if (conn == null) return;
                if (_miClose != null) _miClose.Invoke(conn, null);
                var d = conn as IDisposable; if (d != null) d.Dispose();
            }
            catch (Exception ex) { Logger.Warning("CloseConnection: " + (ex.Message ?? "")); }
        }

        private static void CreateTable(object conn, string dbPath)
        {
            ExecuteNonQuery(conn, "CREATE TABLE IF NOT EXISTS " + TableName + " (Id TEXT, Time TEXT, Source TEXT, EntityKey TEXT, DetailsJson TEXT, SchemaVersion INTEGER)");
            ExecuteNonQuery(conn, "CREATE INDEX IF NOT EXISTS idx_facts_time ON " + TableName + "(Time)");
            ExecuteNonQuery(conn, "CREATE INDEX IF NOT EXISTS idx_facts_source ON " + TableName + "(Source)");
            ExecuteNonQuery(conn, "CREATE INDEX IF NOT EXISTS idx_facts_entity ON " + TableName + "(EntityKey)");
        }

        private static void ExecuteNonQuery(object conn, string sql)
        {
            if (_cmdType == null || _miExecNonQuery == null) return;
            object cmd = Activator.CreateInstance(_cmdType, sql, conn);
            try { _miExecNonQuery.Invoke(cmd, null); }
            finally { var c = cmd as IDisposable; if (c != null) c.Dispose(); }
        }

        private static void InsertRow(object conn, string dbPath, string id, string timeStr, string source, string entityKey, string detailsJson)
        {
            if (_cmdType == null || _miExecNonQuery == null) return;
            string sql = "INSERT INTO " + TableName + " (Id, Time, Source, EntityKey, DetailsJson, SchemaVersion) VALUES (@id, @t, @src, @ek, @json, @ver)";
            object cmd = Activator.CreateInstance(_cmdType, sql, conn);
            try
            {
                AddParameter(cmd, "@id",   id);
                AddParameter(cmd, "@t",    timeStr);
                AddParameter(cmd, "@src",  source);
                AddParameter(cmd, "@ek",   entityKey);
                AddParameter(cmd, "@json", detailsJson);
                AddParameter(cmd, "@ver",  (object)SchemaVersion);
                _miExecNonQuery.Invoke(cmd, null);
            }
            finally { var c = cmd as IDisposable; if (c != null) c.Dispose(); }
        }

        private static void AddParameter(object cmd, string name, object value)
        {
            if (_paramType == null || _piParameters == null) return;
            if (_miAddParam == null)
                _miAddParam = _piParameters.PropertyType.GetMethod("Add", new[] { _paramType });
            object param = Activator.CreateInstance(_paramType, name, value ?? DBNull.Value);
            object parameters = _piParameters.GetValue(cmd, null);
            if (parameters != null && _miAddParam != null)
                _miAddParam.Invoke(parameters, new[] { param });
        }

        private static object BeginTransaction(object conn, string dbPath)
        {
            if (conn == null || _miBeginTrans == null) return null;
            try { return _miBeginTrans.Invoke(conn, null); }
            catch (Exception ex) { Logger.Warning("BeginTransaction: " + (ex.Message ?? "")); return null; }
        }

        private static void CommitTransaction(object trans, string dbPath)
        {
            if (trans == null) return;
            try
            {
                var miCommit = trans.GetType().GetMethod("Commit");
                if (miCommit != null) miCommit.Invoke(trans, null);
            }
            catch (Exception ex) { Logger.Warning("CommitTransaction: " + (ex.Message ?? "")); }
        }

        private static List<Dictionary<string, object>> ExecuteQuery(object conn, string dbPath, string sql)
        {
            if (_cmdType == null || _miExecReader == null) return null;
            object cmd = Activator.CreateInstance(_cmdType, sql, conn);
            var list = new List<Dictionary<string, object>>();
            try
            {
                object reader = _miExecReader.Invoke(cmd, null);
                if (reader == null) return list;
                Type rType = reader.GetType();
                if (_miReaderRead       == null) _miReaderRead       = rType.GetMethod("Read");
                if (_miReaderGetName    == null) _miReaderGetName    = rType.GetMethod("GetName",    new[] { typeof(int) });
                if (_miReaderGetValue   == null) _miReaderGetValue   = rType.GetMethod("GetValue",   new[] { typeof(int) });
                if (_miReaderFieldCount == null) _miReaderFieldCount = rType.GetMethod("get_FieldCount");
                try
                {
                    while (true)
                    {
                        object ok = _miReaderRead.Invoke(reader, null);
                        if (ok == null || !(bool)ok) break;
                        int fieldCount = (int)_miReaderFieldCount.Invoke(reader, null);
                        var row = new Dictionary<string, object>(fieldCount, StringComparer.OrdinalIgnoreCase);
                        for (int i = 0; i < fieldCount; i++)
                        {
                            string colName = (string)_miReaderGetName.Invoke(reader, new object[] { i });
                            object val     = _miReaderGetValue.Invoke(reader, new object[] { i });
                            if (val != null && val != DBNull.Value) row[colName] = val;
                        }
                        list.Add(row);
                    }
                }
                finally { var rd = reader as IDisposable; if (rd != null) rd.Dispose(); }
            }
            finally { var c = cmd as IDisposable; if (c != null) c.Dispose(); }
            return list;
        }

        /// <summary>從 Chrome/Chromium History SQLite 讀取 URL 與最後造訪時間。無 DLL 或非 Chrome 格式時傳回 null。</summary>
        public static List<Tuple<string, DateTime>> TryGetChromeHistory(string dbPath, int maxRows = 5000)
        {
            if (string.IsNullOrEmpty(dbPath) || !File.Exists(dbPath)) return null;
            object conn = CreateSqliteConnection(dbPath);
            if (conn == null) return null;
            try
            {
                var rows = ExecuteQuery(conn, dbPath, "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT " + Math.Max(1, Math.Min(maxRows, 50000)));
                if (rows == null || rows.Count == 0) return null;
                var result = new List<Tuple<string, DateTime>>();
                var wkt = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                foreach (var row in rows)
                {
                    object urlObj; if (!row.TryGetValue("url", out urlObj) || urlObj == null) continue;
                    string url = urlObj.ToString();
                    if (string.IsNullOrEmpty(url)) continue;
                    object ltObj; row.TryGetValue("last_visit_time", out ltObj);
                    long t = 0;
                    if (ltObj != null && ltObj != DBNull.Value)
                    {
                        if (ltObj is long) t = (long)ltObj;
                        else if (ltObj is int) t = (int)ltObj;
                        else long.TryParse(ltObj.ToString(), out t);
                    }
                    DateTime dt = default(DateTime);
                    if (t > 0) dt = wkt.AddTicks(t * 10).ToLocalTime();
                    result.Add(Tuple.Create(url, dt));
                }
                return result.Count > 0 ? result : null;
            }
            catch (Exception ex) { Logger.Warning("TryGetChromeHistory: " + (ex.Message ?? "")); return null; }
            finally { CloseConnection(conn, dbPath); }
        }

        /// <summary>從 Firefox places.sqlite 讀取 URL 與最後造訪時間。無 DLL 或非 Firefox 格式時傳回 null。</summary>
        public static List<Tuple<string, DateTime>> TryGetFirefoxHistory(string dbPath, int maxRows = 5000)
        {
            if (string.IsNullOrEmpty(dbPath) || !File.Exists(dbPath)) return null;
            object conn = CreateSqliteConnection(dbPath);
            if (conn == null) return null;
            try
            {
                var rows = ExecuteQuery(conn, dbPath, "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL AND url IS NOT NULL AND url != '' ORDER BY last_visit_date DESC LIMIT " + Math.Max(1, Math.Min(maxRows, 50000)));
                if (rows == null || rows.Count == 0) return null;
                var result = new List<Tuple<string, DateTime>>();
                var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                foreach (var row in rows)
                {
                    object urlObj; if (!row.TryGetValue("url", out urlObj) || urlObj == null) continue;
                    string url = urlObj.ToString();
                    if (string.IsNullOrEmpty(url)) continue;
                    object lvObj; row.TryGetValue("last_visit_date", out lvObj);
                    long microsec = 0;
                    if (lvObj != null && lvObj != DBNull.Value)
                    {
                        if (lvObj is long) microsec = (long)lvObj;
                        else if (lvObj is int) microsec = (int)lvObj;
                        else long.TryParse(lvObj.ToString(), out microsec);
                    }
                    DateTime dt = default(DateTime);
                    if (microsec > 0) dt = unixEpoch.AddTicks(microsec * 10).ToLocalTime();
                    result.Add(Tuple.Create(url, dt));
                }
                return result.Count > 0 ? result : null;
            }
            catch (Exception ex) { Logger.Warning("TryGetFirefoxHistory: " + (ex.Message ?? "")); return null; }
            finally { CloseConnection(conn, dbPath); }
        }

        #endregion
    }
}
