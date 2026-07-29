using System;

namespace IR_Collect
{
    /// <summary>
    /// 收集產出與平台收容使用的檔名／後綴常數，供 CaseManager、FactStore、MainForm、Collectors 共用。
    /// 更名時僅需修改此處，避免散落字串漏改。
    /// </summary>
    public static class ArtifactNames
    {
        public const string ProcessListCsv = "process_list.csv";
        public const string LogonSessionsCsv = "logon_sessions.csv";
        public const string NetworkResourcesCsv = "network_resources.csv";
        public const string ServerConnectionsCsv = "server_connections.csv";
        public const string StoredCredentialsTxt = "stored_credentials.txt";
        public const string KerberosTicketsTxt = "kerberos_tickets.txt";
        public const string AutorunsRegistryCsv = "autoruns_registry.csv";
        public const string ActivityTimelineCsv = "activity_timeline.csv";
        public const string UacAuthEventsCsv = "uac_auth_events.csv";
        public const string UacNetworkConnectionsCsv = "uac_network_connections.csv";
        public const string UacEvidenceIndexCsv = "uac_evidence_index.csv";
        public const string UacArchiveEntriesCsv = "uac_archive_entries.csv";
        public const string UacAccountsCsv = "uac_accounts.csv";
        public const string UacShellHistoryCsv = "uac_shell_history.csv";
        public const string UacPersistenceCsv = "uac_persistence.csv";
        public const string UacJournalFilesCsv = "uac_journal_files.csv";
        public const string UacBootSessionsCsv = "uac_boot_sessions.csv";
        public const string UacLoginEventsCsv = "uac_login_events.csv";
        public const string UacAuditEventsCsv = "uac_audit_events.csv";
        public const string UacSystemLogEventsCsv = "uac_system_log_events.csv";
        public const string UacPackagesCsv = "uac_packages.csv";
        public const string UacWebServerEventsCsv = "uac_web_server_events.csv";
        public const string UacFileHashesCsv = "uac_file_hashes.csv";
        public const string AnalysisWorkspaceManifestJson = "analysis_workspace_v1.json";
        public const string FactStoreDb = "fact_store.db";
        public const string SystemInfoTxt = "system_info.txt";
        public const string SystemInfoBasicTxt = "system_info_basic.txt";
        public const string SystemInfoFullTxt = "system_info_full.txt";
        public const string MftDumpBin = "MFT_Dump.bin";
        public const string MftPreviewCsv = "mft_preview.csv";
        public const string ScheduledTasksXml = "scheduled_tasks.xml";
        public const string ServicesCsv = "services.csv";
        public const string UsnJournalCsv = "usn_journal.csv";
        public const string Filesystem7DaysCsv = "filesystem_7days.csv";
        public const string InstalledSoftwareCsv = "installed_software.csv";
        public const string RecentFilesCsv = "recent_files.csv";
        public const string JumpListsCsv = "jump_lists.csv";
        public const string FileIntegrityCsv = "file_integrity.csv";
        public const string CollectionCoverageJson = "collection_coverage.json";
        /// <summary>External memory acquisition output folder (collection-only).</summary>
        public const string MemoryFolder = "Memory";
        /// <summary>Metadata JSON for memory acquisition run (tool, timing, hash, status).</summary>
        public const string MemoryAcquisitionJson = "memory_acquisition.json";
        /// <summary>External memory analysis handoff output folder (tool-generated sidecars, text, CSV, JSON).</summary>
        public const string MemoryAnalysisFolder = "MemoryAnalysis";
        /// <summary>Metadata JSON for external memory analysis handoff.</summary>
        public const string MemoryAnalysisJson = "memory_analysis.json";
        public const string AnalystWorkflowJsonSuffix = ".analyst.json";
        public const string BamDamCsv = "bam_dam.csv";
        public const string BitsJobsCsv = "bits_jobs.csv";
        public const string WmiPersistenceCsv = "wmi_persistence.csv";
        public const string ShimCacheCsv = "shimcache.csv";
        public const string AmcacheProgramsCsv = "amcache_programs.csv";
        public const string AmcacheFilesCsv = "amcache_files.csv";
        public const string ShimCacheEntriesCsv = "shimcache_entries.csv";
        public const string SrumNetworkUsageCsv = "srum_network_usage.csv";
        public const string SrumAppUsageCsv = "srum_app_usage.csv";
        public const string ExecutionArtifactsFolder = "ExecutionArtifacts";
        public const string AmcacheHive = "ExecutionArtifacts\\Amcache.hve";
        public const string SrumDb = "ExecutionArtifacts\\SRUDB.dat";
        public const string SrumLog = "ExecutionArtifacts\\SRUDB.log";
        public const string SrumJrs = "ExecutionArtifacts\\SRUDB.jrs";
        /// <summary>Event Log 篩選匯出 CSV 的檔名後綴；檔名格式為 LogLabel_filtered.csv。</summary>
        public const string EventLogFilteredSuffix = "_filtered.csv";
        /// <summary>用於 Directory.GetFiles 的 Event Log CSV 萬用字元。</summary>
        public const string EventLogFilteredGlob = "*_filtered.csv";
        /// <summary>Structured ShellBags rows produced from Registry\ShellBags_*.reg (UTF-8 CSV).</summary>
        public const string ShellBagsCsv = "shellbags.csv";

        /// <summary>判斷檔名是否為 Event Log 篩選 CSV（不區分大小寫）。</summary>
        public static bool IsEventLogFilteredCsv(string fileName)
        {
            return !string.IsNullOrEmpty(fileName) && fileName.EndsWith(EventLogFilteredSuffix, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>從 Event Log 篩選 CSV 檔名取得 log label（去掉 _filtered.csv）。</summary>
        public static string GetEventLogLabelFromFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return fileName;
            if (!fileName.EndsWith(EventLogFilteredSuffix, StringComparison.OrdinalIgnoreCase))
                return fileName;
            return fileName.Substring(0, fileName.Length - EventLogFilteredSuffix.Length);
        }

        public static bool IsBrowserHistoryMainArtifact(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return false;
            string name = fileName.Trim();
            if (name.EndsWith("-wal", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith("-shm", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith("-journal", StringComparison.OrdinalIgnoreCase))
                return false;
            return name.IndexOf("_History", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   name.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase);
        }
    }
}
