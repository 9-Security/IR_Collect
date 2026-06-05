# IR 收集項目與可行性評估 (Feasibility Map)

**最後更新**: 2026-04-09

根據您的需求清單，以下是針對本專案 (C# Portable Tool) 的實作評估。
符號說明：
- [v] **可實作 (Planned)**: 技術上可行，將列入開發計畫。
- [!] **部分實作/有挑戰 (Partial)**: 需考量權限、檔案大小或被防毒軟體攔截的風險。
- [x] **暫不實作 (Out of Scope)**: 因檔案過大或技術複雜度過高，不符合輕量級工具定位。

## 一、基本系統與環境資訊 (Baseline)
- [v] **主機名稱**: Hostname.
- [v] **使用者帳號**: 目前登入 User.
- [v] **作業系統版本**: OS Version, Build, Patch Level (WMI).
- [v] **系統時間**: Timezone, Current Time.
- [v] **開機時間**: Uptime.
- [v] **硬體資訊**: CPU, RAM, Disk 總量/剩餘 (WMI).
- [v] **網路介面設定**: IP, MAC, Gateway, DNS (WMI/NetworkInterface).

## 二、使用者與帳號活動 (User Activity)
- [v] **本機/網域帳號清單**: Local Users & Groups.
- [!] **最近登入紀錄**: 需解析 Event Log 4624/4625 (實作上只抓最近 N 筆).
- [v] **特權帳號**: Administrators Group 成員.
- [!] **RDP/SMB/VPN**: Event Log 仍是重要來源，但已另外補入 `logon_sessions.csv`、`network_resources.csv`、`server_connections.csv`、`stored_credentials.txt` (`cmdkey /list`) 與 `kerberos_tickets.txt` (`klist`) 等非 Event-Log 線索，可在弱日誌情境下保留部分身分與橫向移動可觀測性。
- [v] **ShellBags (資料夾檢視/路徑跡證)**: 匯出 `Registry\ShellBags_<SID>.reg`（BagMRU/Bags）；平台另自動產生 `Registry\shellbags.csv`（第一階段路徑片段／MRU／parser notes；Fact Store／Timeline／UI）。完整細節還原仍可用 Eric Zimmerman ShellBags Explorer 等外部工具。

## 三、行程與記憶體 (Process & Memory)
- [v] **執行中行程**: PID, Parent PID, Path, CommandLine (WMI/ManagementObjectSearcher).
- [v] **行程啟動時間**.
- [v] **雜湊值 (Hash)**: 計算執行檔 Hash (大於 50MB 略過).
- [v] **簽章驗證 (Signature)**: Process/Integrity CSV 加入簽章狀態與簽署者.
- [v] **行程擁有者 (User)**: process_list.csv 的 User 欄位已由 WMI Win32_Process.GetOwner 補齊（Domain\\User）；另含 PPID/SessionId/ThreadCount/WorkingSetSize。
- [!] **開啟的 Handles**: 需呼叫底層 API (NtQuerySystemInformation)，實作較複雜.
- [!] **記憶體映像 (Memory Dump) — 外部工具編排**: 本工具**不**內建採集驅動；可於 **Settings** 啟用後由 `MemoryAcquisitionCollector` 呼叫使用者指定之**外部**擷取程式，產出預設 `Memory\*.raw` / `*.dmp` 與根目錄 `memory_acquisition.json`（時戳、exit code、stdout/stderr 尾段、輸出檔大小與 SHA256、權限脈絡等）。若再啟用 **Memory analysis handoff**，`MemoryAnalysisCollector` 會把既有 dump 交給外部分析器，寫出 `memory_analysis.json` 與 `MemoryAnalysis\*` 工具輸出。兩者都只記錄 orchestration / sidecar / output accounting，**不**解析映像內容、**不**做惡意判決。映像仍可能為 GB 級，需自行評估時間與儲存空間。
- [x] **注入行為/隱藏行程**: 涉及 Rootkit 偵測，C# 實作困難且易被誤判為病毒.

## 四、檔案系統 (File System)
- [v] **MFT (Master File Table)**: 已實作 Raw Copy、run list 解析與強化解析 (MACB/路徑/大小).
- [v] **檔案雜湊**: 針對特定目錄 (如 Startup, Temp) 進行 Hash 计算.
- [v] **MACB 時間**: 透過 MFT 解析取得.
- [!] **已刪除檔案**: MFT 標記為 Deleted 的紀錄可讀取，但無法救援內容.
- [v] **特殊目錄清單**: Startup, Temp, Downloads, Prefetch 資料夾列表.

## 五、啟動與持久化機制 (Persistence)
- [v] **Registry Run/RunOnce**: `HKCU`, `HKLM` Run keys.
- [v] **Services**: 服務列表與設定 (WMI).
- [v] **Scheduled Tasks**: 計劃任務 (解析 XML 或 schtasks 輸出).
- [v] **Startup Folder**: 資料夾檔案列表.
- [!] **WMI Event Subscription**: 需 WMI 查詢 (較進階).
- [!] **Driver/Kernel**: 驅動程式列表.

## 六、系統與安全事件紀錄 (Event Logs)
- [v] **關鍵 Event Logs**: 預設同時匯出 Security, System, Application, PowerShell, TaskScheduler 等 log 的完整 `.evtx` 與分析用 filtered CSV；filtered CSV 另含 `Computer / UserId / TaskDisplayName / EventData` 結構化欄位。若匯入的是僅含 `.evtx` 的舊案卷，平台會離線重建對應 `*_filtered.csv`，避免 Facts / Timeline / Export 掉功能。
- [v] **事件重點摘要**: Summary 顯示常見 IR Event ID 統計與代表樣本（取樣）；樣本優先使用結構化欄位而非只看 message 文字。

## 七、網路與通訊行為 (Network)
- [v] **目前連線**: TCP/UDP Connection (IP:Port, PID).
- [v] **ARP/Routing Table**.
- [v] **DNS Cache**: `ipconfig /displaydns` 輸出.
- [x] **歷史連線/HTTPS紀錄**: 除非有流量錄製設備，否則主機端難以回溯歷史封包，僅能看 Log.

## 八、瀏覽器與使用者行為 (Browser)
- [v] **瀏覽器歷史/下載**: 複製 Chrome/Edge `History` SQLite 檔案 (需處理檔案鎖定問題).
- [!] **Cookie/Session**: 涉及隱私與加密 (DPAPI)，通常僅複製檔案不解密.

## 九、應用程式與第三方工具 (Applications)
- [v] **已安裝軟體**: Registry Uninstall Keys.
- [v] **最近安裝**: 依據 Timestamp 排序.

## 十、橫向移動與關聯證據 (Lateral Movement)
- [v] **SMB Sessions**: `net session`, `net use` 輸出；平台另會正規化 `network_resources.csv` 與 `server_connections.csv` 進入 Fact Store / Timeline，供後續跨主機 pivot。
- [v] **相同 Hash/IP 關聯**: 這是本專案 GUI 分析端的**核心功能** (Correlation Engine).
- [v] **時間軸關聯**: 主頁手動觸發 process/autoruns/tasks/MFT/event logs 時間窗關聯.
- [!] **Credential Dump 跡象**: 檢查 LSASS Process 是否有異常 Handle (難度高).

## 十一、證據完整性與鑑識紀錄 (Integrity)
- [v] **收集時間戳**.
- [v] **工具版本號**.
- [v] **雜湊驗證**: 打包 Zip 後計算 SHA256.
- [v] **執行紀錄**: 執行過程的 Log text.
- [v] **收集覆蓋率報告**: `collection_coverage.json` 會記錄 major artifact groups 的 `complete / partial / failed / skipped / missing` 狀態、缺失項，以及 `collector_user / collector_privilege_state / backup_privilege_status` runtime context，供 Summary / HTML / JSON 匯出使用。Event Logs 需逐 log 對上 `.evtx` 與 `*_filtered.csv` 才算 `complete`；若存在 `missing`，overall 亦會降為 `partial`。

## 十二、分析與事實層 (Analysis & Facts)
- [v] **Execution / Persistence Extensions**: `bam_dam.csv`、`bits_jobs.csv`、`wmi_persistence.csv`、`shimcache.csv`、`amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv` 會進入案卷；`ExecutionArtifacts\` 會保留 raw `Amcache.hve`、`SRUDB.dat`、`SRUDB.log`、`SRUDB.jrs` 等檔案，供後續離線深挖與交叉驗證。
- [v] **Fact Store / Entity Search / Investigation Workspace**: 以正規化後的 Fact 與 Entity 索引支援分析師查詢與交叉比對，不在工具內直接產生 heuristic/rule 結論；每筆 Fact 另保留 `TimeKind` / `TimeConfidence`，以及 `CollectionStep / CollectionStatus / CollectionPrivilege / ParseLevel / FallbackUsed / SourceFile / RawRef / ParserNote` provenance 欄位。除 Event Log 既有欄位外，亦納入 **Phase 3 lateral movement / identity** 相關結構化實體與 actions（Security/Credential/SMB/RDP 等 EventID，`SubjectUser` / `TargetUser` / `ShareName` / `RemoteIP` / Kerberos 票證欄位補註等，仍 facts-only），以及 `LogonSession`、`NetworkResource`、`ServerConnection`、`StoredCredential`、`KerberosTicketCache`、`Amcache`、`ShimCache`、`SRUM Network`、`SRUM App` 等來源。parser notes 不再只限於 Amcache，USN / ShimCache / Process / Event Log fallback 也會在 Summary/HTML/`summary.json`/`full_log_v3` 以 dedicated 摘要保留。平台另提供可關閉的 Guided Hunt overlay，以 ATT&CK-mapped、可解釋規則與 hypothesis templates 消費上述 facts，但不改寫 Fact Store。跨主機關聯含 investigation workspace（trail、pinned、selected edge、host scope、篩選快照）與 `Open Timeline` graph 脈絡交接；graph 開 Timeline 會先用 structured entity 聚焦，再在缺乏 entity ref 時退回文字比對，不新增非 facts 之判定欄位。
- [v] **USN Journal 分析路徑**: `usn_journal.csv` 不再只停留在獨立分頁，現在也會進入 Fact Store 與 Timeline；若原始輸出沒有完整路徑，仍可能只能以 `FileName` 層級關聯。
- [v] **Fact Store 快取新鮮度**: 案卷載入時會檢查 `fact_store.db` 是否比目前 source artifacts 舊；若 stale，會在 Summary / JSON / HTML 與 host 摘要標示 `fact_store_freshness_status/detail`。
- [v] **AI Entry**: Summary JSON 與完整 LOG JSON 匯出供 AI 分析（不外送原始資料）；Summary JSON 另帶 `export_schema=summary_v3`、`analysis_mode=facts_only`、`parser_notes`、`collection_coverage`、`fact_store_freshness_status/detail`、`analyst_workflow`、Fact source/entity type 統計與含 provenance 欄位的 fact samples。完整 LOG JSON 則為 `full_log_v3` envelope，含 host 摘要、workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要與完整 facts。

## Maintenance Notes (2026-03-06)
- No artifact schema changes in this update.
- GUI rendering for heavy artifact views is deferred until first open; output files and platform ingestion rules remain unchanged.
- Case import performance was improved internally by switching artifact discovery to a single recursive scan.
- **v0.17.2 Code Review**：程式穩定性與防呆（SafeInvoke、MftParser 邊界、大檔不載入、ProcessFile log）；無產出格式或收容規則變更。
