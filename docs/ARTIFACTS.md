# 9SEC Evidence Workbench 證據項目與可行性評估 (Artifact Feasibility Map)

**最後更新**: 2026-08-16

**對齊版本**: v0.25.1

以下是本專案目前已實作能力、部分能力與明確範圍外項目的對照；Windows live collection 與 UAC Linux/macOS evidence intake 都納入本表。
符號說明：
- [v] **已實作 (Implemented)**: 現行程式與案卷／分析管線已支援。
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
- [!] **Jump List 路徑還原**: 已將 bounded MS-SHLLINK byte-scan 結果寫入 `jump_lists.csv` 並串接 Fact Store／Timeline；目前對 JLECmd 差異驗證 path recall 為 140/172（81.4%）。因尚非完整 OLE-CFB parser，raw `.automaticDestinations-ms` / `.customDestinations-ms` 必須保留供深度分析。

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
- [v] **MFT (Master File Table)**: 已實作 Raw Copy、run list、MACB／路徑／大小，並會追蹤 resident `$ATTRIBUTE_LIST` 的 `$FILE_NAME` extension record 回收 Win32 長檔名。Non-resident attribute list 仍需保留 raw MFT 並以 MFTECmd 等外部工具交叉驗證。
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
- [v] **雜湊驗證**: 打包 Zip 後計算 SHA256；ZIP 與 sidecar 以同目錄 temporary file 完成後發布，相同 Evidence ID 的既有 output/ZIP/SHA 不覆寫。
- [v] **執行紀錄**: 執行過程的 Log text.
- [v] **收集覆蓋率報告**: `collection_coverage.json` 會記錄 major artifact groups 的 `complete / partial / failed / skipped / missing` 狀態、缺失項、`collector_user / collector_privilege_state / backup_privilege_status` runtime context，以及 `collection_mode_profile`、`operator_acknowledged_risks`、`restricted_steps`、`skipped_by_profile`、`output_target_class`，供 Summary / HTML / JSON 匯出使用。Event Logs 需逐 log 對上 `.evtx` 與 `*_filtered.csv` 才算 `complete`；若存在 `missing` 或 enabled step 因 profile 略過，overall 會降為 `partial`。`ForensicStrict` 預設略過已啟用的外部 memory acquisition / analysis handoff，阻擋 Deep Scan，並留下可稽核的 profile skip，而不是把略過誤記為成功收集。

## 十二、分析與事實層 (Analysis & Facts)
- [v] **Execution / Persistence Extensions**: `bam_dam.csv`、`bits_jobs.csv`、`wmi_persistence.csv`、`shimcache.csv`、`amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv` 會進入案卷；`ExecutionArtifacts\` 會保留 raw `Amcache.hve`、`SRUDB.dat`、`SRUDB.log`、`SRUDB.jrs` 等檔案，供後續離線深挖與交叉驗證。
- [v] **Fact Store / Entity Search / Investigation Workspace**: 以正規化後的 Fact 與 Entity 索引支援分析師查詢與交叉比對，不在工具內直接產生 heuristic/rule 結論；每筆 Fact 另保留 `TimeKind` / `TimeConfidence`，以及 `CollectionStep / CollectionStatus / CollectionPrivilege / ParseLevel / FallbackUsed / SourceFile / RawRef / ParserNote` provenance 欄位。除 Event Log 既有欄位外，亦納入 **Phase 3 lateral movement / identity** 相關結構化實體與 actions（Security/Credential/SMB/RDP 等 EventID，`SubjectUser` / `TargetUser` / `ShareName` / `RemoteIP` / Kerberos 票證欄位補註等，仍 facts-only），以及 `LogonSession`、`NetworkResource`、`ServerConnection`、`StoredCredential`、`KerberosTicketCache`、`Amcache`、`ShimCache`、`SRUM Network`、`SRUM App` 等來源。parser notes 不再只限於 Amcache，USN / ShimCache / Process / Event Log fallback 也會在 Summary/HTML/`summary.json`/`full_log_v3` 以 dedicated 摘要保留。平台另提供可關閉的 Guided Hunt overlay，以 ATT&CK-mapped、可解釋規則與 hypothesis templates 消費上述 facts，但不改寫 Fact Store。跨主機關聯含 investigation workspace（trail、pinned、selected edge、host scope、篩選快照）與 `Open Timeline` graph 脈絡交接；graph 開 Timeline 會先用 structured entity 聚焦，再在缺乏 entity ref 時退回文字比對，不新增非 facts 之判定欄位。
- [v] **USN Journal 分析路徑**: `usn_journal.csv` 不再只停留在獨立分頁，現在也會進入 Fact Store 與 Timeline；若原始輸出沒有完整路徑，仍可能只能以 `FileName` 層級關聯。
- [v] **Fact Store 快取新鮮度**: Evidence root 內預置的 `fact_store.db` 只列為 raw evidence，標示 `untrusted_source` 並由 source artifacts 重建；只有本次 analysis workspace 產生的 SQLite 參與 freshness 檢查。
- [v] **Fact Store 增量建置快取**: 可在 **Advanced → Settings** 選擇把 normalized facts 持久化於目前使用者的 Local Application Data（預設關閉）。Fact Store build 前重驗整體 evidence digest，並重新計算每個 normalizer input 的相對路徑、大小、mtime、SHA-256 與 normalizer 名稱；完全相符時 `Reused`，只有 filtered Event Log CSV 變更時 `Incremental`，其餘輸入變更、版本／設定不相容或快取損毀均明確回退 `Full`。此 gzip JSON 是可清除的內部效能快取，**不是證據 artifact、不是 source of truth，也不寫回證據根目錄**；可能含敏感 normalized facts。CSV 超過 100 MiB、500,000 列或讀取中斷會進入 Load warnings／export。`summary_v3` / `full_log_v3` host metadata 會保留 build mode、時間、原因與 input manifest。
- [v] **Case Diff / Baseline Diff**: 以兩案已正規化 Fact Store 的 category + primary entity 比較觀察狀態，輸出 Added / Modified / Removed 與雙側 fact references/provenance；case references 另帶 collection coverage 與 Fact Store freshness。GUI 可依類別、變更型態與來源篩選並跳回 Facts / Timeline；CLI `-diff <baseline> <target> [out.json]` 原子寫出 `diff_v1` JSON，最多 50,000 筆並以 `changes_truncated` 標示截斷。Added/Removed 只代表某一側未觀察到相同狀態；收集覆蓋差異仍須由分析師核對。
- [v] **AI Entry**: Summary JSON 與完整 LOG JSON 匯出供 AI 分析（不外送原始資料）；Summary JSON 另帶 `export_schema=summary_v3`、`analysis_mode=facts_only`、`parser_notes`、`collection_coverage`、`fact_store_freshness_status/detail`、`analyst_workflow`、Fact source/entity type 統計與含 provenance 欄位的 fact samples。完整 LOG JSON 則為 `full_log_v3` envelope，含 host 摘要、workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要與完整 facts。

- [v] **Archive intake safety**: 預設 hard cap 為 200,000 entries、單檔 300 GiB、總展開 750 GiB；展開量達 1 GiB 後壓縮比上限 1000:1，且保留至少 1 GiB 可用空間。ZIP 依 central directory 預掃，TAR.GZ 於串流 header 階段逐 entry 守門。解壓只寫同磁碟 `.partial-*` staging，完整成功才發布；失敗、取消、截斷與超限皆清理 staging。Canonical CSV、離線 Event Log CSV、SQLite、workflow、workspace manifest 與 CLI JSON 亦採同目錄 temporary file 原子發布，避免半成品被後續 normalizer 或分析師誤用。
- [v] **UAC evidence intake**: Folder、ZIP、TAR、TAR.GZ/TGZ 皆可由 GUI 與分析 CLI 直接收容。Archive intake 計算原始封裝 SHA-256、拒絕 path traversal，並以 `uac_archive_entries.csv` 保存原始 entry 到 Windows-safe 路徑的映射及 symlink/hardlink metadata。Folder/archive 的 evidence root 在分析期間維持唯讀；canonical、重建 Event Log、ShellBags、Fact Store 與預設分析報告寫入獨立 workspace，`analysis_workspace_v1.json` 保存 source digest、tool version 及衍生檔 SHA-256。UAC 來源中預置的 canonical 同名檔只作 raw evidence，不會壓過本次重新解析的結果。逐檔 SHA-256、分類與解析狀態寫入 workspace 的 `uac_evidence_index.csv`；所有索引列進入 `UacEvidence` facts。可解析來源另衍生 `system_info.txt`、`process_list.csv`、`activity_timeline.csv`、`uac_auth_events.csv`、`uac_network_connections.csv`、`uac_accounts.csv`、`uac_packages.csv`、`uac_web_server_events.csv`、`uac_file_hashes.csv`、`uac_shell_history.csv`、`uac_persistence.csv`、`uac_journal_files.csv`、`uac_boot_sessions.csv`、`uac_login_events.csv`、`uac_audit_events.csv`、`uac_system_log_events.csv`。Web server events 支援 plain/gzip Apache/nginx Common/Combined access 與預設 error envelope，保存 remote、HTTP request/response context、severity/PID 及來源行號；access numeric offset 可形成 event time，預設 error local time不虛構 UTC。每案最多 50,000 列、每檔最多解碼 268,435,456 字元、每行上限 1,048,576 字元；canonical 截斷保留 marker。Remote/header 值可能受 proxy/client 控制，status 不等於惡意 verdict；自訂 JSON、ModSecurity/Tomcat 等不支援格式保留 raw。Package inventory 支援 dpkg、RPM query/queryformat、DNF/YUM、pacman、apk、Flatpak、Snap 與 macOS Homebrew command outputs，保存 state/scope/publisher 及原始來源行號；RPM epoch 可形成 install metadata time，其他來源只在 UAC log 含可靠 offset 時以 acquisition reference time 形成低信心 observation，並非 row-level command time。每案最多 50,000 列、來源檔上限 64 MiB、行上限 65,536 字元；canonical 欄位截斷會留下 marker，原始檔不改寫。套件存在不證明近期安裝、執行或惡意。File-hash intake 支援 UAC `hash_executables` 與 `hash_running_processes` 的 MD5/SHA-1/SHA-256 checksum-path / named-digest 輸出，最多 250,000 列、64 個來源檔、單檔 512 MiB、單行 65,536 字元；來源路徑、演算法與 hash 進入 Fact Store 供 IOC／跨主機 pivot，沒有可靠 row timestamp，且 hash observation 不證明執行或惡意。System log events 支援 plain/gzip RFC 3164、RFC 5424 與 ISO timestamp，每案最多 50,000 列、每檔最多解碼 268,435,456 個字元、canonical message 最多 4,096 個字元；原始證據不被改寫。缺少年份或 numeric offset 時只保留 raw time，不虛構 UTC；每列只代表 message observed，不宣稱成功或惡意。`auth.log` / `secure` 僅交由 auth parser，避免重複 facts。Audit events 支援 `/var/log/audit/audit.log*` plain/gzip，依 `audit(epoch:serial)` 合併 compound records，保留 raw syscall、來源路徑/行號及 grouping boundary，不宣稱 audit/AVC record 本身為惡意。Login events 支援 UAC `last` / `lastb` / `lastlog` / `utmpdump` 文字輸出；只有來源含可靠 numeric offset 才填入 UTC，其他時間保留 raw 並標示解析狀態。Persistence 支援 cron/anacron、systemd service/timer、`rc.local`、`ld.so.preload`、SSH `authorized_keys` 與 XML/binary launchd plist；完整 SSH public key 不複製到 canonical CSV，只保存 SHA-256 fingerprint。Native journal 僅解析固定 header metadata，boot range 來自 `journalctl --list-boots`；逐筆 journal entry、損壞/不支援 plist、browser DB 等仍完整保留並標示 `indexed-raw`，不宣稱已解析；加密 ZIP 不支援。

- [v] **UAC file-hash facts**: `uac_file_hashes.csv` 正規化 UAC `hash_executables.{md5,sha1,sha256}` 與 `hash_running_processes.{md5,sha1,sha256}`，欄位為 `Algorithm / Hash / Path / SourceKind / SourcePath / LineNumber / InputFormat`。支援 checksum-path 與 named-digest envelope，最多 250,000 列、64 個來源檔、單檔 512 MiB、單行 65,536 字元；不合格式或超限資料仍保留 raw 並在 load warnings 顯示。`UacFileHash` facts 使用 `Hash / Path / HashAlgorithm` entities，時間維持 unknown/low confidence，不宣稱執行或惡意性。

## 文件維護狀態 (Document Maintenance)
- 本表對齊 `v0.25.1` 的 collector、UAC intake、ArtifactNames、CaseManager discovery、Fact Store 與輸出 schema；歷史版本差異見 `CHANGELOG.md`。
- 新增 collected artifact 時，必須同步 platform intake、案卷 discovery、適用的 UI/file-list 與 normalizer/export 管線；無法同次完成時需在規格 backlog 明列，不得留下孤兒產物。
- 表中 `[v]` 只代表程式已實作，不代表每次收集都完整成功；實案仍須以 `collection_coverage.json`、load warnings、parser notes 與原始證據核對。
