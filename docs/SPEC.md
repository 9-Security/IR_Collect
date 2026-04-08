# IR Collector 開發規格手冊 (Development Specification)

**專案名稱**: IR_Collect
**版本**: v0.21.0
**最後更新時間**: 2026-04-08
**開發者**: Antigravity (collaborating with User)

---

## 1. 專案概述 (Project Overview)
本專案為一個輕量級、可攜帶 (Portable) 的 Windows 事件回應 (Incident Response) 資訊收集與分析平台。除具備單機證據收集能力外，亦內建簡易的分析儀表板，支援多主機關聯分析。

### 核心設計原則
- **Portable**: 單一執行檔 (.exe)，無需安裝，依賴最少 (僅需 .NET Framework 4.5+)。
- **Hybrid Mode**: 同時支援 CLI (自動化派送收集) 與 GUI (分析與檢視)。
- **Forensic Soundness**: 使用原生 API 與標準工具 (schtasks, netstat, wmic) 收集，盡量減少對系統的改動。僅讀取／匯出登錄、事件日誌、MFT 與檔案，不刪改原始資料；惟輸出目錄若在受調查磁碟上會寫入新資料，建議將輸出寫至外接磁碟以降低對現場的影響。詳見 README「DFIR 現場保護」。
- **Encoding Safety**: 強制所有收集指令與檔案輸出使用 UTF-8 (No BOM)，確保跨語系分析時無亂碼。
- **Settings 集中管理**: 所有可讓使用者調整的設定，一律規劃並實作於 **Settings** 對話框 (Advanced → Settings)，由 `ConfigManager` 讀寫並寫入 config.ini；不新增僅能透過手動編輯 config.ini 的選項。

---

## 2. 版本歷程 (Version History)

| 版本 | 日期 | 變更類型 | 變更內容摘要 |
| :--- | :--- | :--- | :--- |
| **v0.21.0** | 2026-04-08 | **Hardening + Feature** | **Memory Analysis Handoff + Endpoint Gate**：新增 `MemoryAnalysisCollector`、`memory_analysis.json`、`MemoryAnalysis\*` 外部分析器輸出編排與 `collection_coverage.json` 的 **Memory analysis handoff** 步驟；Summary / HTML / `summary.json` / `full_log_v3` host 摘要可見 `memory_analysis`。另新增 `run_endpoint_gate.bat` 串起 `run_review_regression.bat` 與正式 `build.bat`，並擴充 `IRCollectSelfTests` 覆蓋 memory-analysis coverage / export regression。其後 acceptance hardening 進一步補強：Event Logs coverage 改為 EVTX 與 filtered CSV 逐 log parity、Summary/HTML/`summary.json` 統一顯示跨來源 parser notes 與 Memory `Coverage / Sidecar`、graph→Timeline 改為 structured entity match + 分鐘級時間窗。 |
| **v0.20.1** | 2026-04-08 | **Feature** | **Memory acquisition（collection-only）**：Settings/config 可開關並設定外部工具路徑、參數（`{OutputPath}` / `{OutputDir}`）、輸出檔名、逾時秒數、未提高權限時略過、RequiresAdmin（僅寫入 sidecar）。收集於 Unified Timeline 之後執行：輸出限 `Memory\` 下，寫 `memory_acquisition.json`；`collection_coverage.json` 新增 Memory 步驟及 `skipped_steps` / `missing_steps`；案卷收容 `.raw`/`.dmp`/`memory_acquisition.json`；Summary / HTML / `summary.json` / `full_log_v3` 帶 `memory_acquisition`。無內建記憶體採集驅動、無映像解析、無 Volatility/Rekall。 |
| **v0.20.0** | 2026-04-08 | **Feature** | **Phase 3 Lateral Movement & Identity Abuse Pack（facts-only）**：`EventLogNormalizer` 深化 Security / TerminalServices 等高價值事件之結構化實體與行為語意（含 4624–4625、4648、4672、4768–4769、4776、5140–5145、1149、4688、4697、4698/4702、7045 等）；標準化 actions（如 `ExplicitCredentialUsed`、`KerberosTgtRequested`、`ShareAccessChecked`、`RemoteDesktopAuthenticated`、`NtlmCredentialValidated` 等）。新增 / 強化實體類型：`SubjectUser`、`TargetUser`、`ShareName`、`ShareLocalPath`、`Workstation`、`TargetServer`、`RemotePort` 等以利跨主機 Pivot / Graph / Timeline；`5145` 之 `RelativeTargetName` 改以 `Path` 呈現而非誤標為 `ShareLocalPath`。Summary 事件亮點擴充對應 EventID。手動驗證用 fixture：`scripts/phase3_lateral_movement_fixture.csv`。 |
| **v0.19.1** | 2026-04-08 | **Fix** | **Phase 2 Investigation Workspace（狀態與下鑽）**：重建 graph 或 Back / Forward / Reset 時清除並驗證 selected edge，避免 stale `Current edge hosts` 悄悄限制下一輪結果；trail 上每一步儲存 correlation 篩選與 host scope 快照，導覽時先還原 UI 再重算 graph。`Open Timeline` 帶入 graph edge 之 entity 類型／顯示值、investigation trail，並可套用 edge 的 First/Last seen 近似時間窗與 Description/Type 文字篩選；Timeline 分頁顯示提示列與「Show full timeline」返回完整檢視。 |
| **v0.19.0** | 2026-04-08 | **Feature** | **Phase 2 Investigation Graph Workspace（第一階段）**：新增 `InvestigationWorkspaceState`，支援 seed trail、selected edge、pinned entities、host scope（all/edge hosts/host filter）與 result mode。Dashboard graph workflow 新增 `Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`、`Pin Edge`、`Open Facts`、`Open Timeline`，可從同一調查脈絡連續展開，不再是一次性 graph 查詢。 |
| **v0.18.9** | 2026-04-08 | **Fix** | **Phase 1 final polish**：Amcache parser/fallback notes 於 Summary/HTML/`summary.json`/`full_log_v3` 新增 dedicated summary，避免因 fact sample 截斷或 `DateTime.MinValue` 排序而隱藏；另修正 Amcache parser notes 去重（collector 僅保留單一路徑輸出，normalizer 端再做 note-level dedup）避免重複 `ParseNoteObserved` facts。 |
| **v0.18.8** | 2026-04-08 | **Fix** | **Phase 1 gap fixes**：Amcache parser note 不再在 normalizer 遺失，會轉為 `ParseNoteObserved` facts 並保留 provenance；`ProgramName` 改為獨立 entity type（不再混入 `FileName`）；Correlation `Source` filter 補齊 `Amcache`、`ShimCache`、`SRUMNetwork`、`SRUMApp`。 |
| **v0.18.7** | 2026-04-08 | **Feature** | **Phase 1 Execution/Persistence 結構化解析**：新增 `amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv`。新增 `Amcache/ShimCache/SRUM` normalizer 並接入 Fact Store、Timeline、Entity search、Summary/HTML/summary.json/full_log_v3；保留 raw `ExecutionArtifacts\Amcache.hve`、`SRUDB.dat` 不替代。 |
| **v0.17.9** | 2026-03-06 | **UX & Doc** | **Settings 補齊**：AI/Upload 端點與 Key、EventLogDays/EventLogMaxEvents、DeleteOutputDirAfterZip 納入對話框。**Activity Timeline 日期防呆**：From/To MinDate/MaxDate 1980–2100；From > To 時自動對調並提示。About/AssemblyInfo 0.17.8。 |
| **v0.17.8** | 2026-03-06 | **Security** | **VirusTotal**：hash 僅允許 32/64 字元十六進位。**MFT**：磁碟代號強制單一 A–Z（NormalizeDriveLetter、RawDiskReader）。**設定匯出**：拒絕寫入系統目錄（IsPathSafeForExport）、Export 回傳 bool。**規則引擎**：Regex 逾時 2 秒防 ReDoS（SafeRegexIsMatch）。SECURITY.md v1.1、README 設定檔說明。 |
| **v0.18.6** | 2026-03-13 | **UX Fix** | **Event Log**：可拉伸線改為「資訊區｜Per page」之間（Panel1=表格、Panel2=Per page+Event detail）。**MFT View**：Path/Max size 標籤完整顯示。見 CHANGELOG 0.18.6。 |
| **v0.18.5** | 2026-03-13 | **UX Fix** | **Event Logs**：Event ID/Source 標籤顯示完整、輸入與右側控制項右移。**Event detail**：資訊區可拉伸、垂直捲軸。**MFT View**：標籤 Path/Min size/Max size、AutoScroll 使 Apply/Reset 可見。見 CHANGELOG 0.18.5。 |
| **v0.18.4** | 2026-03-13 | **UX Fix** | **Dashboard**：Correlation/Export 圖示並排、Entity search 間隔。**Timeline**：Source/From/To/Per page 不裁切、間隔剛好。**MFT View**：Path/Min/Max 間隔、篩選 Refresh。**Event Log**：Event ID/Source/User/Contains 不遮、搜尋正常。**Event detail View**：View 不遮選單、選項無 "View:" 前綴。見 CHANGELOG 0.18.4。 |
| **v0.18.3** | 2026-03-13 | **UX Fix** | **Timeline**：From/To/Source 標籤與日期框間距、Source 字不異常。**Per page**：標籤不遮下拉、分頁列右移。**MFT View**：Path 間距與長度、Min/Max 間距、篩選 Refresh 生效。見 CHANGELOG 0.18.3。 |
| **v0.18.2** | 2026-03-12 | **UX Fix** | **Recent Files**：僅 LNK、排除 desktop.ini/Thumbs.db。**Lnk Dump**：先複製 .lnk 再寫 CSV 避免 Dump 為空。**MFT View**：TableLayoutPanel、Path/Min/Max 不遮、Min/Max 防呆與 Invalidate。**Timeline**：Source/From 間距、CSV/JSON 按鈕對齊。**USN Journal**：篩選區 Dock Top、Reset/Exclude 寬度與不裁切。見 CHANGELOG 0.18.2。 |
| **v0.18.1** | 2026-03-12 | **Refactor & Encoding** | **ArtifactNames**：產出檔名集中為常數類，CaseManager/FactStore/MainForm/RuleEngine/Collectors/Normalizers 共用。**讀取 UTF-8**：本工具產出之 CSV/XML/txt 讀取優先 UTF-8。**Logger**：log 檔寫入改 UTF-8 no BOM。**空 catch**：關鍵路徑改為 Logger.Warning。見 CHANGELOG 0.18.1。 |
| **v0.18** | 2026-03-12 | **UI & UX** | **Dashboard**：移除說明文字（尚無案卷/建議以系統管理員/建議流程）；按鈕統一 300×50、移除 Build Fact Store 與 Clear Fact Store 按鈕；結果表右/下留白 24px、最後欄 -2 填滿。**Fact Store**：Auto Build 預設勾選；Clear 改 **File → Clear all hosts**。見 CHANGELOG 0.18.0。 |
| **v0.17.7** | 2026-03-06 | **Doc** | **安全性**：新增 docs/SECURITY.md 潛在風險檢測報告（輸入/路徑/敏感資料/命令/UI/規則/鑑識）；README 文件表加入 SECURITY.md 連結。 |
| **v0.17.6** | 2026-03-06 | **Fix & Doc** | **CommandHelper**：新增 `EscapeArgForCmd`，reg export/save 路徑跳脫。**Smoke run**：docs/SMOKE_RUN.md。**Code Review 結案**：DeferredTab SafeInvoke、FirstOrDefault、3 處 catch、Directory 列舉上限、一處 ToList 移除。 |
| **v0.17.5** | 2026-03-06 | **UX** | **分頁列**：移至表格下方（Dock Bottom）。**USN 篩選**：單行 Contains→輸入→then Exclude→[+][Reset]，按 [+] 該列改 [-] 並新增下一列；篩選區可拖曳分隔線調整、依條件列數自動增高，預設僅一行高度。**延遲分頁**：首次顯示時 PerformLayout 避免篩選區裁切。 |
| **v0.17.4** | 2026-03-06 | **UX** | **LOG 分頁**：USN Journal、Activity Timeline、Event Log、Processes（及所有 BuildCsvTabFromData 之 CSV 分頁）、Timeline Analysis 五類，筆數超過 500 自動顯示分頁列；每頁筆數可選 150/200/250/300（預設 150）；顯示「Page X of Y」、Prev/Next、Go to 頁碼輸入。 |
| **v0.17.3** | 2026-03-06 | **Fix & UX** | **分頁**：CSV/USN 背景載入、DoubleBuffered、SuspendLayout 減輕卡頓。**USN 篩選**：Contains→then Exclude→[-] 樣式、功能鍵集中（Reset, Apply, Add）、移除 Remove、固定高度不遮欄位名。 |
| **v0.17.2** | 2026-03-06 | **Fix (Code Review)** | **穩定性**：SafeInvoke 避免背景回調 Invoke 時表單已 Dispose 崩潰；**MftParser** 屬性長度與緩衝區邊界檢查；**大檔防呆**：USN/Activity Timeline >100MB 不載入；ProcessFile 空 catch 改 Logger.Warning。 |
| **v0.17** | 2026-03-06 | **Feature & Fix** | **BrowsingHistoryView**：Chrome History 以 SQLite 查詢，新增「Last visit」欄位。**Jump Lists**：依 MS-SHLLINK 解析 LNK 結構擷取 LocalBasePath，減少 Path 為空。**Temp 自動清理**：關閉程式與 Clear Host Data 時刪除 %TEMP% 解壓目錄。**UI**：Event Log View 改 ToolStripDropDown 防遮擋；Event Log 分頁背景載入防沒有回應；CSV/USN 表格欄位 NotSortable 防連點卡頓。 |
| **v0.16** | 2026-03-06 | **Fix** | **Dashboard/分析邏輯**：Find Common Artifacts（FindCommonFiles 防 null MftEntries、Hostname 顯示；無 host 提示）；Find Timeline Correlation（e.Host/ExtractPath/Artifacts 防呆、無 host 提示）；Build Fact Store 建置中停用 Export/Clear 按鈕防 race；RunCorrelation 每次重設三欄欄位；Entity Search / Export full LOG JSON 無 host 提示。 |
| **v0.15** | 2026-03-06 | **Tech Debt** | **TD-01**：`MainForm.cs` 再拆兩個 partial class：`MainFormVisualization.cs`（System Info / IP Config / Connections / ARP / DNS 視覺化分頁）與 `MainFormTimeline.cs`（`TimelineEvent` 類別、`BuildTimelineEvents`、`CreateTimelineTab`）；`MainForm.cs` 從 3309 行縮至 **2865 行**（原始 4028 行共減少 **1163 行**）。**TD-02**：`CorrelationCsvHelper.SplitCsvLine` 改為委派 `CsvUtils.SplitLine`，全專案 CSV 解析統一使用同一實作，並順帶修正原版不處理 escaped quote（`""`）的 bug。 |
| **v0.14** | 2026-03-06 | **Refactor & Fix (Code Review)** | **架構**：`ConfigManager` 統一使用 `BaseDirectory`（`LogCollector`/`CaseManager` 不再直接讀 config.ini）；`CaseManager.LoadedCases` 改為執行緒安全快照屬性；`MainForm.cs` 拆成 4 個 partial class 檔（`MainFormAnalysis.cs`、`MainFormCollection.cs`、`MainFormSettings.cs`）。**邏輯修正**：`CollectFiltered` 失敗時實際執行 full evtx fallback；`FactStore.BuildFromCase` MFT 上限改從 ConfigManager 讀取；WMI `GetOwner` outParams 加 `Dispose`。**效能**：SQLite Reflection `MethodInfo` 靜態快取；`ir_rules.json` 合併為一次讀取並加修改時間快取。**Code Quality**：`EscapeCsv`/`SplitCsvLine` 集中至 `Utils/CsvUtils.cs`；移除 `PngToIco.cs`/`ImgToIco.cs` 殘留；`MftParser.fileSize` sentinel 改 0；`ConfigManager.Save` 改 no-BOM UTF-8；全域移除 `ex != null ?` 冗余防衛；`MftParser` 靜默 catch 改記錄 Logger。 |
| **v0.13** | 2026-02-10 | **Fix & Release** | **安全性**：Zip Slip 改為 ExtractZipSafely；GetArtifactPath/FindArtifactPath 路徑驗證；CleanupAll null 檢查；DragDrop 安全；FillGridFromCsv 欄數 pad；VT URL 僅 https。**收集**：打包後預設刪除暫存目錄（config DeleteOutputDirAfterZip）；Recent Files 排除 AutomaticDestinations/CustomDestinations；Recent Mod (7d) 不跟隨 junction/symlink。**UI**：分頁改名 MFT View、BrowsingHistoryView、Registry exports；USN Journal 跳過 metadata 顯示 CSV 表格。 |
| **v0.12** | 2026-02-10 | **Fix & Improve** | **MFT 從 GUI 收集必失敗**：修正 `Console.OutputEncoding` 在無主控台時拋錯，改為 try-catch 略過；MFT Browser 無資料時顯示說明。**收集部分失敗**：UserActivity 拒絕存取/路徑太長改彙總計數並減少 log；Prefetch 略過時寫入 log；Registry 啟用 SeBackupPrivilege + System hives X/4 摘要；Event Log 失敗重試一次 + 成功/失敗摘要。README 新增 DFIR 現場保護、收集失敗處理說明。 |
| **v0.11** | 2026-02-10 | **Feature & Fix** | **Phase B3**：Fact Store 可選寫入 SQLite（Settings）、Export full LOG JSON（DateTime 正規化避免序列化錯誤）；**Auto Build Fact Store** 選項；Build 防呆（已有資料不覆寫）+ **Clear Fact Store** 按鈕；Build Fact Store 改背景執行、FactStore 索引改 HashSet 與 AddRange 效能優化；Process User 文件標為完成。 |
| **v0.10** | 2026-02-09 | **Feature** | **Correlation 事實層 (Fact Store)**：Fact/EntityRef、Process/Autorun/ActivityTimeline/MFT/ScheduledTask/EventLog Normalizer；Build Fact Store (all hosts)、Entity search (Path/Hash/User/RegistryKey/Provider/EventId)；correlation_rules 跨來源（Source 前綴匹配）；Timeline 納入 EventLog、Export CSV/JSON；Event Log 詳情 View: Description｜Parsed fields｜Raw XML；Summary 匯出 HTML Report；Event Log 收集可選篩選模式 (config.ini)；Logger；ZipFile 取代 PowerShell 壓縮/解壓。 |
| **v0.9** | 2026-02-09 | **Doc & Polish** | 文件與程式碼狀態同步。MFT 使用動態系統碟；mft_preview 含完整 MACB；process_list 含 CommandLine/Hash/Signature/User（WMI GetOwner）、PPID/SessionId/ThreadCount/WorkingSetSize。 |
| **v0.8** | 2026-01-25 | **Feature** | 新增 **Timeline Analysis (時間軸分析)** 分頁。整合 Process StartTime 與 MFT (Created/Modified) 事件，提供單一時間軸視圖，協助重建攻擊路徑。 |
| **v0.7.1** | 2026-01-24 | **Feature** | 新增設定管理 (`ConfigManager.cs`) 支援 VirusTotal/AI API Key 儲存。Advanced 選單新增設定/匯入/匯出功能。主機列表與資料表格新增右鍵選單 (Clear, Summary, Copy, VT Query)。修復部分 UI 邏輯重複與 C# 5.0 相容性問題。 |
| **v0.7** | 2026-01-24 | **UI & Build** | 新增 MenuStrip 功能表列 (File, Advanced, Help)。側邊欄優化 (收合按鈕、寬度調整、Dashboard 分離)。實作 System Info/Network 等純文字檔案的自動解析與視覺化 (Grid/TreeView)。MFT 瀏覽器升級為 Virtual Mode 以支援大數據。建置腳本新增自動簽章 (Self-Signed) 功能。 |
| **v0.6** | 2026-01-23 | **Fix & UX** | 解決亂碼問題 (`chcp 65001`)。GUI 改為**動態分頁 (Dynamic Host Tabs)** 架構。Scheduled Tasks 改為 XML 收集與解析 (含 Command/Args 欄位拆分)。介面字體放大優化。 |
| **v0.5** | 2026-01-22 | **Feature** | 新增全面收集模組，包括 Process, Network, Registry (Autoruns), Services, Scheduled Tasks, Event Logs。實作自動驗證測試。 |
| **v0.4** | 2026-01-22 | **GUI/UX** | GUI 全面翻新。新增儀表板 (Dashboard)、雙欄式佈局、非同步收集 (Async)、多檔拖曳匯入 (Drag & Drop)。 |
| **v0.3** | 2026-01-22 | **Feature** | 新增「多主機分析」與「關聯引擎 (Correlation Engine)」。實作 CaseManager，可同時載入多個 ZIP 案卷並尋找跨主機的共同檔案。 |
| **v0.2** | 2026-01-22 | **Feature** | 新增 MFT 收集功能。實作 `RawDiskReader` 直接讀取磁區匯出 `$MFT`，並包含簡易 Parser 產出預覽 CSV。 |
| **v0.1** | 2026-01-22 | **Init** | 專案初始化。建立 C# Solution 結構，實作與 `build.bat` 編譯腳本，確立 GUI/CLI 雙模式架構。 |

---

## 3. 功能規格說明 (Functional Specifications)

### 3.1 收集端 (Collector Engine)
收集端透過 `SystemCollector`, `PersistenceCollector`, `LogCollector` 等靜態類別實作。
**關鍵機制**: `CommandHelper` 類別確保所有 `cmd /c` 指令執行前先執行 `chcp 65001`，且寫入檔案時明確指定 UTF-8 Encoding (無 BOM)。

#### A. 系統與揮發性資訊 (System & Volatile)
- **收集器**: `src\Collectors\SystemCollector.cs`
- **產出檔案**:
    - `system_info_basic.txt`: Hostname, OS Version.
    - `system_info_full.txt`: 完整 `systeminfo` 輸出。
    - `process_list.csv`: 執行中程序列表 (PID, Name, Path, CommandLine, StartTime, SignatureStatus, Signer)。
    - `network_connections.txt`: `netstat -ano` 輸出。
    - `dns_cache.txt`: `ipconfig /displaydns` 輸出。

#### B. 持久化機制 (Persistence)
- **收集器**: `src\Collectors\PersistenceCollector.cs`
- **產出檔案**:
    - `autoruns_registry.csv`: 掃描 `HKLM/HKCU` 的 `Run`, `RunOnce` 以及 `Winlogon` 機碼。
    - `services.csv`: 透過 WMIC 匯出服務清單 (Name, DisplayName, PathName, State, StartMode)。
    - `scheduled_tasks.xml`: 透過 `schtasks /query /xml` 匯出排程任務 (URI, Actions, Triggers, Principal)。

#### C. 登錄與 ShellBags (Registry Hives & ShellBags)
- **收集器**: `src\Collectors\RegistryCollector.cs`
- **產出**:
    - `Registry\*.hiv`: 以 `reg save` 匯出系統 Hive（SYSTEM, SOFTWARE, SAM, SECURITY）及每位使用者的 NTUSER、UsrClass。
    - `Registry\ShellBags_<SID>.reg`: 每位使用者之 Shell（BagMRU/Bags）子樹匯出為 .reg，供 ShellBags 解析工具使用；內含使用者曾開啟的資料夾路徑跡證（含本機、網路、USB 等）。
- **ShellBags 解析**：本工具僅負責收集。還原路徑與時間請使用外部工具，例如 [Eric Zimmerman ShellBags Explorer](https://github.com/EricZimmerman/ShellBags) — 可載入案卷內 `Registry\ShellBags_<SID>.reg` 或 `Registry\UsrClass_<SID>.dat`（需先掛載 Hive 或使用支援離線解析的工具）。

#### D. 事件日誌 (Event Logs)
- **收集器**: `src\Collectors\LogCollector.cs`
- **機制**:
  - **預設雙輸出**: 呼叫 `wevtutil epl` 匯出原始 `.evtx` 檔，並額外使用 `EventLogReader` 產出分析用 `EventLogs\*_filtered.csv`。
  - **分析窗設定**: `config.ini` 的 `EventLogDays=0` 表示使用預設 7 天 filtered CSV 視窗；`EventLogDays>0` 為自訂天數。`EventLogMaxEvents` 控制每個 log 的 filtered CSV 上限。
  - **離線重建**: 若載入的案卷只有 `.evtx` 而缺少 `*_filtered.csv`，`CaseManager` 會在匯入時以離線模式重建 filtered CSV；重建時以各 EVTX 內最新事件時間為分析窗結束點，回推 `EventLogDays` 指定的天數，避免舊案卷因「現在時間」而被錯誤篩空。
- **收集範圍**: System, Security, Application, PowerShell, TaskScheduler, RDP, Defender, SMB 等。

#### E. 使用者與瀏覽器活動 (User & Browser)
- **收集器**: `src\Collectors\UserActivityCollector.cs`, `src\Collectors\BrowserCollector.cs`
- **機制**:
    - **Recent Files**: 遞迴掃描 `%APPDATA%\Microsoft\Windows\Recent` 產出 `recent_files.csv` (含 LNK 檔案名稱與時間)。
    - **Browser History**: 複製 Chrome, Edge, Firefox 的 `History` / `places.sqlite` 檔案至 `Browsers/` 目錄。

#### F. 檔案系統跡證 (File System)
- **收集器**: `src\MFT\MftDumper.cs`
- **機制**:
    - 使用 `CreateFile` 開啟 **動態系統碟**（`Path.GetPathRoot(Environment.SystemDirectory)`，如 `\\.\C:`）物理磁碟或 `\\.\X:\$MFT` (需 Admin)。
    - 匯出為 `MFT_Dump.bin`。
    - 支援 `$MFT` run list 解析以處理碎片化 MFT。
    - 自動解析前 5000 筆紀錄為 `mft_preview.csv`（包含 Standard 與 FileName MACB、大小與完整路徑）。載入 Case 時，MFT 筆數由 **Settings** 內 **MFT max entries** 控制（預設 100000，上限 500000，對應 config.ini 的 MftMaxEntries），binary 與 CSV 後備皆套用，以降低大 MFT 記憶體使用。
    - 透過 `fsutil usn readjournal` 產出 `usn_journal.csv`。

#### G. 活動彙整 (Activity Timeline)
- **收集器**: `src\Collectors\RegistryActivityCollector.cs`, `src\Collectors\JumpListsCollector.cs`, `src\Collectors\ActivityTimelineBuilder.cs`
- **來源**: UserAssist / RunMRU / RecentDocs / Jump Lists / Prefetch / Recent Files / Process
- **產出**: `activity_timeline.csv`（統一時間軸，整合所有活動來源）

#### H. 記憶體採集編排 (Memory acquisition, external tool)
- **收集器**: `src\Collectors\MemoryAcquisitionCollector.cs`（由 `Collector.RunCollectionDetailed` 於建立 `activity_timeline.csv` 之後、`collection_coverage.json` 之前呼叫）
- **設定**: `config.ini` / **Advanced → Settings** — `MemoryAcquireEnabled`, `MemoryAcquireToolPath`, `MemoryAcquireToolArgs`（`{OutputPath}`、`{OutputDir}`）、`MemoryAcquireOutputName`, `MemoryAcquireTimeoutSec`, `MemoryAcquireRequiresAdmin`（僅記錄於 sidecar）, `MemoryAcquireSkipIfNotElevated`
- **產出**: 根目錄 `memory_acquisition.json`；可選 `Memory\` 下由外部工具寫入之 `.raw` / `.dmp`
- **執行模型**: 重新導向之 stdout/stderr 於子行程存續期間以背景執行緒並行讀取至串流結束，避免管線緩衝區塞滿造成假性阻塞／逾時；側錄仍以尾段摘要寫入 sidecar。
- **Coverage**: `collection_coverage.json` 之 Memory 步驟若偵測 sidecar 狀態為 `complete` 但預期 dump 路徑上檔案不存在，覆寫為 `failed` 並加註 `[Coverage]` 說明，避免顯示誤導性「成功」。

#### I. 記憶體分析交接 (Memory analysis handoff, external tool)
- **收集器**: `src\Collectors\MemoryAnalysisCollector.cs`（於 `MemoryAcquisitionCollector` 之後、`collection_coverage.json` 之前呼叫）
- **設定**: `config.ini` / **Advanced → Settings** — `MemoryAnalyzeEnabled`, `MemoryAnalyzeToolPath`, `MemoryAnalyzeToolArgs`（`{InputPath}`、`{InputDir}`、`{OutputDir}`、`{CaseDir}`）、`MemoryAnalyzeOutputDirName`, `MemoryAnalyzeTimeoutSec`
- **產出**: 根目錄 `memory_analysis.json`；可選 `MemoryAnalysis\` 下由外部工具寫入之 text/CSV/JSON sidecars
- **語意**: 僅記錄 dump handoff 的執行狀態、輸出目錄與輸出檔 accounting；不在程式內解析記憶體映像、不把外部分析結果包裝成內建 verdict
- **輸出目錄安全**: `MemoryAnalyzeOutputDirName` 必須解析為案卷下專用子目錄；拒絕 case root、input dump 所在目錄與既有保留證物目錄，避免 handoff 清理步驟誤刪證物
- **Coverage**: 若 sidecar 聲稱 `complete` / `partial` 但分析輸出目錄或預期輸出檔不存在，`collection_coverage.json` 會降級或補註 `[Coverage]`，避免誤導性成功狀態
- **範圍**: 不內建實體記憶體讀取、不解析映像、不整合 Volatility/Rekall；亦不在 Fact Store 產出「記憶體事實」。

#### I. 打包機制 (Packer)
- **收集器**: `src\Collector.cs` (PackDir 方法)
- **機制**:
    - 使用 `System.IO.Compression.ZipFile.CreateFromDirectory` 將輸出目錄打包為 `.zip`（無需 PowerShell）。
    - 解壓由 `CaseManager.LoadCase` 使用 `ZipFile.ExtractToDirectory` 完成。
    - CLI `-c` 支援手動傳入證物編號作為 ZIP 檔名；若未提供則自動產生 `AA-YYYYMMDDHHmm` 形式。
    - GUI Local Collect 會提示輸入證物編號，收集完成後可自動上傳並顯示結果。
    - 產出 ZIP 後會建立對應 `*.sha256` 檔案。

### 3.2 建置系統 (Build System)
- **腳本**: `build.bat`, `build_release.bat`
- **功能**:
    - 自動偵測 .NET Framework 4.0+ 編譯器 (csc.exe)。
    - `build.bat`: 本機建置，直接產出並簽章 `IR_Collect.exe`。
    - `build_release.bat`: 一鍵正式發佈，先產出 `IR_Collect_release_candidate.exe`，簽章成功後升級為 `IR_Collect.exe`。
    - **自動簽章**: 自動生成或檢索 "nine-security Inc" 自簽憑證，並對 `IR_Collect.exe` 進行代碼簽章；若僅因本機未信任自簽 root 導致驗證狀態非 `Valid`，建置輸出會明確標示 `LocalSelfSignedUntrusted`；若本機無法建立自簽 code-signing 憑證，則標示 `SkippedLocalCertUnavailable`，避免將其誤認為一般編譯失敗。
    - **Icon**: 支援嵌入應用程式圖示 (`/win32icon`)。

### 3.3 產出檔案規格詳情 (Output Artifacts Detail)

| 檔案名稱 (File Name) | 格式 (Format) | 欄位/內容說明 (Content/Columns) | 來源工具/API |
| :--- | :--- | :--- | :--- |
| **system_info_basic.txt** | Text (UTF-8) | Hostname, OS Version | `Environment` Class |
| **system_info_full.txt** | Text (Raw) | 完整系統資訊 (Hotfix, Network Cards, Hyper-V...) | `systeminfo.exe` |
| **process_list.csv** | CSV | `PID`, `Name`, `Path`, `CommandLine`, `StartTime`, `User`, `SHA256`, `SignatureStatus`, `Signer`, `PPID`, `SessionId`, `ThreadCount`, `WorkingSetSize` | `Process` API + WMI (Win32_Process: CommandLine, ParentProcessId, SessionId, ThreadCount, WorkingSetSize, GetOwner) |
| **network_connections.txt** | Text (Raw) | Proto, Local Address, Foreign Address, State, PID | `netstat -ano` |
| **arp_table.txt** | Text (Raw) | Interface, Internet Address, Physical Address, Type | `arp -a` |
| **network_config.txt** | Text (Raw) | 完整網路介面設定 (IP, MAC, DHCP, DNS Server) | `ipconfig /all` |
| **dns_cache.txt** | Text (Raw) | Record Name, Record Type, Time To Live, Data Length, Section, A Record | `ipconfig /displaydns` |
| **autoruns_registry.csv** | CSV | `Hive` (HKLM/HKCU), `Path` (Key Path), `Name` (Entry), `Value` (Data) | `Microsoft.Win32.Registry` |
| **bam_dam.csv** | CSV | `Source`, `User`, `RegistryPath`, `ValueName`, `Path`, `LastExecutionTime`, `DataLength`, `Details` | Registry (`bam` / `dam` State\UserSettings) |
| **bits_jobs.csv** | CSV | `DisplayName`, `OwnerAccount`, `JobState`, `Priority`, `CreationTime`, `ModificationTime`, `TransferType`, `RemoteName`, `LocalName`, `Description` | PowerShell `Get-BitsTransfer -AllUsers` |
| **wmi_persistence.csv** | CSV | `Class`, `Name`, `Filter`, `Consumer`, `Query`, `Path`, `Details` | WMI `root\subscription` |
| **shimcache.csv** | CSV | `RegistryPath`, `ValueName`, `ValueType`, `DataLength`, `Sha256Prefix`, `Details` | Registry `AppCompatCache` metadata export |
| **shimcache_entries.csv** | CSV | `RegistryPath`, `ValueName`, `EntryIndex`, `Path`, `FileName`, `LastModifiedTime`, `DataHashPrefix`, `ParserNote` | ShimCache entry-level reconstruction |
| **amcache_programs.csv** | CSV | `RegistryKey`, `ProgramName`, `Publisher`, `Version`, `ProductName`, `InstallDate`, `UninstallString`, `ProgramId`, `ParserNote` | Offline Amcache hive parser (`reg load/query`) |
| **amcache_files.csv** | CSV | `RegistryKey`, `Path`, `FileName`, `Hash`, `ProductName`, `Publisher`, `ProgramId`, `FirstObservedTime`, `ExecutedTime`, `ParserNote` | Offline Amcache hive parser (`reg load/query`) |
| **srum_network_usage.csv** | CSV | `Timestamp`, `AppId`, `Path`, `User`, `RemoteIP`, `Interface`, `BytesSent`, `BytesReceived`, `ParserNote` | SRUM exporter（核心 network usage table + IdMap） |
| **srum_app_usage.csv** | CSV | `Timestamp`, `AppId`, `Path`, `User`, `ForegroundCycleTime`, `BackgroundCycleTime`, `ParserNote` | SRUM exporter（核心 app usage table + IdMap） |
| **services.csv** | CSV | `Node`, `DisplayName`, `Name`, `PathName`, `StartMode`, `State` | `wmic service get ...` |
| **installed_software.csv** | CSV | `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `UninstallString` | Registry Uninstall Keys |
| **scheduled_tasks.xml** | XML | `URI` (Path), `Actions`, `Triggers`, `Principal` (RunAs), `Settings` (Enabled) | `schtasks /query /xml` |
| **EventLogs/*.evtx** | EVTX (Binary) | 完整匯出時產出 | `wevtutil epl` |
| **EventLogs/*_filtered.csv** | CSV (UTF-8) | TimeCreated, EventId, LevelDisplayName, ProviderName, Computer, UserId, TaskDisplayName, Message, EventData（預設與 EVTX 同步輸出；供 Timeline / Fact Store / Highlights / AI 匯出使用） | `EventLogReader` + config.ini |
| **Registry/*.hiv** | HIV (Binary) | SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER_\<SID\>.dat, UsrClass_\<SID\>.dat | `reg save` |
| **Registry/ShellBags_\<SID\>.reg** | REG (Text) | BagMRU/Bags 子樹（使用者曾開啟之資料夾路徑跡證）；供外部 ShellBags 解析工具使用 | `reg export` |
| **ExecutionArtifacts/Amcache.hve** | Binary | Raw Amcache hive，供離線執行歷程還原 | File Copy |
| **ExecutionArtifacts/SRUDB.dat** | Binary | Raw SRUM database，供離線網路/應用程式使用量分析 | `esentutl` fallback / File Copy |
| **ExecutionArtifacts/SRUDB.log** | Binary | SRUM log sidecar（若存在） | File Copy |
| **ExecutionArtifacts/SRUDB.jrs** | Binary | SRUM reserve sidecar（若存在） | File Copy |
| **MFT_Dump.bin** | Binary | Raw NTFS Master File Table ($MFT) content | `CreateFile` (Raw Disk) |
| **mft_preview.csv** | CSV | `Record`, `InUse`, `IsDir`, `FileName`, `FullPath`, `Size`, `StdCreated`, `StdModified`, `StdMftModified`, `StdAccessed`, `FnCreated`, `FnModified`, `FnMftModified`, `FnAccessed` | Internal MFT Parser |
| **usn_journal.csv** | CSV | USN Journal (`fsutil usn readjournal` raw output；供 USN 分頁、Fact Store、Timeline 使用) | `fsutil usn readjournal` |
| **recent_files.csv** | CSV | `FileName`, `Extension`, `LastModified`, `Created`, `Directory` | File Scan (Recursive) |
| **filesystem_7days.csv** | CSV | `Path`, `Size`, `Created`, `Modified`, `Extension`, `SHA256` | 最近 7 天新增/修改檔案掃描（&lt;50MB 計算 Hash） |
| **file_integrity.csv** | CSV | `FileName`, `Path`, `SHA256`, `SignatureStatus`, `Signer`, `Status` | `SHA256` Hash of System32 binaries |
| **activity_timeline.csv** | CSV | `Time`, `Source`, `Action`, `Path`, `User`, `Details` | Unified Activity Timeline (Registry/JumpLists/Prefetch/Recent/Process) |
| **jump_lists.csv** | CSV | `Time`, `Source`, `AppId`, `Path`, `User`, `Details` | Jump Lists Parser |
| **JumpLists/*.automaticDestinations-ms** | Binary | Jump List files (raw copy) | File Copy |
| **collection_coverage.json** | JSON | 收集覆蓋率報告；含 `overall_status`、各 major artifact group 的 `complete / partial / failed / skipped / missing` 狀態（Memory 步驟另可反映略過或未產出 sidecar）、`completed_steps` / `partial_steps` / `failed_steps` / **`skipped_steps`** / **`missing_steps`**、present/missing artifacts、detail，以及 `collector_user / collector_privilege_state / backup_privilege_status` runtime context。若有 `missing_steps`，overall 亦降為 `partial`；Event Logs 只有在每個 `.evtx` 都有對應 `*_filtered.csv` 時才會是 `complete` | Collector |
| **memory_acquisition.json** | JSON | 外部記憶體採集編排 sidecar（`schema=memory_acquisition_v1`）：`status`（complete/partial/failed/skipped 等）、工具路徑與參數、輸出相對路徑、起迄 UTC、逾時設定、exit code、stdout/stderr 尾段、輸出檔大小與 SHA256、collector 是否管理員、設定旗標。不含映像解析 | `MemoryAcquisitionCollector` |
| **memory_analysis.json** | JSON | 外部記憶體分析 handoff sidecar（`schema=memory_analysis_v1`）：`status`、工具路徑與參數、輸入 dump 相對路徑、分析輸出目錄、輸出檔清單/數量/總大小、起迄 UTC、逾時設定、exit code、stdout/stderr 尾段、collector 是否管理員。不含 dump verdict | `MemoryAnalysisCollector` |
| **Memory/*** | `.raw` / `.dmp` (Binary) | 使用者指定外部工具寫入之記憶體映像（檔名預設 `memory.raw`，可設定）；路徑限於 `Memory\` 下 | 外部工具（由 IR_Collect 呼叫） |
| **MemoryAnalysis/*** | text / CSV / JSON / tool-specific | 外部分析器寫入之 handoff 產物；平台僅收容與列示，不內建解析 | 外部工具（由 IR_Collect 呼叫） |
| **summary.json** | JSON | Summary/Counts/EventHighlights/FactSamples（facts-only manual export）；另含 `export_schema`、`analysis_mode`、`parser_notes`、`collection_coverage`、`memory_acquisition`、`memory_analysis`、`fact_store_freshness_status/detail`、`analyst_workflow`、Fact source/entity type 統計，fact sample 可帶 `SourceFile` / `CollectionStep` / `CollectionStatus` / `CollectionPrivilege` / `ParseLevel` / `FallbackUsed` / `RawRef` / `ParserNote`。`parser_notes` 為跨來源 dedicated 摘要，不依賴 fact sample 排序；缺失 artifact counts 以 `0` 表示，缺失語意由 `collection_coverage` 承載 | GUI Export |
| **full_log_facts.json** | JSON | Full LOG facts-only envelope；含 `export_schema=full_log_v3`、`analysis_mode`、`host_count`、`fact_count`、`fact_source_counts`、`entity_type_counts`、`load_warnings`、`parser_notes`、`hosts[]` 摘要與 `facts[]` 完整明細（host 摘要可帶 `collection_coverage_status` / `memory_acquisition` / `memory_analysis` / `fact_store_freshness_status` / `fact_store_freshness_detail` / `analyst_workflow`；每筆 fact 可帶 `SourceFile` / `CollectionStep` / `CollectionStatus` / `CollectionPrivilege` / `ParseLevel` / `FallbackUsed` / `RawRef` / `ParserNote`） | Dashboard Export |
| **\<case>.zip.analyst.json / analyst_workflow.json** | JSON | 分析師 sidecar；保存 bookmark / priority / tags / hypothesis / notes，避免修改原始證據 ZIP | Summary Workflow Editor |
| **<evidence>.zip.sha256** | Text | ZIP SHA256（Hex, uppercase） | Internal SHA256 |
| **Prefetch/*.pf** | Binary | Windows Prefetch Files (Execution History, Run Count, Last Run) | File Copy |
| **LnkFiles/*.lnk** | Binary | Shortcut Files from Recent & Desktop (File Access History) | File Copy |
| **Browsers/*_History** | SQLite | 瀏覽器歷史紀錄 Database (Chrome/Edge/Firefox/Opera/Brave) | File Copy |

---

## 4. 介面規格 (UI Specification)

### 4.1 Local Collect（本機收集）
- **觸發**: 左側欄或按鈕「Local Collect」；需具備管理員權限以進行完整收集（含 MFT）。
- **流程**: 提示輸入證物編號 → 執行收集（System / Persistence / Event Logs / MFT / Registry / Browser / User Activity 等；若 Settings 啟用則於 Timeline 建立後呼叫**外部**記憶體採集工具）→ 產出證物編號.zip 與對應 .sha256。
- **完成後**: 產出的 ZIP **自動載入平台**（等同 Import Case），案件出現在左側 Hosts List，可直接於右側分頁檢視 Summary、Timeline、MFT、Event Log 等；若已設定上傳端點則會嘗試上傳並顯示結果。
- **規格要點**: 本機收集完成後無需手動「Import Case」，平台會自動讀進該次收集的案卷，便於立即分析。

### 4.2 GUI (Graphical User Interface)
- **主視窗 (MainForm)**: 1300x850 (加大), 固定式雙欄設計。
- **功能表列 (Menu Strip)**: 位於視窗頂端，提供 `File` (Open Case, Clear all hosts, Exit), `Advanced` (Settings、Rebuild Selected Host Event Logs、Rebuild Selected Host Fact Store 等), `Help` (About)。
- **標題列 (Header)**: 深色風格，包含 "☰" 側邊欄切換按鈕與 Application Title。
- **左側欄 (Sidebar)**（含 Local Collect、Import Case(s) 等）:
    - **Global Dashboard**: 獨立於列表上方，點擊顯示全域匯總；載入案卷時**預設自動建置 Fact Store**（Settings 可關閉）。含 **Correlation**（單一按鈕，下拉選單：**Find Common Artifacts** 跨主機共有、**Find Shared Entities** 跨主機實體 Pivot、**Back To Last Shared Pivot** 返回上一個共享實體清單、**Find Related Entities** 實體關聯、**Build Investigation Graph** 跨主機圖譜表、**Find Time-Window Entity Correlation** 跨主機＋同實體＋同時段、**Find Timeline Correlation** 跨主機＋同時段；`Find Shared Entities` 會沿用目前的 Entity type / filter 做跨主機彙整，且可雙擊結果列下鑽到 host-level facts，再雙擊某筆 fact 跳到對應 host 的 focused Facts tab）。Dashboard 另提供 `Source / Confidence / Host / From / To / Window` 篩選列，供共享實體、實體關聯、graph 與 time-window correlation 共用。`Build Investigation Graph` 旁新增 workspace 控制（`Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`、`Pin Edge`、`Open Facts`、`Open Timeline`）與 trail/pinned 摘要，支援 multi-step graph exploration；`Open Timeline` 會帶入 edge 的 entity、trail 與分鐘級時間窗，並以 structured entity match 優先。**Entity search**（類型：Path/FileName/Hash/User/RegistryKey/Provider/EventId/RemoteIP/RemoteName/ServiceName/TaskName/ThreatName/CommandLine/Computer/BitsJob/WmiFilter/WmiConsumer/Query/AppId/Interface/Publisher/ProductName/ProgramName/ProgramId）、Export full LOG JSON（匯出 `full_log_v3` facts-only envelope；移除所有主機資料（非僅 Fact Store）為 **File → Clear all hosts**；已移除「Build Fact Store (all hosts)」按鈕）。
    - **Hosts List**: 可收合/調整寬度，顯示載入的案件/主機列表。
- **右側欄 (Dynamic Host Tabs)**: 根據該 Host 擁有的 Artifacts 動態顯示，細分為：
    - **0. Summary**: 案件摘要（統計、事件重點、Load warnings、觀察事實摘要、collection coverage、fact_store freshness、parser notes）；Memory 區塊同時顯示 `Coverage` 與 `Sidecar`，避免把 sidecar `complete` 誤解成平台已完成記憶體分析；含 **Analyst Workflow** sidecar 編輯區（bookmark / priority / tags / hypothesis / notes，不修改原始 ZIP）；**Export Summary JSON**、**AI Analyze**、**Export HTML Report**。
    - **0. Timeline Analysis (全方位時間軸分析)**: **Virtual Grid** 整合 Process、MFT、EventLog（*_filtered.csv，含結構化欄位）、USN、BAM/DAM、BITS、Amcache、ShimCache Entries、SRUM Network/App、Activity（activity_timeline.csv：Registry/JumpList/Prefetch/Recent 等）；含 **Time Type / Confidence**、**Source 與時間區間篩選**、**Export CSV/JSON**；依時間倒序。若由 Investigation Graph 開啟，會先用 structured entity 聚焦，再在缺乏 entity ref 時退回文字比對。
    - **1. Basic Info (基礎資訊)**:
        - `System Info`: **Grid Visualization** (解析 Key:Value)。
        - `Processes`: 表格檢視 `process_list.csv`。
        - `Network`:
            - **IP Config**: TreeView 結構化顯示 Adapter 與屬性。
            - **Connections**: 表格顯示 Netstat (Proto, Local, Foreign, State, PID)。
            - **ARP / DNS**: 表格顯示相關紀錄。
    - **2. Persistence (持久化機制)**:
        - `Services`: 表格檢視 `services.csv`。
        - `Autoruns`: 表格檢視 `autoruns_registry.csv`。
        - `BAM / DAM`: 表格檢視 `bam_dam.csv`。
        - `BITS Jobs`: 表格檢視 `bits_jobs.csv`。
        - `WMI Persistence`: 表格檢視 `wmi_persistence.csv`。
        - `Software`: 表格檢視 `installed_software.csv`。
        - `Scheduled Tasks`: 表格檢視 `scheduled_tasks.xml`。
    - **3. Logs & Artifacts (日誌與跡證)**:
        - `Event Logs`: 檢視 `.evtx` 或篩選後 CSV；各 log 分頁支援 **View: Description | Parsed fields | Raw XML** 切換事件詳情。
        - `MFT Explorer`: **Virtual Grid** 檢視完整 MFT 紀錄 (路徑/大小篩選；Record, Path, Size, MACB)。
        - `Browser Artifacts`: 檢視瀏覽器歷史紀錄檔案列表。
        - `ShimCache`: 表格檢視 `shimcache.csv`。
        - `ShimCache Entries`: 表格檢視 `shimcache_entries.csv`（entry-level reconstruction）。
        - `Amcache Programs / Files`: 表格檢視 `amcache_programs.csv` 與 `amcache_files.csv`。
        - `SRUM Network / App Usage`: 表格檢視 `srum_network_usage.csv` 與 `srum_app_usage.csv`。
        - `Execution Artifacts (Raw)`: 檢視 `ExecutionArtifacts\` 內的 raw `Amcache.hve` / `SRUDB.dat` 等檔案。
        - `Memory (Raw dump)` / `Memory acquisition (meta)` / `Memory analysis output` / `Memory analysis (meta)`: 若有收集或 handoff，分別列出 `Memory\` 內映像檔、根目錄 `memory_acquisition.json`、`MemoryAnalysis\` 下外部工具輸出與 `memory_analysis.json` 文字內容（僅編排與稽核 metadata）。
        - `Facts`: 顯示由 Fact Store 正規化後的觀察事實（Time / Time Type / Confidence / Source / Action / Entities / Details / Artifact / Provenance / RawRef），不在 UI 內直接下內建結論。
    - **4. File Activity (檔案活動)**:
        - `Recent Files`: 表格檢視 `recent_files.csv`。
        - `Recent Mod (7d)`: 表格檢視 `filesystem_7days.csv`（7 天內新增/修改檔案，含 SHA256）。
        - `Jump Lists`: 表格檢視 `jump_lists.csv`。
        - `Lnk Files`: 檢視已收集的快捷方式檔案列表 (Dump)。
        - `Prefetch`: 檢視已收集的 Prefetch 檔案列表 (Dump)。
    - **5. Integrity Check (完整性檢查)**:
        - `File Check`:
            - **Baseline**: 顯示收集時的 System32/Hosts/Startup 檔案 Hash。
            - **Deep Scan**: 介面按鈕，支援即時掃描 System32 所有執行檔。

### 4.3 建議流程 (Recommended Workflow)
1. **取得案卷**: **Local Collect**（本機收集，完成後自動載入）或 **Import Case(s)**（匯入既有 ZIP/資料夾），使左側 Hosts List 有案件、各 Case 具 ExtractPath。載入時**預設自動建置 Fact Store**（Settings「Auto Build Fact Store when case is loaded」可關閉）。
2. **檢視與篩選**: 在右側分頁依需檢視 Summary、Timeline Analysis、Basic Info、Persistence、Logs、File Activity、Integrity；Timeline Analysis 可篩選來源／時間並 **Export CSV/JSON**。
3. **關聯分析與匯出**: 使用 **Facts** 分頁、**Entity search**、或 **Export full LOG JSON**（需先有 Fact Store；若已關閉自動建置則需先 Clear 後重新載入案卷以觸發建置）。
4. **匯出**: Summary → **Export Summary JSON** / **Export HTML Report**；Timeline → **Export CSV/JSON**。Phase B3：自動建置時可選寫入 SQLite，並可自 Fact Store 匯出 **完整 LOG JSON**。
5. **手動重建**: 若單一主機的 Event Log filtered CSV 或 Fact Store 需要刷新，可於 **Advanced** 或 Hosts list 右鍵選單使用 **Rebuild Selected Host Event Logs / Fact Store**；前者會依目前 `EventLogDays / EventLogMaxEvents` 重建 filtered CSV，後者會重建該主機的 observed facts，並在啟用 SQLite 寫入時同步更新 `fact_store.db`。

**Build Fact Store**：已移除「Build Fact Store (all hosts)」按鈕；改為**預設於載入案卷時自動建置**（Settings「Auto Build Fact Store when case is loaded」預設勾選，可關閉）。僅 Facts、Entity search、完整 LOG JSON 匯出依賴 Fact Store。**Clear all hosts**：於 **File → Clear all hosts** 移除所有已載入主機的資料（含解壓目錄與 Fact Store），清空左側 Hosts list 與右側分頁並回到 Dashboard；會提示確認且無法復原。

---

## 5. 待辦事項/未來規劃 (Backlog)
- [x] **File Hash Calculation**: 針對 System32 關鍵檔案進行 SHA256 計算 (File Check)。
- [x] **Process Hash**: 將 Hash 計算整合至執行中的 Process List（大於 50MB 跳過）。
- [x] **Process User 欄位**: 已以 WMI `Win32_Process.GetOwner()` 補齊 process_list.csv 的 User 欄位（Domain\\User）；另含 PPID/SessionId/ThreadCount/WorkingSetSize。
- [x] **Process / 全機記憶體映像（外部工具）**: Settings 設定外部採集工具與參數，收集時編排執行並寫 `memory_acquisition.json` + `Memory\`（無內建採集驅動、無映像解析）；若再啟用 handoff，外部分析器會寫 `memory_analysis.json` + `MemoryAnalysis\`，平台只收容 sidecar / output accounting，不內建記憶體 verdict，且 handoff 輸出目錄受限於專用 case 子目錄。
- [x] **Activity Timeline**: 已整合 Registry/JumpLists/Prefetch/Recent/Process；時間區間/Source/Keyword 篩選、CSV/JSON 匯出。
- [x] **Timeline (Combined)**: Process + MFT + EventLog（*_filtered.csv）+ USN 整合時間軸；Export CSV/JSON。
- [x] **Advanced EVTX Viewer**: 事件詳情可切換 Description | Parsed fields | Raw XML。
- [x] **Report HTML**: Summary 分頁「Export HTML Report」產出單一 HTML（Host、Counts、Highlights、Observed facts）。
- [x] **Fact Store**: 記憶體 FactStore、Entity 索引（HashSet 存 Fact，O(1) add/lookup）、GetByEntity/GetByTimeRange；載入案卷時預設於背景自動建置（Settings 可關閉），支援 Entity search。Fact 另帶 `TimeKind` / `TimeConfidence`，用來標示 timestamp 來源與可信度；目前已含 USN Journal normalizer。若案卷內存在 `fact_store.db`，載入時會檢查其是否比目前 source artifacts 舊，並以 `fact_store_freshness_status/detail` 標示 cache 是否 stale。**前置**：須先載入 Case（ExtractPath 存在）；Build 時從磁碟讀取各 CSV/XML（及已解析的 MftEntries），**目前預設寫入記憶體**，SQLite 持久化見 Phase B3。
- [x] **Manual Rebuild Entry**: UI 提供單一主機層級的 **Rebuild Selected Host Event Logs / Fact Store**。Event Log 重建會改寫該主機 `EventLogs/*_filtered.csv`；Fact Store 重建則會刷新記憶體中的 facts，並於啟用 SQLite 寫入時同步更新 `fact_store.db`。
- [x] **Cross-source Fact Correlation**: 以 Fact Store、Entity 索引與時間窗查詢支援分析師做跨來源比對，不在工具內直接執行內建規則判定。
- [x] **Event Log 收集優化**: 預設保留完整 EVTX，並同時輸出含 `Computer / UserId / TaskDisplayName / EventData` 的 filtered CSV 供 Timeline / Fact Store / Export 使用；config.ini EventLogDays/EventLogMaxEvents 控制 filtered 視窗與上限。
- [x] **Collection Coverage**: 收集完成時寫出 `collection_coverage.json`，記錄 major artifact groups 的 `complete / partial / failed / skipped / missing`、缺失 artifacts 與 `collector_user / collector_privilege_state / backup_privilege_status`；若有 `missing` 則 overall 亦降為 `partial`。Summary / HTML / JSON 匯出會同步帶出，協助分析師區分「未觀察到」與「未成功收集」。
- [x] **Logger**: Utils/Logger.cs 集中記錄；ZipFile 取代 PowerShell 壓縮/解壓。
- [x] **Phase B3 SQLite**: Fact Store 持久化（拆欄 Id/Time/Source/EntityKey + JSON 欄 Details；SchemaVersion 3）。**實作**：Settings「Write Fact Store to SQLite when building」勾選後，Build Fact Store 時寫入各 host 之 `ExtractPath\fact_store.db`；Dashboard「Export full LOG JSON」匯出 `full_log_v3` facts-only envelope（host 摘要、analyst workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要、完整 facts）；SQLite 以執行期載入 System.Data.SQLite.dll（DLL 未放置於 exe 同目錄時僅略過寫入）；`FactStorePersistence.LoadFromSqlite` 可自 DB 還原 FactStore。**未來新增的 LOG**：凡納入 `FactStore.BuildFromCase` 即自動納入同一 JSON 輸出。**Case Diff** 不需要；**Privacy redaction** 不實作。

### 5.1 下一版本候選更新項目（v0.22.0 draft）
- [ ] **Low Impact / Forensic Strict 模式**：新增現場低擾動操作模式，強化外接媒體輸出建議、工具自產痕跡提示、可選步驟限制與更明確的 operator warning。
- [ ] **Memory handoff 一等公民化**：補齊外部工具 preset、輸出驗證、常見失敗診斷，並評估將常見記憶體分析摘要回填至 Fact Store 的 sidecar-normalized 路徑。
- [ ] **非 Event Log 的 lateral movement / identity 補強**：降低對 Security / TerminalServices 等日誌的單點依賴，補足更多可離線或弱日誌情境下的關聯訊號。
- [ ] **ShellBags 內建解析**：由目前 raw/export-only 提升為平台內可直接檢視的路徑與時間資訊，減少分析師切換外部工具。
- [ ] **Guided Hunt Pack（與 facts 分層）**：在不污染 facts-only 模型的前提下，加入可關閉的 ATT&CK 對映、可解釋規則、假設模板與 analyst guidance。
- [ ] **Redaction / Endpoint Governance**：補上 redaction profile、endpoint allowlist、設定檔保護與更強的 AI / Upload 治理控制，降低敏感資料外送風險。
- [ ] **Case Diff / Baseline Diff**：支援主機與基線之差異比對，讓分析師更快看見新增程序、持久化、檔案與關鍵實體差異。

## 6. 開發進度路徑圖 (Development Roadmap)

### Phase 2: 多主機分析與關聯
- [x] 多案件管理 (Case Manager)、關聯分析 (Correlation Engine)：檔案關聯、時間關聯。
- [x] Investigation Graph Workspace 持續修正（v0.19.1 + acceptance hardening）：edge 主機範圍與結果集一致、workspace 篩選快照隨 trail 重播、從 graph 開啟 Timeline 帶入可讀脈絡與可關閉的聚焦篩選，並改為 structured entity match + 分鐘級時間窗。
- [x] **Phase 3 Lateral Movement & Identity Abuse Pack（v0.20.0）**：Event Log 正規化加深（見版本歷程）；跨主機 pivot / graph / timeline 可觀測性提升，無內建攻擊者歸因或惡意評分。

### Phase 3–6: 收集與分析
- [x] **Phase 3**：MFT 收集與分析、Process List、Network、Services & Drivers。
- [x] **Phase 4**：Autoruns、Scheduled Tasks、Event Logs。
- [x] **Phase 5**：Browser History、Prefetch、Recent Files、Shortcuts、Recents Mods (7d)。
- [x] **Phase 6**：Registry Hives、Software Inventory、File Integrity、Process Hash、Signature Verification、Fact Store、Activity Timeline、Timeline (Combined)、Event Log 優化、Logger、Process User。  
（維護完成項如 Code Review、LOG 分頁、USN 篩選等已反映於版本歷程與 changelog。）

## 7. 2026-03-06 Maintenance Notes
- Deferred host tabs: heavy GUI tabs (Timeline Analysis, large CSV/XML/file-list views) are instantiated on first open instead of during host selection.
- Event Log async safety: lazy EVTX loading validates the target tab before applying UI updates, preventing disposed-control crashes during close/switch.
- Case import performance: CaseManager.LoadCase performs a single recursive file enumeration to locate MFT_Dump.bin, mft_preview.csv, and supported artifacts.
- Artifact schema: no output filename, extension, or column schema changed in this maintenance update.
- **Code Review (v0.17.2)**：SafeInvoke 用於收集/Deep Scan 回調；MftParser 緩衝區邊界與 attrLen 驗證；大檔 >100MB 不載入；ProcessFile 改記 log。
