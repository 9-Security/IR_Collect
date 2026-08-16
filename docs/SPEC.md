# 9SEC Evidence Workbench 開發規格手冊 (Development Specification)

**專案名稱**: 9SEC Evidence Workbench
**版本**: v0.25.2
**最後更新時間**: 2026-08-17
**開發者**: Antigravity (collaborating with User)

---

## 1. 專案概述 (Project Overview)
本專案為一個輕量級、可攜帶 (Portable) 的 Windows 事件回應資訊收集與跨平台證據分析工作台。Live collection 限 Windows；分析端可直接收容 Windows 案卷與 UAC 產生的 Linux/macOS folder 或 archive，並共用 Fact Store、Timeline、Diff、Correlation、Graph 與匯出管線。

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
| **v0.25.2** | 2026-08-17 | **Jump List parser / Provenance** | 新增 bounded OLE-CFB FAT／DIFAT／miniFAT 與 regular/mini stream 重組；擴充 A-Z／UNC／HTTP(S)／known-folder 目的地，fallback 狀態進入 Fact provenance；移除每檔 10 筆靜默截斷並修正非零偏移 LNK 掃描。對本機 JLECmd path recall 162/172（94.2%）；完整 shell-item／Target IDList 仍列為限制。 |
| **v0.25.1** | 2026-08-16 | **Forensic integrity / Fix** | Collector output collision 拒絕與 atomic ZIP/SHA publish；evidence manifest 完整性、reparse 防護及 Fact Store build 前 digest 重驗；預置 `fact_store.db` 不再當作可信 facts；CSV 上限警告進入 export；CLI 失敗／coverage-gap exit code 對齊；MFT resident `$ATTRIBUTE_LIST` extension `$FILE_NAME` 長檔名合併。 |
| **v0.25.0** | 2026-07-29 | **Cross-platform intake / Analysis / Governance** | UAC folder、ZIP、TAR、TAR.GZ/TGZ 可由 GUI 與分析 CLI 直接收容，支援 Linux/macOS process、bodyfile、auth、auditd、system/web log、package、network、account、shell history、persistence、journal/boot、login 與 executable/running-process hashes，保留逐檔 SHA-256 provenance 並進入 Fact Store／Timeline／Correlation／Graph／export。新增 facts-only Case Diff、選用的 persistent Fact Store build cache，以及完整化 Low Impact / Forensic Strict；archive intake、analysis workspace 與衍生輸出同步加入 bounded extraction、read-only evidence root 與 atomic publish hardening。 |
| **v0.24.2** | 2026-07-20 | **教學資產 / Fix** | **上手教學資產 + Prefetch 解析器強化**:新增 `docs/sample-case/`——手工合成、零真實證據的雙主機案卷（釣魚→Temp 執行→Run 機碼→C$ 橫移→清日誌,兩台以同一 SHA-1 相連）+ 雙語導覽 `docs/DEMO.md`／`DEMO.zh-TW.md`,帶使用者把 `-analyze`／`-correlate`／`-graph` 端到端跑過（實測觸發 4+2 條 Guided Hunt、跨主機共享 Hash、18 節點調查圖）;整合兼漂移守門自測 `GuidedHunt_demo_case_trips_expected_rules`。另收 v0.24.1 後的 Prefetch code-review 強化:v30（Win10）run-count offset 誠實標為「推測、未驗證」、referenced-files 上限 8192、解壓 workspace 用較大值、malformed/v23 自測。詳見 CHANGELOG。 |
| **v0.24.1** | 2026-06-16 | **Hunt / 互通** | **Guided Hunt 規則 ×3 + 輸出 JSON Schema**：新增 ATT&CK 對應規則——事件日誌被清除（T1070.001）、可疑路徑執行（T1204/T1036）、DLL side-loading（T1574.002,接 Prefetch）,各帶正反向自測。新增 `docs/schemas/` 的 `summary_v3`／`correlation_v1`／`graph_v1` JSON Schema（draft-07）+ 漂移守門測試。README 雙語補上離線分析 CLI 段落。詳見 CHANGELOG。 |
| **v0.24.0** | 2026-06-16 | **Parser（執行證據）** | **Prefetch (.pf) 解析器 + normalizer**：補上「Prefetch 只被原始複製、從不變 facts」的分析層缺口。解壓 MAM/Xpress-Huffman（ntdll）→ 解析 SCCA（執行檔名、run count、最多 8 個 last-run 時間、載入檔案清單）→ `Source=Prefetch`／`Executed` facts（`FileName` 實體可跨來源關聯、user-writable 載入路徑以 `ReferencedFile` 實體呈現 = DLL side-load 訊號）。對真實 .pf **差異化驗證 80/80 完全一致 vs PECmd**（執行檔名 + run count + last-run + 載入檔案數）。詳見 CHANGELOG。 |
| **v0.23.1** | 2026-06-15 | **Performance（收集速度）** | **Local Collect 大幅提速（實機驗證 ~16 分→~5.5 分）**：事件日誌過濾加格式化時間預算（`EventLogMessageFormatBudgetSeconds`，FormatDescription 瓶頸實測 1022×）並**跨 log 平行化**（Event Logs 200s→93s）；打包壓縮預設改 `Fastest`（`CollectionZipCompression`；6.7× 快、+2% 體積）；每步加計時並寫入 `collection_timing.txt`。鑑識零妥協（事件一筆不少、只降級顯示字串；檔案掃描誠實截斷）。詳見 CHANGELOG。 |
| **v0.23.0** | 2026-06-15 | **Analysis layer / Court-admissibility** | **Phase 2–5 強化路線**：解析器對齊 EZ 工具（MFT USN/fixup + Win32 名、SRUM 原生 ESE reader、Amcache 現代 schema、ShimCache 結構化 + canonical-value）；**分析層前門** `-analyze <folder>`（吃任意已採集資料夾、原始 hive 自動解析）；**跨機關聯** `-correlate` + **多跳調查圖** `-graph`（`correlation_v1`／`graph_v1` JSON）；**可呈堂性**：`BuildInfo` 單一版本來源、所有輸出帶 `tool_name`/`tool_version`、`-version`、證據 SHA-256 manifest（`evidence_digest`）、`docs/SBOM.md` 相依宣告；GUI 新增「Open Folder (triage)」。詳見 CHANGELOG。 |
| **v0.22.0** | 2026-04-08 | **Security / Governance** | **WP-A Redaction / Endpoint Governance（出站治理）**：AI 與 ZIP Upload 使用**分離**的 endpoint allowlist（`AiEndpointAllowlist`、`UploadEndpointAllowlist`；空清單預設阻擋對應管道之 HTTP POST）。Summary → **AI Analyze** 僅對「即將 POST 的 JSON」套用 `AiExportRedactionProfile`（`None` / `Basic` / `Strict`，預設 `Basic`）；**Export Summary JSON** 與 raw ZIP upload **不改寫**內文。AI 送出前 UI 確認對話框顯示目前 endpoint 與 redaction profile。見 **SECURITY.md**、**USER_MANUAL**。 |
| **v0.22.0** | 2026-04-08 | **Governance / UX** | **WP-E Collection mode profile**：**Advanced → Settings** 可選並保存 `CollectionModeProfile`（`Standard` | `TriageFast` | `ForensicStrict`，預設 Standard）。CLI/GUI 收集前提示 live-response 與輸出路徑風險（**非** zero-footprint／完整低擾動鑑識承諾）。`collection_coverage.json` 寫入 `collection_mode_profile`；Summary / HTML / `summary.json` 與 `full_log_v3` 的 host 摘要帶同一欄位。`ForensicStrict` **額外**阻擋 Local Collect 後之 ZIP 出站上傳與 **AI Analyze**（與 WP-A allowlist 正交；變更 profile 方可恢復 allowlist 治理流程）。 |
| **v0.22.0** | 2026-04-08 | **Feature（facts-only）** | **WP-D 非 Event Log 之 lateral movement／identity 補強（第一階段）**：新增 `JumpListNormalizer`，將 `jump_lists.csv` 納入 `FactStore.BuildFromCase`（`Source=JumpList`、`Action=JumpListDestinationObserved`；實體 `Path`／`User`／`AppId`；UNC／http(s) 目標另衍生 `Workstation`／`ShareName`／`RemoteIP`）。`BITS` 之 `RemoteName` 可以 `;` 分段（多檔／多 URL）後逐项衍生上述實體，**不**另拆多筆 fact；完整字串仍保留於 `RemoteName` 實體。**Unified Timeline** 中 Jump List 列僅經 `activity_timeline.csv`（`ActivityTimelineBuilder` 已併入 jump list），**不再**額外餵入 `jump_lists.csv`，避免重複列。Dashboard Correlation **Source** 篩選含 **JumpList**；`fact_store.db` freshness 源清單含 `jump_lists.csv`。 |
| **v0.22.0** | 2026-04-08 | **Feature（facts-only）** | **WP-C ShellBags 內建解析（第一階段）**：收集仍匯出 `Registry\ShellBags_<SID>.reg` 不變；平台於收集完成與案卷匯入時產生／更新 `Registry\shellbags.csv`（UTF-8），`ShellBagsNormalizer` 納入 `FactStore.BuildFromCase`（`Source=ShellBags`、`Action=FolderBrowsed`，實體 `Path`／`User`（SID 字串）／`Sid`）。UI：**Logs & Artifacts → ShellBags (parsed)**；Dashboard Correlation **Source** 篩選含 **ShellBags**；Entity type 含 **Sid**。Timeline 納入 ShellBags 事實；事的 **Observation** 時間來自 CSV `LastWriteTime`，其值為來源 `.reg` 檔之 **UTC LastWriteTime**（登錄匯出不含原機碼 LastWriteTime）。非完整 Shell Item 還原器；無法還原處保留 `ParserNote`。 |
| **v0.22.0** | 2026-04-09 | **Feature（facts-only）** | **Guided Hunt Pack v1 + Service / credential artifacts**：`services.csv` 新增 `ServiceNormalizer`；另將 `logon_sessions.csv`、`network_resources.csv`、`server_connections.csv`、`stored_credentials.txt` (`cmdkey /list`) 與 `kerberos_tickets.txt` (`klist`) 接入 `FactStore.BuildFromCase`、fact provenance、freshness source list、Timeline 與 Correlation Source 篩選。`GuidedHuntPack` 以獨立 overlay 方式提供 ATT&CK-mapped、可解釋規則與 hypothesis templates；目前規則涵蓋 RDP、SMB admin share、BITS、WMI、Autorun、Scheduled Task、Service path 與 credential-backed remote access，且 `GH-CRED-001` 可同時參考 Event Log 與上述 credential artifacts。Guided Hunt 只讀取 facts 產生線索，不改寫 Fact Store。 |
| **v0.22.0** | 2026-04-09 | **Hardening + Feature** | **Memory handoff first-class**：`memory_acquisition.json` / `memory_analysis.json` 升級為 `schema=*_v2`，新增 args preset、validation mode/status/detail、diagnostic category/detail 與 analysis required-pattern accounting；Settings 支援 acquire/analyze preset、validation mode、minimum dump size、required output patterns 與 Guided Hunt enable/disable。Memory sidecar 可正規化回 `FactStore`、Timeline、Summary、HTML、`summary.json`、`full_log_v3`，但仍不解析 dump 內容。 |
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
    - `logon_sessions.csv`: 目前登入工作階段摘要 (User, Domain, SID, LogonType, AuthenticationPackage, StartTime)。
    - `network_resources.csv`: 目前工作站已連線的網路資源 / mapped drives (`WNetOpenEnum`)。
    - `server_connections.csv`: 本機作為伺服器端被連入的 share/session 概況 (`NetSessionEnum`)。
    - `stored_credentials.txt`: `cmdkey /list` 原始輸出，首行附 `ObservedAtUtc`。
    - `kerberos_tickets.txt`: `klist` 原始輸出，首行附 `ObservedAtUtc`。

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
    - `Registry\ShellBags_<SID>.reg`: 每位使用者之 Shell（BagMRU/Bags）子樹匯出為 .reg；內含使用者曾開啟的資料夾路徑跡證（含本機、網路、USB 等）。
    - `Registry\shellbags.csv`: 由 `ShellBagsParser` 從所有 `ShellBags_*.reg` 彙整之**第一階段**結構化列（Bag 路徑、MRU 槽位、可還原之路徑片段、`ParserNote`、來源檔名等）；收集完成與案卷匯入時若偵測到新的 `.reg` 會重建。Registry Editor 5.00 之 `hex:` 多行續行（物理行行尾 `\`）合併為單一邏輯行時，續行尾端 `\` 不保留、續行之前導空白可忽略，以免十六進位解析被污染。鍵路徑至少涵蓋 `...\BagMRU\...`、以及結尾為 `...\Bags\<n>\Shell` / `...\Bags\<n>\ShellNoRoam` 之 **Bags** 子機碼（此類路徑末尾通常無 `\Shell\` 段，故不能只依 `\Shell\` 前綴篩選）。納入 Fact Store / Timeline / Entity search（facts-only、`FolderBrowsed`）；**非**完整 Shell Item 語意還原器。CSV 之 `LastWriteTime` 為來源 `.reg` 檔 UTC mtime，**不是**原登錄機碼 LastWriteTime。進階還原仍可使用外部工具（例如 [Eric Zimmerman ShellBags Explorer](https://github.com/EricZimmerman/ShellBags)）載入 `.reg` 或離線 Hive。

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
    - 自動解析前 5000 筆紀錄為 `mft_preview.csv`（包含 Standard 與 FileName MACB、大小與完整路徑）。載入 Case 時，MFT 筆數由 **Settings** 內 **MFT max entries** 控制（預設 100000，上限 500000，對應 config.ini 的 MftMaxEntries），binary 與 CSV 後備皆套用，以降低大 MFT 記憶體使用。Parser 會追蹤 resident `$ATTRIBUTE_LIST` 中的 `$FILE_NAME` extension record 以回收 Win32 長檔名；non-resident attribute list 無法僅由 `$MFT` dump 完整還原，維持外部工具交叉驗證邊界。
    - 透過 `fsutil usn readjournal` 產出 `usn_journal.csv`。

#### G. 活動彙整 (Activity Timeline)
- **收集器**: `src\Collectors\RegistryActivityCollector.cs`, `src\Collectors\JumpListsCollector.cs`, `src\Collectors\ActivityTimelineBuilder.cs`
- **來源**: UserAssist / RunMRU / RecentDocs / Jump Lists / Prefetch / Recent Files / Process
- **產出**: `activity_timeline.csv`（統一時間軸，整合所有活動來源）

#### H. 記憶體採集編排 (Memory acquisition, external tool)
- **收集器**: `src\Collectors\MemoryAcquisitionCollector.cs`（由 `Collector.RunCollectionDetailed` 於建立 `activity_timeline.csv` 之後、`collection_coverage.json` 之前呼叫）
- **設定**: `config.ini` / **Advanced → Settings** — `MemoryAcquireEnabled`, `MemoryAcquireToolPath`, `MemoryAcquireArgsPreset`（`custom` \| `quoted_output` \| `winpmem_o`）, `MemoryAcquireToolArgs`（`custom` 時為完整模板；**非** `custom` 時為接在 preset 核心引數後的額外 CLI 片段，仍支援 `{OutputPath}` / `{OutputDir}` 展開）、`MemoryAcquireOutputName`, `MemoryAcquireTimeoutSec`, `MemoryAcquireRequiresAdmin`（僅記錄於 sidecar）, `MemoryAcquireSkipIfNotElevated`, `MemoryAcquireValidationMode`（`exists_only` / `minimum_size`）, `MemoryAcquireMinFileBytes`
- **產出**: 根目錄 `memory_acquisition.json`；可選 `Memory\` 下由外部工具寫入之 `.raw` / `.dmp`
- **執行模型**: 重新導向之 stdout/stderr 於子行程存續期間以背景執行緒並行讀取至串流結束，避免管線緩衝區塞滿造成假性阻塞／逾時；側錄仍以尾段摘要寫入 sidecar。
- **Coverage / 稽核**: `collection_coverage.json` 之 Memory 步驟若偵測 sidecar 狀態為 `complete` 但預期 dump 路徑上檔案不存在，覆寫為 `failed` 並加註 `[Coverage]` 說明；寫入 `memory_acquisition.json` 前亦會做一次磁碟 reconcile（Detail 可含 `[Reconciled]`），避免 sidecar 與磁碟不一致。Summary / HTML / `summary.json` / `full_log_v3` 共用同一段 `CoverageVsSidecarGuidance` 解釋 `[Coverage]` 與 `[Reconciled]`。
- **ForensicStrict**: `ForensicStrictSkipMemoryHandoff=1` 時，即使 acquisition 已啟用亦不啟動外部工具；寫出 `skipped` sidecar，將步驟列入 `restricted_steps` 與 `skipped_by_profile`，overall coverage 降為 `partial`。

#### I. 記憶體分析交接 (Memory analysis handoff, external tool)
- **收集器**: `src\Collectors\MemoryAnalysisCollector.cs`（於 `MemoryAcquisitionCollector` 之後、`collection_coverage.json` 之前呼叫）
- **設定**: `config.ini` / **Advanced → Settings** — `MemoryAnalyzeEnabled`, `MemoryAnalyzeToolPath`, `MemoryAnalyzeArgsPreset`（`dual_quoted` \| `custom`）, `MemoryAnalyzeToolArgs`（`{InputPath}`、`{InputDir}`、`{OutputDir}`、`{CaseDir}`）、`MemoryAnalyzeOutputDirName`, `MemoryAnalyzeTimeoutSec`, `MemoryAnalyzeValidationMode`（`directory_has_files` / `required_patterns`）, `MemoryAnalyzeRequiredPatterns`
- **產出**: 根目錄 `memory_analysis.json`；可選 `MemoryAnalysis\` 下由外部工具寫入之 text/CSV/JSON sidecars
- **語意**: 僅記錄 dump handoff 的執行狀態、輸出目錄與輸出檔 accounting；不在程式內解析記憶體映像、不把外部分析結果包裝成內建 verdict
- **輸出目錄安全**: `MemoryAnalyzeOutputDirName` 必須解析為案卷下專用子目錄；拒絕 case root、input dump 所在目錄與既有保留證物目錄，避免 handoff 清理步驟誤刪證物
- **Coverage / 稽核**: 若 sidecar 聲稱 `complete` / `partial` 但分析輸出目錄或預期輸出檔不存在，`collection_coverage.json` 會降級或補註 `[Coverage]`；寫入 `memory_analysis.json` 前若 sidecar 已列 output accounting 但磁碟上無對應檔案，會降級為 `failed` 並加註 `[Reconciled]`（同上，與 `[Coverage]` 一併於共用 analyst 說明中定義）。
- **ForensicStrict**: `ForensicStrictSkipMemoryHandoff=1` 時不啟動外部分析器；若 handoff 已啟用，寫出 `skipped` sidecar，將步驟列入 profile skip 並使 overall coverage 為 `partial`。
- **範圍**: 不內建實體記憶體讀取、不解析映像、不整合 Volatility/Rekall；亦不在 Fact Store 產出「記憶體事實」。

#### J. 打包機制 (Packer)
- **收集器**: `src\Collector.cs` (PackDir 方法)
- **機制**:
    - 使用 `System.IO.Compression.ZipFile.CreateFromDirectory` 將輸出目錄先打包至同目錄 temporary file，再原子發布為 `.zip`（無需 PowerShell）；若 `IR_Output_<ID>`、最終 ZIP 或 SHA sidecar 已存在，收集器會在寫入前拒絕執行，不覆寫或混入前次證據。
    - 案卷匯入由 `ArchiveIntake` 安全處理 ZIP、TAR、TAR.GZ/TGZ；拒絕 path traversal，限制 entry 數、單檔/總展開量、展開壓縮比與最低剩餘空間。預設 hard cap 為 200,000 entries、單檔 300 GiB、總展開 750 GiB；展開量達 1 GiB 後壓縮比上限 1000:1，最低保留 1 GiB 可用空間。ZIP 先做 central-directory preflight；TAR.GZ 依串流 header 逐 entry 守門。解壓只寫同磁碟 staging，成功才發布，失敗/取消/截斷/超限不留下半成品，並輸出 archive entry 映射。原生 collector 仍以 ZIP 產出。
    - Folder/archive 的原始 evidence root 只讀；載入必須完成逐檔 SHA-256 manifest，拒絕 reparse-point file/directory，Fact Store build 前重新計算整體 digest，來源改變或 manifest 不完整即停止並要求重新匯入。所有 canonical derivatives、離線重建 Event Log CSV、ShellBags、Fact Store cache 與 CLI 預設報告寫入獨立 `%TEMP%` analysis workspace，並採同目錄 temporary file + atomic replace/move 發布。Writer 失敗時保留既有完整輸出且清理 partial file。來源中預置的 canonical 同名檔與 `fact_store.db` 列為 raw evidence，不直接信任。`analysis_workspace_v1.json` 記錄 source digest、tool identity 與每個衍生檔的 SHA-256。Analyst workflow 依來源 digest 保存在目前使用者 Local Application Data。
    - CLI `-c` 支援手動傳入證物編號作為 ZIP 檔名；若未提供則自動產生 `AA-YYYYMMDDHHmm` 形式。Exit code `0/1/2/3/4` 分別表示完整成功、執行或輸出失敗、收集步驟失敗／命令參數錯誤、操作員取消、完成但有 coverage gap；分析 CLI 寫檔失敗回傳 `1`。
    - GUI Local Collect 會提示輸入證物編號，收集完成後可自動上傳並顯示結果。
    - 產出 ZIP 後會建立對應 `*.sha256` 檔案。

### 3.2 建置與發布系統 (Build and Release System)
- **腳本**: `build.bat`, `build_review.bat`, `run_review_regression.bat`, `build_release.bat`, `publish_release.bat`, `scripts\PackageRelease.ps1`, `scripts\SignLocalBuild.ps1`
- **功能**:
    - 使用固定路徑 `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`，維持 .NET Framework 4.5+ / C# 5 相容性；`build_common.rsp` 為明確且有序的建置輸入清單。
    - `build.bat`: 本機建置，在 `%TEMP%\9SEC_EvidW-local-build\9SEC_EvidW.exe` 產出並嘗試簽章，不覆寫專案根目錄的正式檔。本機若無法建立 code-signing 憑證或 timestamp server 不可達，會明確標示 `SkippedLocalCertUnavailable` 或 `TimestampServerUnavailable`，供開發者判讀。
    - `build_release.bat`: 先在 `.release-stage\` 以最終 basename 產出 `9SEC_EvidW.exe`；正式 release gate 同時要求簽章與可信時間戳，任一缺失即 fail closed。驗證成功後才搬移到專案根目錄，確保 PE `OriginalFilename` / `InternalName` 與發布檔名一致。
    - `build_review.bat` / `run_review_regression.bat`: 在 `%TEMP%` 建置 `INCLUDE_TESTS` review EXE、執行 self-tests，完成後清理 review EXE並保留測試結果文字檔。
    - `publish_release.bat`: 預設先執行 regression，再呼叫正式 release build，最後產生 `dist\9SEC_Evidence_Workbench_vX.Y.Z.zip` 與同名 `.zip.sha256`。`-SkipBuild` 僅封裝既有正式 EXE且明確略過 regression，但仍要求 FileVersion、PE `OriginalFilename`、Authenticode 簽章與時間戳符合版本契約；`-Publish` 透過 GitHub CLI 建立或更新 Release並上傳 ZIP/checksum，缺少 `gh` 時 fail closed。
    - Parser differential validation 直接由 `scripts\DiffValidate.ps1` 執行；若 reference tools 不存在則明確 skip 並成功結束，存在時按需建置及清理 `%TEMP%` review EXE。
    - **自動簽章**: 自動生成或檢索 "nine-security Inc" 自簽憑證；既有憑證必須通過跨 PowerShell 版本的 code-signing EKU 判讀，且 RSA 私鑰可實際開啟，才會被重用。若簽章存在但本機未信任自簽 root，輸出明確標示 `LocalSelfSignedUntrusted`，不誤稱為受公有 CA 信任。
    - **Icon**: 支援嵌入應用程式圖示 (`/win32icon`)。

### 3.3 產出檔案規格詳情 (Output Artifacts Detail)

| 檔案名稱 (File Name) | 格式 (Format) | 欄位/內容說明 (Content/Columns) | 來源工具/API |
| :--- | :--- | :--- | :--- |
| **system_info_basic.txt** | Text (UTF-8) | Hostname, OS Version | `Environment` Class |
| **system_info_full.txt** | Text (Raw) | 完整系統資訊 (Hotfix, Network Cards, Hyper-V...) | `systeminfo.exe` |
| **process_list.csv** | CSV | `PID`, `Name`, `Path`, `CommandLine`, `StartTime`, `User`, `SHA256`, `SignatureStatus`, `Signer`, `PPID`, `SessionId`, `ThreadCount`, `WorkingSetSize` | `Process` API + WMI (Win32_Process: CommandLine, ParentProcessId, SessionId, ThreadCount, WorkingSetSize, GetOwner) |

| **uac_auth_events.csv** | CSV | `Time`, `Source`, `Action`, `User`, `TargetUser`, `RemoteIP`, `RemoteName`, `Terminal`, `CommandLine`, `Details` | UAC intake adapter (`auth.log` / `secure` / `system.log` to canonical auth facts) |
| **uac_network_connections.csv** | CSV | `ObservedAtUtc`, `Collector`, `Protocol`, `State`, `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort`, `ProcessId`, `ProcessName`, `User`, `Details` | UAC intake adapter (`lsof` / `ss` / `netstat` snapshots to canonical network facts) |
| **uac_accounts.csv** | CSV | `RecordType`, `Name`, `Id`, `PrimaryGroupId`, `Home`, `Shell`, `Members`, `PasswordState`, `Description`, `SourcePath` | UAC `passwd` / `group` / `shadow`; shadow 僅衍生 password state，不複製 password hash |
| **uac_shell_history.csv** | CSV | `TimeUtc`, `User`, `Shell`, `CommandLine`, `SourcePath`, `LineNumber`, `Details` | UAC collected bash/zsh/fish/ksh/ash/PowerShell history；history 表示命令被記錄，不單獨證明成功執行 |
| **uac_persistence.csv** | CSV | `ModifiedTimeUtc`, `Platform`, `Mechanism`, `Scope`, `Name`, `User`, `Executable`, `Arguments`, `Trigger`, `EnabledState`, `KeyFingerprintSha256`, `SourcePath`, `LineNumber`, `Details` | UAC collected cron/anacron、systemd service/timer、`rc.local`、`ld.so.preload`、SSH `authorized_keys`、XML/binary launchd plist；設定存在不單獨證明執行、惡意性或目前啟用，SSH 僅保存 fingerprint |
| **uac_journal_files.csv** | CSV | `ModifiedTimeUtc`, `SourcePath`, `FileSizeBytes`, `State`, `FileId`, `MachineId`, `TailBootId`, `HeaderSize`, `ArenaSize`, `ObjectCount`, `EntryCount`, `HeadEntrySequence`, `TailEntrySequence`, `HeadEntryTimeUtc`, `TailEntryTimeUtc`, `CompatibleFeatures`, `IncompatibleFeatures`, `ParseStatus`, `Details` | UAC native `.journal` / `.journal~` 固定 header metadata；不宣稱已解析 individual entry payload |
| **uac_boot_sessions.csv** | CSV | `BootIndex`, `BootId`, `FirstEntry`, `FirstEntryUtc`, `LastEntry`, `LastEntryUtc`, `TimeParseStatus`, `SourcePath`, `LineNumber` | UAC `journalctl --list-boots` output；保留原始時間文字，僅在 timezone 可可靠解讀時填入 UTC |
| **uac_login_events.csv** | CSV | `Time`, `TimeUtc`, `EndTime`, `EndTimeUtc`, `TimeParseStatus`, `Action`, `User`, `Terminal`, `RemoteHost`, `RemoteAddress`, `ProcessId`, `RecordId`, `Duration`, `SourceType`, `SourcePath`, `LineNumber`, `Details` | UAC `last` / `lastb` / `lastlog` / `utmpdump` 文字輸出；僅在來源提供 numeric UTC offset 時填入 UTC，local time 不以收集時 offset 回推 |
| **uac_audit_events.csv** | CSV | `TimeUtc`, `AuditEventId`, `RecordTypes`, `Action`, `Success`, `Syscall`, `Executable`, `CommandLine`, `WorkingDirectory`, `User`, `AuditUserId`, `RealUserId`, `EffectiveUserId`, `SessionId`, `ProcessId`, `ParentProcessId`, `Terminal`, `RemoteAddress`, `RemoteHost`, `TargetPaths`, `SELinuxDecision`, `SourcePath`, `LineNumbers`, `Details` | UAC `/var/log/audit/audit.log*` plain/gzip；依 `audit(epoch:serial)` bounded grouping compound records，syscall 保留 raw numeric/name，不做 architecture-dependent 猜測，AVC 僅為 policy result |
| **uac_system_log_events.csv** | CSV | `Time`, `TimeUtc`, `TimeParseStatus`, `Host`, `Facility`, `Severity`, `Program`, `ProcessId`, `MessageId`, `Message`, `SourcePath`, `LineNumber`, `Details` | UAC Linux/macOS system-text logs plain/gzip；RFC 3164、RFC 5424、ISO timestamp；yearless/offset-less time 不虛構 UTC，PRI 僅解碼 facility/severity，fact action 固定為 `SystemLogMessageObserved` |
| **uac_packages.csv** | CSV | `ObservedAtUtc`, `InstallTimeUtc`, `InstallTimeParseStatus`, `Manager`, `Name`, `Version`, `Architecture`, `State`, `Scope`, `Publisher`, `Description`, `SourcePath`, `LineNumber`, `Details` | UAC dpkg/RPM/DNF/YUM/pacman/apk/Flatpak/Snap/Homebrew command outputs；RPM epoch 為 package DB metadata，其他以 acquisition reference time 作低信心 state observation，並非 row-level command time；不將 package presence 解讀為近期安裝、執行或惡意 |
| **uac_web_server_events.csv** | CSV | `Time`, `TimeUtc`, `TimeParseStatus`, `ServerType`, `EventType`, `RemoteAddress`, `RemotePort`, `User`, `VirtualHost`, `Method`, `RequestTarget`, `Protocol`, `StatusCode`, `ResponseBytes`, `Referrer`, `UserAgent`, `Severity`, `ProcessId`, `Message`, `SourcePath`, `LineNumber`, `Details` | UAC Apache/nginx Common/Combined access 與 default error logs plain/gzip；numeric offset 才填 UTC；remote/header 可由 proxy/client 控制，status/error message 不形成惡意 verdict |
| **uac_file_hashes.csv** | CSV | `Algorithm`, `Hash`, `Path`, `SourceKind`, `SourcePath`, `LineNumber`, `InputFormat` | UAC `hash_executables.{md5,sha1,sha256}` / `hash_running_processes.{md5,sha1,sha256}`；支援 UAC 可能選用的 checksum-path 與 named-digest 文字 envelope。每案最多 250,000 列、最多 64 個來源檔、單檔最多 512 MiB、單行最多 65,536 字元；hash/path 為無可靠 row timestamp 的低時間信心 observation，不代表檔案已執行或具有惡意性 |
| **uac_evidence_index.csv** | CSV | `ModifiedTimeUtc`, `RelativePath`, `SizeBytes`, `Sha256`, `Category`, `AnalysisStatus` | 所有 UAC 原始檔的逐檔證據索引；`normalized-source` / `parser-eligible` / `metadata-source` / `indexed-raw` |
| **uac_archive_entries.csv** | CSV | `OriginalPath`, `ExtractedPath`, `EntryType`, `LinkTarget`, `SizeBytes`, `Status` | ZIP/TAR intake entry 映射；Windows 非法檔名採可追溯改名，link 以 metadata 收容 |
| **analysis_workspace_v1.json** | JSON | `schema`, `tool_name`, `tool_version`, `generated_at_utc`, `source_format`, `source_evidence_sha256`, `evidence_digest`, `source_read_only`, `outputs[]` (`relative_path`, `size_bytes`, `sha256`) | 分析衍生物 manifest；位於 evidence root 之外，綁定本次 parser 輸出與來源 digest |
| **network_connections.txt** | Text (Raw) | Proto, Local Address, Foreign Address, State, PID | `netstat -ano` |
| **arp_table.txt** | Text (Raw) | Interface, Internet Address, Physical Address, Type | `arp -a` |
| **network_config.txt** | Text (Raw) | 完整網路介面設定 (IP, MAC, DHCP, DNS Server) | `ipconfig /all` |
| **dns_cache.txt** | Text (Raw) | Record Name, Record Type, Time To Live, Data Length, Section, A Record | `ipconfig /displaydns` |
| **logon_sessions.csv** | CSV | `ObservedAtUtc`, `StartTime`, `LogonId`, `User`, `Domain`, `Sid`, `LogonType`, `LogonTypeName`, `AuthenticationPackage`, `LogonProcessName` | LSA/WMI-based logon session enumeration |
| **network_resources.csv** | CSV | `ObservedAtUtc`, `LocalName`, `RemoteName`, `UserName`, `ConnectionState`, `ConnectionType`, `DisplayType`, `ProviderName`, `Persistent`, `Status`, `Comment` | `WNetOpenEnum` / `WNetEnumResource` |
| **server_connections.csv** | CSV | `ObservedAtUtc`, `ComputerName`, `UserName`, `ShareName`, `ActiveTimeSec`, `IdleTimeSec`, `ConnectionId`, `NumberOfFiles`, `NumberOfUsers` | `NetSessionEnum` |
| **stored_credentials.txt** | Text (Raw) | `ObservedAtUtc` header + `cmdkey /list` credential target / type / user blocks | `cmdkey /list` |
| **kerberos_tickets.txt** | Text (Raw) | `ObservedAtUtc` header + `klist` client / server / ticket flags / start-end-renew / KDC blocks | `klist` |
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
| **Registry/ShellBags_\<SID\>.reg** | REG (Text) | BagMRU/Bags 子樹（使用者曾開啟之資料夾路徑跡證）；平台內建 parser 之第一階段輸入 | `reg export` |
| **Registry/shellbags.csv** | CSV (UTF-8) | `Sid`, `User`, `BagPath`, `RegistryKey`, `ValueName`, `DecodedPath`, `MruSlot`, `LastWriteTime`（來源 `.reg` 檔 UTC mtime）, `ParserNote`, `SourceFile` | `ShellBagsParser`（匯入／收集後自動更新） |
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
| **jump_lists.csv** | CSV | `Time`, `Source`, `AppId`, `Path`, `User`, `Details` | `.automaticDestinations-ms` 以 bounded OLE-CFB reader 重組 FAT／DIFAT／miniFAT、directory 與 regular/mini streams，再解析 MS-SHLLINK LocalBasePath；非 CFB、損壞串流及 path-like A-Z／UNC／HTTP(S)／known-folder 目的地使用 bounded fallback。`Details` 記錄 `Parser`／`Fallback`／`ParserNote`，每檔最多 4,096 個去重目的地；fallback 狀態傳入 Fact provenance。目前本機對 JLECmd path recall 162/172（94.2%），完整 shell-item／Target IDList 尚未涵蓋。**另**經 `JumpListNormalizer` 入 Fact Store／Entity search／`full_log_v3`（facts-only）；**Unified Timeline** 經 `activity_timeline.csv` 之 JumpList 列呈現，不重複 merge 本檔 |
| **JumpLists/*.automaticDestinations-ms** | Binary | Jump List files (raw copy) | File Copy |
| **collection_coverage.json** | JSON | 收集覆蓋率報告；含 `collection_mode_profile`（本次收集作用中之 **Standard / TriageFast / ForensicStrict**；舊案卷可缺）、`operator_acknowledged_risks`、`restricted_steps`、`skipped_by_profile`、`output_target_class`（`system_disk / removable / network / unknown`）、`overall_status`、各 major artifact group 的 `complete / partial / failed / skipped / missing` 狀態（Memory 步驟另可反映略過或未產出 sidecar）、`completed_steps` / `partial_steps` / `failed_steps` / **`skipped_steps`** / **`missing_steps`**、present/missing artifacts、detail，以及 `collector_user / collector_privilege_state / backup_privilege_status` runtime context。若有 `missing_steps` 或 `skipped_by_profile`，overall 亦降為 `partial`；Event Logs 只有在每個 `.evtx` 都有對應 `*_filtered.csv` 時才會是 `complete` | Collector |
| **memory_acquisition.json** | JSON | 外部記憶體採集編排 sidecar（`schema=memory_acquisition_v2`）：`status`（complete/partial/failed/skipped 等）、工具路徑與參數、`args_preset`、輸出相對路徑、起迄 UTC、逾時設定、exit code、stdout/stderr 尾段、輸出檔大小與 SHA256、`validation_mode / validation_status / validation_detail`、`diagnostic_category / diagnostic_detail`、collector 是否管理員、設定旗標。不含映像解析 | `MemoryAcquisitionCollector` |
| **memory_analysis.json** | JSON | 外部記憶體分析 handoff sidecar（`schema=memory_analysis_v2`）：`status`、工具路徑與參數、`args_preset`、輸入 dump 相對路徑、分析輸出目錄、輸出檔清單/數量/總大小、起迄 UTC、逾時設定、exit code、stdout/stderr 尾段、`validation_mode / validation_status / validation_detail`、`required_output_patterns / matched_output_patterns / missing_output_patterns`、`diagnostic_category / diagnostic_detail`、collector 是否管理員。不含 dump verdict | `MemoryAnalysisCollector` |
| **Memory/*** | `.raw` / `.dmp` (Binary) | 使用者指定外部工具寫入之記憶體映像（檔名預設 `memory.raw`，可設定）；路徑限於 `Memory\` 下 | 外部工具（由 9SEC Evidence Workbench 呼叫） |
| **MemoryAnalysis/*** | text / CSV / JSON / tool-specific | 外部分析器寫入之 handoff 產物；平台僅收容與列示，不內建解析 | 外部工具（由 9SEC Evidence Workbench 呼叫） |
| **summary.json** | JSON | Summary/Counts/EventHighlights/FactSamples（facts-only manual export）；另含 `export_schema`、`analysis_mode`、`collection_mode_profile`（與 `collection_coverage.collection_mode_profile` 對齊；無 coverage 時可為空字串）、`parser_notes`、`collection_coverage`、`memory_acquisition`、`memory_analysis`、`fact_store_freshness_status/detail`、`fact_store_build_mode/generated_at/detail/inputs`、`analyst_workflow`、Fact source/entity type 統計，fact sample 可帶 `SourceFile` / `CollectionStep` / `CollectionStatus` / `CollectionPrivilege` / `ParseLevel` / `FallbackUsed` / `RawRef` / `ParserNote`。`parser_notes` 為跨來源 dedicated 摘要，不依賴 fact sample 排序；缺失 artifact counts 以 `0` 表示，缺失語意由 `collection_coverage` 承載 | GUI Export |
| **full_log_facts.json** | JSON | Full LOG facts-only envelope；含 `export_schema=full_log_v3`、`analysis_mode`、`host_count`、`fact_count`、`fact_source_counts`、`entity_type_counts`、`load_warnings`、`parser_notes`、`hosts[]` 摘要與 `facts[]` 完整明細（host 摘要可帶 `source_format` / `source_evidence_sha256` / `evidence_digest` / `uac` / `collection_mode_profile` / `collection_coverage_status` / `operator_acknowledged_risks` / `restricted_steps` / `skipped_by_profile` / `output_target_class` / `memory_acquisition` / `memory_analysis` / `fact_store_freshness_status` / `fact_store_freshness_detail` / `fact_store_build_mode/generated_at/detail/inputs` / `analyst_workflow`；每筆 fact 可帶 `SourceFile` / `CollectionStep` / `CollectionStatus` / `CollectionPrivilege` / `ParseLevel` / `FallbackUsed` / `RawRef` / `ParserNote`） | Dashboard Export |
| **ir_diff.json**（或指定路徑） | JSON | Case Diff facts-only envelope；含 `diff_schema=diff_v1`、tool/version、baseline/target references（含 collection coverage / Fact Store freshness）、變更計數、50,000 筆上限與截斷旗標，以及 Added / Modified / Removed changes。每筆 change 保留 category、entity key、來源、信心、雙側計數、雙側 fact references（含 collection/parse provenance）與 coverage caveat | GUI Diff Export / CLI `-diff` |
| **\<case>.zip.analyst.json / analyst_workflow.json** | JSON | 分析師 sidecar；保存 bookmark / priority / tags / hypothesis / notes，避免修改原始證據 ZIP | Summary Workflow Editor |
| **<evidence>.zip.sha256** | Text | ZIP SHA256（Hex, uppercase） | Internal SHA256 |
| **Prefetch/*.pf** | Binary | Windows Prefetch Files (Execution History, Run Count, Last Run) | File Copy |
| **LnkFiles/*.lnk** | Binary | Shortcut Files from Recent & Desktop (File Access History) | File Copy |
| **Browsers/*_History** | SQLite | 瀏覽器歷史紀錄 Database (Chrome/Edge/Firefox/Opera/Brave) | File Copy |

---

## 4. 介面規格 (UI Specification)

### 4.1 Local Collect（本機收集）
- **觸發**: 左側欄或按鈕「Local Collect」；需具備管理員權限以進行完整收集（含 MFT）。
- **流程**: 提示輸入證物編號 → 建立本次 collection policy 並分類輸出位置 → `ForensicStrict` 顯示限制與輸出風險，要求確認（預設二次確認）；未確認時在建立輸出目錄前取消 → 執行收集（System / Persistence / Event Logs / MFT / Registry / Browser / User Activity 等；外部記憶體工具是否執行由 profile 與 Settings 共同決定）→ 產出證物編號.zip 與對應 .sha256。
- **完成後**: 產出的 ZIP **自動載入平台**（等同 Import Case），案件出現在左側 Hosts List，可直接於右側分頁檢視 Summary、Timeline、MFT、Event Log 等；若已設定上傳端點且 profile 不是 `ForensicStrict`，則依 allowlist 嘗試上傳並顯示結果。
- **規格要點**: 本機收集完成後無需手動「Import Case」，平台會自動讀進該次收集的案卷，便於立即分析。

### 4.2 GUI (Graphical User Interface)
- **主視窗 (MainForm)**: 1300x850 (加大), 固定式雙欄設計。
- **功能表列 (Menu Strip)**: 位於視窗頂端，提供 `File` (Open Case, Clear all hosts, Exit), `Advanced` (Settings、Rebuild Selected Host Event Logs、Rebuild Selected Host Fact Store (full)、Rebuild Selected Host Fact Store (changed artifacts only) 等), `Help` (About)。**Settings** 管理 `AiApiEndpoint`、AI / Upload **分離**之 endpoint allowlist（`AiEndpointAllowlist`、`UploadEndpointAllowlist`；空清單阻擋對應出站 POST）、**AI Analyze** 專用之 `AiExportRedactionProfile`（`None` / `Basic` / `Strict`）、`FactStoreAutoBuild`、`FactStoreWriteSqlite`、預設關閉的 `FactStoreIncrementalCache` 與 cache 清除按鈕、`GuidedHuntEnabled`、`PostCollectDelaySeconds`、`ShowCollectionCompleteMessage`，以及 `RequireRemovableMediaConfirmation`、`WarnOnSystemDiskOutput`、`ForensicStrictSkipMemoryHandoff`、`ForensicStrictSkipDeepScan`、`ForensicStrictRequireSecondConfirmation` 五項可見的 profile safeguard。
- **標題列 (Header)**: 深色風格，包含 "☰" 側邊欄切換按鈕與 Application Title。
- **左側欄 (Sidebar)**（含 Local Collect、Import Case(s) 等）:
    - **Global Dashboard**: 獨立於列表上方，點擊顯示全域匯總；載入案卷時**預設自動建置 Fact Store**（Settings 可關閉）。含 **Correlation**（單一按鈕，下拉選單：**Find Common Artifacts** 跨主機共有、**Find Shared Entities** 跨主機實體 Pivot、**Back To Last Shared Pivot** 返回上一個共享實體清單、**Find Related Entities** 實體關聯、**Build Investigation Graph** 跨主機圖譜表、**Find Time-Window Entity Correlation** 跨主機＋同實體＋同時段、**Find Timeline Correlation** 跨主機＋同時段；`Find Shared Entities` 會沿用目前的 Entity type / filter 做跨主機彙整，且可雙擊結果列下鑽到 host-level facts，再雙擊某筆 fact 跳到對應 host 的 focused Facts tab）。Dashboard 另提供 `Source / Confidence / Host / From / To / Window` 篩選列，供共享實體、實體關聯、graph 與 time-window correlation 共用。`Build Investigation Graph` 旁新增 workspace 控制（`Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`、`Pin Edge`、`Open Facts`、`Open Timeline`）與 trail/pinned 摘要，支援 multi-step graph exploration；`Open Timeline` 會帶入 edge 的 entity、trail 與分鐘級時間窗，並以 structured entity match 優先。**Entity search**（類型：Path/FileName/Hash/User/RegistryKey/Provider/EventId/RemoteIP/RemoteName/ServiceName/TaskName/ThreatName/CommandLine/Computer/BitsJob/WmiFilter/WmiConsumer/Query/AppId/Interface/Publisher/ProductName/ProgramName/ProgramId）、Export full LOG JSON（匯出 `full_log_v3` facts-only envelope；移除所有主機資料（非僅 Fact Store）為 **File → Clear all hosts**；已移除「Build Fact Store (all hosts)」按鈕）。
    - **Hosts List**: 可收合/調整寬度，顯示載入的案件/主機列表。
- **右側欄 (Dynamic Host Tabs)**: 根據該 Host 擁有的 Artifacts 動態顯示，細分為：
    - **0. Summary**: 案件摘要（統計、事件重點、Load warnings、觀察事實摘要、collection coverage、fact_store freshness、parser notes）；coverage 顯示輸出分類、操作員確認、受限步驟與 profile 略過項目。Memory 區塊同時顯示 `Coverage` 與 `Sidecar`，避免把 sidecar `complete` 誤解成平台已完成記憶體分析；含 **Analyst Workflow** sidecar 編輯區（bookmark / priority / tags / hypothesis / notes，不修改原始 ZIP）；**Export Summary JSON**、**AI Analyze**、**Export HTML Report**。
    - **0. Timeline Analysis (全方位時間軸分析)**: **Virtual Grid** 整合 Process、MFT、EventLog（*_filtered.csv，含結構化欄位）、USN、BAM/DAM、BITS、Amcache、ShimCache Entries、SRUM Network/App、Activity（activity_timeline.csv：Registry/**JumpList（列來自已併入之 jump list，Source=JumpList；不重複讀 jump_lists.csv）**/Prefetch/Recent 等）；含 **Time Type / Confidence**、**Source 與時間區間篩選**、**Export CSV/JSON**；依時間倒序。若由 Investigation Graph 開啟，會先用 structured entity 聚焦，再在缺乏 entity ref 時退回文字比對。
    - **1. Basic Info (基礎資訊)**:
        - `System Info`: **Grid Visualization** (解析 Key:Value)。
        - `Processes`: 表格檢視 `process_list.csv`。
        - `Network`:
            - **IP Config**: TreeView 結構化顯示 Adapter 與屬性。
            - **Connections**: 表格顯示 Netstat (Proto, Local, Foreign, State, PID)。
            - **ARP / DNS**: 表格顯示相關紀錄。
        - `Stored Credentials`: 文字檢視 `stored_credentials.txt`。
        - `Kerberos Tickets`: 文字檢視 `kerberos_tickets.txt`。
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
        - `Diff`: 以目前 host 為 target，選擇另一個已載入且 Fact Store ready 的 case 為 baseline；依 Process / Persistence / File / Identity / Network / Fact 與 Added / Modified / Removed 篩選，支援 source filter、分頁、`Export JSON`、雙擊/Open Facts、Open Timeline。Added/Modified 導向 target，Removed 導向 baseline；所有跳轉使用 change 內實際 fact reference/provenance。
    - **4. File Activity (檔案活動)**:
        - `Recent Files`: 表格檢視 `recent_files.csv`。
        - `Recent Mod (7d)`: 表格檢視 `filesystem_7days.csv`（7 天內新增/修改檔案，含 SHA256）。
        - `Jump Lists`: 表格檢視 `jump_lists.csv`。
        - `Lnk Files`: 檢視已收集的快捷方式檔案列表 (Dump)。
        - `Prefetch`: 檢視已收集的 Prefetch 檔案列表 (Dump)。
    - **5. Integrity Check (完整性檢查)**:
        - `File Check`:
            - **Baseline**: 顯示收集時的 System32/Hosts/Startup 檔案 Hash。
            - **Deep Scan**: 介面按鈕，支援即時掃描 System32 所有執行檔；`ForensicStrictSkipDeepScan=1` 時阻擋，若允許執行但仍要求 strict 二次確認，則掃描前再次確認。

### 4.3 建議流程 (Recommended Workflow)
1. **取得案卷**: **Local Collect**（本機收集，完成後自動載入）或 **Import Case(s)**（匯入既有 folder / ZIP / TAR / TAR.GZ / TGZ），使左側 Hosts List 有案件、各 Case 具 read-only evidence root 與獨立 AnalysisPath。載入時**預設自動建置 Fact Store**（Settings「Auto Build Fact Store when case is loaded」可關閉）。UAC 封裝可直接匯入：平台保留來源 archive SHA-256、archive entry 映射與逐檔 evidence index，並在 analysis workspace best-effort 衍生 host/process/bodyfile/auth/audit/system-log/web-log/package/network/accounts/shell-history/persistence/journal-metadata/boot-session/login-event canonical CSV。來源內既有的 UAC canonical 同名檔不作為可信 parser output。所有未正規化檔案仍以 `indexed-raw` 收容與顯示；損壞 binary plist 不會被當成 launchd fact，native journal 的 individual entry payload 不會被描述成已解析，缺少可靠 offset 的 login/system-log/web-error/package observation time 不會被虛構成 UTC，audit/AVC/system-log/web/package facts 不會被當成自動惡意判定。
2. **檢視與篩選**: 在右側分頁依需檢視 Summary、Timeline Analysis、Basic Info、Persistence、Logs、File Activity、Integrity；Timeline Analysis 可篩選來源／時間並 **Export CSV/JSON**。
3. **關聯與差異分析**: 使用 **Facts**、**Diff**、**Entity search** 或 Dashboard correlation。Diff 需至少兩個 Fact Store ready 的 case；目前 host 為 target，另一案為 baseline。Added/Removed 只代表某一側未觀察到相同狀態，仍須核對 collection coverage。
4. **匯出**: Summary → **Export Summary JSON** / **Export HTML Report**；Timeline → **Export CSV/JSON**；Diff → **Export JSON** (`diff_v1`)；Dashboard → **Export full LOG JSON**。Phase B3：自動建置時可選寫入 SQLite。
5. **手動重建**: 若單一主機的 Event Log filtered CSV 或 Fact Store 需要刷新，可於 **Advanced** 或 Hosts list 右鍵選單使用 **Rebuild Selected Host Event Logs / Fact Store (full) / Fact Store (changed artifacts only)**；Event Log 項目依目前 `EventLogDays / EventLogMaxEvents` 重建 filtered CSV。Full 項目強制重跑所有 normalizer；changed-artifacts-only 需先啟用持久化 cache，只有 filtered Event Log 變更時局部重建，其他變更會以原因明確的 Full rebuild 降級。啟用 SQLite 寫入時仍會同步更新 `fact_store.db`。

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
- [x] **Fact Store**: 記憶體 FactStore、Entity 索引（HashSet 存 Fact，O(1) add/lookup）、GetByEntity/GetByTimeRange；載入案卷時預設於背景自動建置（Settings 可關閉），支援 Entity search。Fact 另帶 `TimeKind` / `TimeConfidence`，用來標示 timestamp 來源與可信度；目前已含 USN Journal normalizer。Evidence root 內預置的 `fact_store.db` 不載入為 facts，狀態標示 `untrusted_source` 並要求由 source artifacts 重建；只有本次 analysis workspace 產生的 SQLite 參與 freshness 檢查。**前置**：須先載入 Case（ExtractPath 存在）；Build 時從磁碟讀取各 CSV/XML（及已解析的 MftEntries），**目前預設寫入記憶體**，SQLite 持久化見 Phase B3。
- [x] **Incremental Fact Store Build Cache**: Settings 可選啟用目前使用者 Local Application Data 下的 gzip JSON cache（預設關閉，不寫入 evidence root）。每次 build 先重驗 evidence digest，並重新計算每個 input 的 `relative_path / size / mtime_utc / sha256 / normalizer_name`；exact match 直接 `Reused`，只有 `EventLogs/*_filtered.csv` 變更時局部重建受影響 facts，其他新增／刪除／變更、schema/tool/config 不相容或損毀 cache 均回退 `Full`。cache 原子寫入、ACL best effort 限目前使用者、壓縮 1 GiB／解壓 4 GiB 安全上限，並可由 Settings 清除。CSV 超過 100 MiB、500,000 列或讀取中斷會寫入 case Load warnings 與 exports。Summary 與 exports 保存 build mode、產生時間、原因與 input manifest。
- [x] **Manual Rebuild Entry**: UI 提供單一主機層級的 **Rebuild Selected Host Event Logs / Fact Store**。Event Log 重建會改寫該主機 `EventLogs/*_filtered.csv`；Fact Store 重建則會刷新記憶體中的 facts，並於啟用 SQLite 寫入時同步更新 `fact_store.db`。
- [x] **Cross-source Fact Correlation**: 以 Fact Store、Entity 索引與時間窗查詢支援分析師做跨來源比對，不在工具內直接執行內建規則判定。
- [x] **Event Log 收集優化**: 預設保留完整 EVTX，並同時輸出含 `Computer / UserId / TaskDisplayName / EventData` 的 filtered CSV 供 Timeline / Fact Store / Export 使用；config.ini EventLogDays/EventLogMaxEvents 控制 filtered 視窗與上限。
- [x] **Collection Coverage**: 收集完成時寫出 `collection_coverage.json`，記錄 major artifact groups 的 `complete / partial / failed / skipped / missing`、缺失 artifacts、runtime context，以及 collection profile、輸出分類、操作員確認、受限與 profile 略過步驟；若有 `missing` 或 enabled step 因 profile 略過，overall 亦降為 `partial`，CLI 回傳 exit code `4`。Summary / HTML / JSON 匯出會同步帶出，協助分析師區分「未觀察到」與「未成功收集」。
- [x] **Logger**: Utils/Logger.cs 集中記錄；ZipFile 取代 PowerShell 壓縮/解壓。
- [x] **Phase B3 SQLite**: Fact Store 持久化（拆欄 Id/Time/Source/EntityKey + JSON 欄 Details；SchemaVersion 3）。**實作**：Settings「Write Fact Store to SQLite when building」勾選後，Build Fact Store 時寫入各 host 之 analysis workspace `fact_store.db`，不回寫 evidence root；Dashboard「Export full LOG JSON」匯出 `full_log_v3` facts-only envelope（host 摘要、analyst workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要、完整 facts）；SQLite 以執行期載入 System.Data.SQLite.dll（DLL 未放置於 exe 同目錄時僅略過寫入）；`FactStorePersistence.LoadFromSqlite` 僅供受控內部／測試讀取，匯入 evidence root 內預置 DB 不會直接還原為本案 facts。**未來新增的 LOG**：凡納入 `FactStore.BuildFromCase` 即自動納入同一 JSON 輸出。Case Diff 另由兩案 Fact Store 產生 `diff_v1`，不新增 artifact-specific export；**Privacy redaction** 不實作。

### 5.1 已完成工程工作包與後續邊界
> `v0.22.0` 的歷史拆分見 [V0_22_ENGINEERING_SPEC.md](V0_22_ENGINEERING_SPEC.md)；Case Diff、Fact Store 增量快取與 Forensic Strict 的現行規格／驗收狀態見 [V0_25_ENGINEERING_SPEC.md](V0_25_ENGINEERING_SPEC.md)。

- [x] **Low Impact / Forensic Strict 模式**：完成輸出位置分類、系統碟強警示、明確風險確認與預設二次確認；Collector 未確認即 fail closed。預設略過 enabled memory acquisition / analysis handoff，阻擋 Deep Scan、ZIP 上傳及 AI Analyze，並將限制、略過與輸出分類完整寫入 coverage / Summary / HTML / JSON export。此模式明確不宣稱 zero-footprint。
- [x] **Memory handoff 一等公民化**：已補齊外部工具 preset、輸出驗證、常見失敗診斷，並以 sidecar-normalized 方式把 acquisition / analysis 摘要回填至 Fact Store、Timeline 與匯出；仍不解析 dump 內容。
- [x] **非 Event Log 的 lateral movement / identity 補強**：已納入 `logon_sessions.csv`、`network_resources.csv`、`server_connections.csv`、`stored_credentials.txt` (`cmdkey /list`) 與 `kerberos_tickets.txt` (`klist`) 等 sources，降低對 Security / TerminalServices 等日誌的單點依賴，並讓 Guided Hunt / Timeline / Entity pivot 可在弱日誌情境下仍保有調查線索。
- [x] **ShellBags 內建解析（WP-C，第一階段）**：`shellbags.csv` + Fact Store + UI + Timeline／Entity search；完整 Shell Item 還原與原機碼 LastWriteTime 仍屬未來範圍。
- [x] **Guided Hunt Pack（與 facts 分層）**：已提供可關閉的 ATT&CK 對映、可解釋規則、evidence lines 與 hypothesis templates；結果作為獨立 overlay 顯示於 Summary / HTML / `summary.json` / `full_log_v3`，不污染 Fact Store、也不輸出 verdict。
- [x] **Redaction / Endpoint Governance（WP-A）**：endpoint allowlist（AI / Upload 分離）、AI 出站 redaction profile（`None` / `Basic` / `Strict`）、AI 送出前 endpoint/profile 辨識；raw ZIP upload 僅治理不內容改寫。進階設定見 **Advanced → Settings**。
- [x] **Case Diff / Baseline Diff**：GUI Diff 分頁與 CLI `-diff` 已支援兩案 Fact Store 比較，涵蓋 Process / Persistence / File / Identity / Network / Fact 的 Added / Modified / Removed，提供 source/category/change filters、雙側 provenance、Facts / Timeline 下鑽、50,000 筆上限與 `diff_v1` 原子 JSON 匯出。
- [x] **Large Case Performance / Incremental Rebuild（WP-B 第一階段）**：完成 persistent build cache、exact reuse、filtered Event Log 局部重建、其他來源 fail-safe full fallback、GUI/CLI build mode 可見性與 cache 清除。非 Event Log 的 source-level partial rebuild 留待後續。

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
