# IR Collector (IR_Collect)

## 專案簡介
這是一個基於 C# 開發的 Windows 事件回應 (Incident Response, IR) 收集工具。
設計目標為**單一執行檔 (Portable)**，無需安裝即可執行，並支援 GUI 與 CLI 兩種模式。

## 功能特色
1.  **免安裝**: 只需一個 `IR_Collect.exe` 檔案，支援 Win7 - Win11。
2.  **雙模式 (Hybrid Mode)**:
    *   **GUI 模式**: 視覺化儀表板，支援多案例匯入 (Case Manager)，具備 5 大類別導航與即時 Hash 掃描。
    *   **CLI 模式**: 使用 `IR_Collect.exe -c` 於背景快速收集證據 (System, Network, Logs, Files, MFT, etc.)。
3.  **全面收集**: 涵蓋 System Info, Persistence (Autoruns/Tasks), Logs (Event/MFT/Registry), Browser History, File Artifacts (Lnk/Prefetch)。

## 使用說明

### 1. 編譯 (Build)
- **本機建置**：專案根目錄執行 `build.bat`，直接產出並簽章 `IR_Collect.exe`；若使用本機自簽憑證且該 root 尚未受信任，輸出會明確顯示 `LocalSelfSignedUntrusted`；若本機無法建立自簽 code-signing 憑證，則顯示 `SkippedLocalCertUnavailable`，避免誤判成一般建置失敗。
- **正式發佈**：執行 `build_release.bat`，先建立 `IR_Collect_release_candidate.exe`，簽章成功後再升級為正式版 `IR_Collect.exe`。
- **GitHub Release（僅 EXE 的 zip）**：執行根目錄 `publish_release.bat` 會先跑 `build_release.bat`，再產生 `dist\IR_Collect_vX.Y.Z.zip`（版本讀取 `docs\SPEC.md` 標頭約前 18 行內第一個 `vX.Y.Z`）。僅打包可使用 `publish_release.bat -SkipBuild`。已安裝 [GitHub CLI](https://cli.github.com/) 並 `gh auth login` 後，可 `publish_release.bat -Publish` 建立或上傳至現有 Release；細部參數見 `scripts\PackageRelease.ps1`。
- **自動化 regression review**：執行 `run_review_regression.bat`，會先建置 `IR_Collect_review.exe`（`INCLUDE_TESTS`），再跑 `IR_Collect_review.exe -test` 並輸出 `%TEMP%\IR_Collect_TestResult.txt`。若要做最終收斂檢查，可直接跑 `run_endpoint_gate.bat`，串起 regression 與正式 `build.bat`。
```cmd
build.bat          REM 本機建置
build_release.bat  REM 一鍵正式發佈
```
成功後皆產生 `IR_Collect.exe`。

### 專案文件 (Documentation)
以下文件皆位於本目錄 `docs/` 內。若在本專案之**公開 GitHub 鏡像**閱讀，目前與原始碼主倉同步釋出的通常為本表內之 FIELD_SOP / USER_MANUAL / SPEC / CHANGELOG／本 README；其餘檔案請另於完整開發工作區或對應發佈渠道取得。
| 文件 | 說明 |
|------|------|
| **SPEC.md** | 開發規格、版本歷程、產出格式、功能規格、開發 Roadmap |
| **README.md** | 本文件：使用說明、DFIR 注意、版本摘要 |
| **FIELD_SOP.md** | 現場短版 SOP：收集、初步判讀、交接與快速排錯 |
| **USER_MANUAL.md** | 正式使用手冊：GUI / CLI / 匯入 / 調查流程 / 匯出 / 排錯 |
| **CHANGELOG.md** | 版本變更紀錄（Keep a Changelog 格式） |
| **ARTIFACTS.md** | 收集項目與可行性評估 |
| **SMOKE_RUN.md** | End-to-end smoke run 檢查清單（手動收集／匯入／檢視） |
| **REGRESSION_RUN.md** | review build + 內建 self-tests 的自動化回歸執行方式 |
| **SECURITY.md** | 潛在安全性風險檢測報告（輸入/路徑/敏感資料/命令/UI/規則/鑑識） |
| **CORRELATION_ARCHITECTURE.md** | Fact Store／關聯引擎架構設計 |

**Cursor/Agent 規則** 位於專案根目錄 `.cursor/rules/ir-collect-agents.mdc`（alwaysApply，無須放在 docs 內）。

### 2. 執行 (Usage)

#### 圖形介面 (GUI)
直接執行 `IR_Collect.exe` (建議以系統管理員身分執行以獲取完整資訊)。
- **Local Collect**: 開始在本機收集資訊；**收集完成後會自動將產出的 ZIP 載入平台**，無需手動 Import，可直接在左側主機列表與右側分頁檢視分析。
- **Import Case**: 匯入之前收集的 ZIP/資料夾。
- **Deep Scan**: 於 File Check 頁面執行 System32 即時完整性掃描。
> 若設定 Upload Endpoint，Local Collect 結束後會自動上傳 ZIP 並顯示回應。

**建議流程**（詳見 **SPEC.md §4.3**）：取得案卷（Local Collect 或 Import）→ 載入時**自動建置 Fact Store**（預設開啟，可於 **Advanced → Settings** 關閉「Auto Build Fact Store when case is loaded」）→ 檢視/篩選各分頁與 Timeline → 使用 **Facts** 分頁、Entity search 與完整 LOG JSON 匯出。Dashboard 僅保留 **Export full LOG JSON** 與關聯分析按鈕；**File → Clear all hosts** 為移除所有已載入主機的資料（含解壓目錄與 Fact Store），非僅清除 Fact Store，不再提供「Build Fact Store (all hosts)」按鈕。
若需對單一主機手動重建分析資料，可使用 **Advanced → Rebuild Selected Host Event Logs / Fact Store**，或在 Hosts list 右鍵選單直接重建目前主機。

**設定檔 (config.ini)**：內含 API Key、端點等敏感資料，請勿放在共用的可寫目錄，並建議限制檔案權限（僅當前使用者可讀寫）。匯出設定時程式會拒絕寫入系統目錄（如 Windows、Program Files），請選擇使用者目錄或桌面。詳見 **SECURITY.md**。

**記憶體採集（選用）**：於 **Advanced → Settings** 可開啟 `Memory acquisition` 區塊，指定外部工具路徑與參數（預設空參數將以引號傳遞完整輸出路徑）。收集成功與否會寫入 `memory_acquisition.json`，且出現在 `collection_coverage.json` 的 **Memory acquisition** 步驟；若 sidecar 宣稱 `complete` 但預期 dump 不存在，coverage 會降級，Summary / HTML / `summary.json` 會分開顯示 `Coverage` 與 `Sidecar`，避免把外部工具回傳碼誤讀成實際採集成功。案卷內 `Memory\` 下為映像檔（可能很大）。本工具僅編排執行與稽核 metadata，不解析 dump。

**記憶體分析 handoff（選用）**：同一個 Settings 對話框內可再啟用 `Memory analysis handoff`，指定外部分析器與參數（支援 `{InputPath}`、`{InputDir}`、`{OutputDir}`、`{CaseDir}`）。若案卷中已有 dump，平台會在收集階段把 dump 交給外部工具執行，並寫出 `memory_analysis.json` 與 `MemoryAnalysis\` 目錄下的工具輸出；輸出目錄必須是案卷下專用子目錄，平台會拒絕 case root 或既有保留證物目錄。Summary / HTML / `summary.json` / `full_log_v3` 只會記錄 handoff 執行情況與輸出檔，且同樣分開顯示 `Coverage` 與 `Sidecar`，不會把外部工具結果包裝成內建記憶體 verdict。

#### 命令列模式 (CLI)
在 Administrator CMD 或 PowerShell 中執行：
```cmd
IR_Collect.exe -c [EvidenceId]
```
或是查看說明：
```cmd
IR_Collect.exe --help
```
### DFIR 現場保護（是否破壞現場）

本工具為 **Live Response** 收集：僅**讀取**系統與磁碟上的資料，並將結果寫入**輸出目錄**（預設為執行目錄下的 `IR_Output_<ID>`），**不刪除、不修改**原始登錄、事件日誌或檔案內容。

| 項目 | 說明 |
|------|------|
| **登錄** | 僅讀取／匯出（`reg save`、`reg export`），不寫回系統登錄。 |
| **事件日誌** | 僅匯出（`wevtutil epl` 或 EventLogReader 讀取），不修改原始 .evtx。 |
| **MFT** | 僅讀取 `\$MFT` 或磁區，不寫入受調查磁碟。 |
| **檔案** | 僅讀取與複製到輸出目錄（如 LNK、Prefetch、Browser），不刪改原始檔。 |

**仍可能對現場造成的影響**（可透過操作方式降低）：

1. **寫入輸出目錄**  
   若輸出目錄在**受調查磁碟**（例如 C:\），會寫入大量新檔案並產生 ZIP，可能覆寫未配置空間或殘餘資料。  
   **建議**：將程式放在**外接磁碟**執行，或先 `cd` 到外接磁碟再執行，使 `IR_Output_*` 與 ZIP 寫在外接裝置。

2. **最後存取時間 (LAT)**  
   讀取檔案時，部分系統設定下可能更新檔案的「最後存取時間」。Windows 10+ 預設常關閉此更新（`NtfsDisableLastAccessUpdate=1`），影響較小。

3. **揮發性狀態**  
   執行本程式會新增程序、載入 DLL，可能產生 Prefetch、頁面檔等紀錄，屬於任何 Live Response 工具共通的現象；若需極小化變動，可考慮先做記憶體擷取再於離線環境分析。

**結論**：設計上盡量**只讀不寫受調查系統**；若要最大程度保護現場，請將**輸出寫到外接儲存裝置**，並避免在受調查磁碟上建立輸出目錄。

### 收集階段部分失敗的處理

部分項目可能因權限或路徑限制而部分失敗，程式已做下列處理，方便事後對帳與重試：

| 項目 | 改進 |
|------|------|
| **UserActivity** | 拒絕存取、路徑過長時改為**彙總計數**，結束時輸出「Skipped: N access denied, M path too long」，不再對每一筆寫 log。 |
| **Prefetch** | 未以管理員執行時略過，並在 `logs/ir_collect.log` 寫入一筆說明，便於稽核。 |
| **Registry** | 收集前啟用 **SeBackupPrivilege**（子行程可繼承），結束時輸出「System hives: X/4 saved」（SECURITY 常需 LocalSystem 才可存）。 |
| **Event Log** | 單一 log 匯出失敗時**自動重試一次**（間隔 1 秒），結束時若有失敗則輸出「N exported, M failed」。 |

整次收集不會因單一子項目失敗而中斷；請依主控台摘要與 `logs/ir_collect.log` 確認哪些成功、哪些失敗。

- **打包後暫存目錄**：壓縮完成後預設會**刪除**暫存目錄（`IR_Output_<ID>`），僅保留 ZIP 與 `.sha256`。若需保留暫存目錄以便除錯，可在 `config.ini` 設 `DeleteOutputDirAfterZip=0`。

## 目錄結構
- `src/`
    - `Program.cs`: 程式入口。
    - `MainForm.cs`: 視覺化分析介面 (5-tab layout)。
    - `Collector.cs`: 收集邏輯控制器。
- `Analysis/`: 案卷載入、Summary 匯出、Fact Store／關聯分析。
    - `Collectors/`: 各類跡證收集模組 (System, Log, Registry, Browser, Prefetch, Integrity...)。
    - `MFT/`: RAW NTFS MFT 解析器。
    - `Utils/`: 共用工具與集中式 Logger。
- `build.bat`: 本機建置腳本；`build_release.bat`: 正式版建置／簽章腳本。

## 目前狀態 (Current Status)
- [x] **Core Collection**: System, Network, Process, Software.
- [x] **Advanced Artifacts**: MFT Parsing (動態系統碟、run list、完整 MACB), Registry Hives, **ShellBags** (`Registry\ShellBags_<SID>.reg`)，Event Logs (預設同時保留完整 `.evtx` 與分析用 `*_filtered.csv`), Browser History.
- [x] **File Activity**: Recent Files, Recent Mod 7d (SHA256), Lnk/Prefetch/Jump Lists (Dump + CSV).
- [x] **Integrity**: System32 Baseline Check + Live Deep Scan.
- [x] **UI**: Grouped Navigation (Summary, Timeline Analysis, Basic, Persistence, Logs, Files, Integrity)；MFT/Event Log 篩選器；**Entity search**（含 Phase 3：`SubjectUser`、`TargetUser`、`ShareName`、`ShareLocalPath`、`Workstation`、`TargetServer`、`LogonType`、`LogonProcess`、`AuthenticationPackage`、`RemotePort`、`ProcessId` 等 lateral movement 實體，以及 Path/FileName/Hash/User/RegistryKey/Provider/EventId/RemoteIP/RemoteName/ServiceName/TaskName/ThreatName/CommandLine/Computer/BitsJob/WmiFilter/WmiConsumer/Query/AppId/Interface/Publisher/ProductName/ProgramName/ProgramId）。
- [x] **Signature Verification**: Process/Integrity CSV 加入簽章狀態與簽署者。
- [x] **Fact-based Analysis**: 以 Fact Store、Entity search、Timeline 與完整 LOG JSON 為主，避免內建 heuristic/rule 結論干擾分析判讀。
- [x] **Fact Store**: 載入案卷時預設自動建置（可於 Settings 關閉）；含 Process/Autorun/ActivityTimeline/MFT/ScheduledTask/EventLog/USN/BAM/DAM/BITS/WMI Persistence/**Amcache/ShimCache Entries/SRUM Network/SRUM App** Normalizer、實體索引與查詢，並保留 `TimeKind` / `TimeConfidence`；每筆 fact 另帶 `CollectionStep / CollectionStatus / CollectionPrivilege / ParseLevel / FallbackUsed / SourceFile / RawRef / ParserNote` provenance，不在工具內直接下判斷。UI 另提供 **Rebuild Selected Host Fact Store**，供分析師在單機層級手動刷新。
- [x] **Collection Coverage**: 收集完成時輸出 `collection_coverage.json`，標示 major artifact groups 為 `complete / partial / failed / skipped / missing`，並保留 `collector_user / collector_privilege_state / backup_privilege_status` runtime context；若有 `missing` 亦會把 overall 狀態降為 `partial`。Event Logs 只有在每個 `.evtx` 都有對應 `*_filtered.csv` 時才會是 `complete`。Summary、HTML、Summary JSON 與 full LOG host 摘要都會帶出，避免把「沒看到」誤判成「不存在」。
- [x] **Fact Store Cache Awareness**: 載入案卷時會檢查 `fact_store.db` 是否比目前 source artifacts 舊；若為 stale，Summary、匯出與 Load warnings 會標示，提醒分析師重建 Fact Store，而不是在不知情下沿用過期快取。
- [x] **Correlation / Investigation Workspace**: 以 Fact Store、Entity search 與時間範圍交叉比對為主，協助分析師自行判讀跨來源關聯；Dashboard 現含 **Find Shared Entities**、**Find Related Entities**、**Build Investigation Graph**、**Find Time-Window Entity Correlation**、**Back To Last Shared Pivot**，並支援 `Source / Confidence / Host / From / To / Window` 篩選。`Build Investigation Graph` 已升級為可持續探索的 workspace：可 `Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`、`Pin Edge`，且可用 host scope（all/edge hosts/host filter）限制後續展開；trail 上每一步會記住當時的篩選與 scope（導覽時先還原再重算 graph）。Selected edge 會隨結果集驗證，避免舊 edge 的主機列表在「Current edge hosts」下被誤用。`Open Timeline` 除切到該 host 外，會帶入 graph edge 的 entity 與 trail，並以**分鐘級**時間窗聚焦相關列；Timeline 會先做 structured entity match，只有在 row 沒有 entity ref 時才退回文字比對（可用「Show full timeline」還原）。
- [x] **Execution / Persistence Extensions**: 新增 `bam_dam.csv`、`bits_jobs.csv`、`wmi_persistence.csv`、`shimcache.csv`，並進一步補 `amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv`；同時保留 `ExecutionArtifacts\` raw `Amcache.hve` / `SRUDB.dat` / `SRUDB.log` / `SRUDB.jrs` 不被覆蓋。Host UI 可直接檢視上述結構化 CSV 與 raw execution artifacts。
- [x] **Parser Notes Visibility**: parser/fallback notes 不再只限於 Amcache；USN、ShimCache、Process 與 Event Log fallback 也會保留於 facts 與匯出。Summary/HTML/`summary.json`/`full_log_v3` 會用 dedicated parser-note 摘要顯示，不依賴 fact sample 截斷或時間排序。
- [x] **Amcache Parser Notes Dedup**: 同一批 `AmcacheParser.ParserNotes` 不再同時寫入 `amcache_programs.csv` 與 `amcache_files.csv`；normalizer 亦以 note 文字去重，避免同一 note 產生重複 facts 與膨脹 source counts。
- [x] **Analyst Workflow**: Summary 分頁新增 workflow sidecar（優先寫入 `<case>.zip.analyst.json`；若僅有解壓資料夾則寫入 `analyst_workflow.json`），保存 bookmark / priority / tags / hypothesis / notes，不修改原始證據 ZIP。
- [x] **AI Entry**: Summary JSON 匯出、AI 分析入口、**Export HTML Report**。Summary JSON 會帶 `export_schema=summary_v3`、`analysis_mode=facts_only`、`parser_notes`、Fact source/entity type 統計、`collection_coverage`、`fact_store_freshness_status/detail`、`analyst_workflow`，以及含 provenance 欄位的 fact samples；缺失 artifact counts 會正規化為 `0`，而不是負數 sentinel。**Export full LOG JSON** 亦改為 `full_log_v3` envelope，包含 host 摘要、workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要與完整 facts，方便分析師或外部 AI 後續接手。
- [x] **Memory acquisition / analysis handoff**: 外部採集工具會寫 `memory_acquisition.json` 與 `Memory\*.raw|*.dmp`；若再啟用 handoff，外部分析器會針對既有 dump 產出 `memory_analysis.json` 與 `MemoryAnalysis\*`。兩者皆進入 `collection_coverage.json`、Summary / HTML / `summary.json` / `full_log_v3`，且 analyst-facing 輸出會同時顯示 coverage 與 raw sidecar 狀態，避免把外部工具 `complete` 誤解成平台已完成記憶體分析。平台本身仍不解析 dump、不輸出記憶體 verdict。
- [x] **Timeline Analysis (全方位時間軸)**: Process + MFT + EventLog + USN + BAM/DAM + BITS + **Amcache + ShimCache Entries + SRUM Network/App + Activity**（activity_timeline.csv）合併為單一時間軸；支援 **Time Type / Confidence**、**Source / 時間區間篩選**、**Export CSV/JSON**。時間篩選會 honor 到分鐘，不再把 graph handoff 視窗擴大成整天。（原 Activity Timeline 分頁已移除，活動資料於此檢視。）
- [x] **Event Log**: 預設完整 `.evtx` + filtered CSV 雙輸出（`EventLogDays=0` 代表使用預設 7 天分析窗；`>0` 為自訂窗）；filtered CSV 另含 `Computer / UserId / TaskDisplayName / EventData` 結構化欄位，供 Fact Store、Timeline、Summary 與 AI 匯出共用；**Phase 3** 針對橫向移動／身分濫用相關事件加深正規化（如 4624–4625、4648、4672、4768–4769、4776、5140/5145、1149、4688、4697、4698/4702、7045），actions 為描述性語意（如 `KerberosServiceTicketRequested`、`ExplicitCredentialUsed`、`ShareAccessChecked`、`RemoteDesktopAuthenticated`），並強化 `SubjectUser` / `TargetUser` 與 SMB path 等實體；`5145` 存取之 `RelativeTargetName` 以 `Path` 呈現。若載入的是 **EVTX-only** 舊案卷，平台會於匯入時離線重建 `*_filtered.csv`，分析窗以各 `.evtx` 內**最新事件時間**為錨點回推；EVTX 檢視支援 **Description | Parsed fields | Raw XML**。UI 另提供 **Rebuild Selected Host Event Logs**。手動 fixture：`scripts/phase3_lateral_movement_fixture.csv`。
- [x] **Logger**: 集中記錄 (logs/ir_collect.log)；**ZipFile** 壓縮/解壓（無需 PowerShell）。
- [x] **Phase B3**: Fact Store 可選寫入 SQLite（Settings 勾選；各 host `ExtractPath\fact_store.db`；SchemaVersion 3）；**Export full LOG JSON**（Dashboard，`full_log_v3` envelope：`analysis_mode=facts_only`、host 摘要、workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要、完整 facts）；未放置 System.Data.SQLite.dll 時僅略過 SQLite 寫入。同 DLL 亦用於 **BrowsingHistoryView** Chrome/Firefox「Last visit」欄位（有則顯示造訪時間）。
- [x] **Jump Lists**：CSV 產出含 Path；解析 .automaticDestinations-ms / .customDestinations-ms 內 LNK 結構（MS-SHLLINK）擷取 LocalBasePath，減少 Custom 項目 Path 為空。
- [x] **案卷 Temp 清理**：關閉程式或右鍵「Clear Host Data」時自動刪除 %TEMP% 下該案解壓目錄。
- [x] **Process User**: process_list.csv 的 User 欄位已由 WMI Win32_Process.GetOwner 補齊（另含 PPID/SessionId/ThreadCount/WorkingSetSize）。
- [x] **Memory acquisition / handoff**: 已支援外部記憶體採集工具編排與後續外部分析 handoff；平台保留 sidecar 與輸出檔，不內建 dump 解析。

**MFT Browser 空白時**：MFT 資料來自「已載入案卷」內的 `MFT_Dump.bin` 或 `mft_preview.csv`。若為空，表示 (1) 尚未執行 Local Collect 或未匯入含 MFT 的案卷，或 (2) 收集時 MFT 步驟失敗（即使以系統管理員執行，仍可能因防毒、$MFT 鎖定等失敗）。請以**系統管理員**執行 Local Collect，完成後案卷會自動載入；若仍無 MFT，請查看 `logs/ir_collect.log` 是否有 MFT 相關錯誤。

**ShellBags 解析**：收集產出 `Registry\ShellBags_<SID>.reg`（含 BagMRU/Bags）。還原使用者曾開啟的資料夾路徑與時間請使用外部工具，例如 [Eric Zimmerman ShellBags Explorer](https://github.com/EricZimmerman/ShellBags)，載入案卷內上述 .reg 或 UsrClass_\<SID\>.dat。

## 最近更新 (Recent Updates)

- **v0.18.6**：Event Log 可拉伸線改為「資訊區(表格)｜Per page」之間；MFT View Path/Max size 標籤完整顯示。
- **2026-04-08 acceptance hardening**：`collection_coverage` 的 Event Logs 需逐 log 對上 EVTX/filtered CSV 才算 `complete`；Summary/HTML/`summary.json` 統一顯示跨來源 parser notes 與 Memory `Coverage / Sidecar`；Timeline graph handoff 改為 structured entity match + 分鐘級時間窗。
- **v0.18.5**：Event Logs Event ID/Source 標籤顯示完整；Event detail 資訊區可拉伸與垂直捲軸；MFT View 標籤簡短、Apply/Reset 可見（AutoScroll）。
- **v0.18.4**：Dashboard 圖示並排與 Entity search 間隔；Timeline/Per page/MFT View 標籤不裁切與間隔；Event Log 篩選不遮與搜尋；Event detail View 不遮選單、選項無 "View:"。
- **v0.18.3**：Timeline From/To/Source 間距與字顯示；Per page 不遮下拉、分頁列右移；MFT View Path 長度與間距、Min/Max 篩選 Refresh 生效。
- **v0.18.2**：Recent Files 僅 LNK、排除 desktop.ini；Lnk Dump 先複製再寫 CSV；MFT View 篩選不遮、Min/Max 防呆；Timeline Source/CSV・JSON 對齊；USN Journal 篩選區與 Reset/Exclude 寬度修正。
- **v0.17.9**：Settings 對話框補齊（AI/Upload 端點與 Key、EventLogDays/MaxEvents、DeleteOutputDirAfterZip）；Activity Timeline 日期防呆（From/To 1980–2100、From>To 自動對調）；About/AssemblyInfo 0.17.8。
- **v0.17.8**：VirusTotal hash 僅允許 32/64 字元十六進位；MFT 磁碟代號強制 A–Z；設定匯出拒絕系統目錄；規則引擎 Regex 逾時 2 秒防 ReDoS。
- **v0.17.5–v0.17**：分頁列與 USN 篩選區 UX、LOG 分頁（五類、自動切頁）、BrowsingHistoryView 瀏覽時間、Jump List Path 解析、案卷 Temp 自動清理、Event Log 詳情 View/背景載入、CSV/USN 表格 NotSortable。

**完整版本歷程**見 **CHANGELOG.md**；Roadmap 與 Backlog 見 **SPEC.md §5–6**。
