# 9SEC Evidence Workbench

## 專案簡介
這是一個基於 C# 開發的 Windows 事件回應收集與跨平台證據分析工作台。
設計目標為**單一 Windows 執行檔 (Portable)**，無需安裝即可執行，支援 GUI 與 CLI；live collection 限 Windows，分析端可直接收容 Windows 案卷及 UAC 產生的 Linux/macOS folder、ZIP、TAR、TAR.GZ/TGZ 證據。

## 功能特色
1.  **免安裝**: 只需一個 `9SEC_Evidence_Workbench.exe` 檔案，支援 Win7 - Win11。
2.  **雙模式 (Hybrid Mode)**:
    *   **GUI 模式**: 視覺化儀表板，支援多案例匯入 (Case Manager)，具備 5 大類別導航與即時 Hash 掃描。
    *   **CLI 模式**: 使用 `9SEC_Evidence_Workbench.exe -c` 於背景快速收集證據 (System, Network, Logs, Files, MFT, etc.)。
3.  **Windows 收集面**: 涵蓋 System Info, Persistence (Autoruns/Tasks), Logs (Event/MFT/Registry), Browser History, File Artifacts (Lnk/Prefetch)。Registry 收集除 Hive／`ShellBags_<SID>.reg` 外，平台會自動產生第一階段結構化 **`Registry\shellbags.csv`**（供 Facts／Timeline／Entity search；非完整 ShellBags 鑑識還原器）。

## 使用說明

### 1. 編譯 (Build)
- **本機建置**：專案根目錄執行 `build.bat`，直接產出並簽章 `9SEC_Evidence_Workbench.exe`；憑證重用會同時確認 code-signing EKU 與私鑰實際可開啟，不會只因 `HasPrivateKey=true` 就誤選 provider 已失效的舊憑證。若使用本機自簽憑證且該 root 尚未受信任，輸出會明確顯示 `LocalSelfSignedUntrusted`；若 timestamp server 在離線或受限環境下不可達，簽章仍會保留，但輸出會明確顯示 `TimestampServerUnavailable` 與 `Timestamp signer: not attached`；若本機無法建立自簽 code-signing 憑證，則顯示 `SkippedLocalCertUnavailable`，避免誤判成一般建置失敗。
- **正式發佈**：執行 `build_release.bat`，先建立 `9SEC_Evidence_Workbench_release_candidate.exe`；release gate 要求有效簽章與可信時間戳，任一缺失都會 fail closed，不會升級或封裝候選檔。兩者驗證成功後才升級為正式版 `9SEC_Evidence_Workbench.exe`。
- **GitHub Release（僅 EXE 的 zip）**：執行根目錄 `publish_release.bat` 會先跑 `build_release.bat`，再產生 `dist\9SEC_Evidence_Workbench_vX.Y.Z.zip`（版本讀取 `docs\SPEC.md` 標頭約前 18 行內第一個 `vX.Y.Z`）。僅打包可使用 `publish_release.bat -SkipBuild`。已安裝 [GitHub CLI](https://cli.github.com/) 並 `gh auth login` 後，可 `publish_release.bat -Publish` 建立或上傳至現有 Release；細部參數見 `scripts\PackageRelease.ps1`。
- **自動化 regression review**：執行 `run_review_regression.bat`，會先建置 `9SEC_Evidence_Workbench_review.exe`（`INCLUDE_TESTS`），再跑 `9SEC_Evidence_Workbench_review.exe -test` 並輸出 `%TEMP%\9SEC_Evidence_Workbench_TestResult.txt`。若要做最終收斂檢查，可直接跑 `run_endpoint_gate.bat`，串起 regression 與正式 `build.bat`。
```cmd
build.bat          REM 本機建置
build_release.bat  REM 一鍵正式發佈
```
成功後皆產生 `9SEC_Evidence_Workbench.exe`。

### 專案文件 (Documentation)
以下文件皆位於本目錄 `docs/` 內。若在本專案之**公開 GitHub 鏡像**閱讀，目前與原始碼主倉同步釋出的通常為本表內之 FIELD_SOP／USER_MANUAL（雙語）/ SPEC / CHANGELOG／本 README；其餘檔案請另於完整開發工作區或對應發佈渠道取得。

**操作文件雙語慣例：** `FIELD_SOP.md` / `USER_MANUAL.md` 為 **英文**；`FIELD_SOP.zh-TW.md` / `USER_MANUAL.zh-TW.md` 為 **繁體中文**；各檔頂端可切換語言連結。

| 文件 | 說明 |
|------|------|
| **SPEC.md** | 開發規格、版本歷程、產出格式、功能規格、開發 Roadmap |
| **V0_22_ENGINEERING_SPEC.md** | `v0.22.0` 歷史工程拆分與實作基線；現況以 SPEC 與 v0.25 文件為準 |
| **V0_25_ENGINEERING_SPEC.md** | `v0.25.0` 工程規格與實作狀態：Case Diff、Fact Store 增量快取與 Forensic Strict |
| **REASONABLE_ENDPOINT_PLAN.md** | 現行合理終點、已完成工作包、defer 與維運邊界 |
| **CURSOR_ENGINEERING_PLAN.md** | 早期 Fact Store／Investigation Workspace 分期規劃（歷史文件） |
| **README.md** | 本文件：使用說明、DFIR 注意、版本摘要 |
| **FIELD_SOP.md** / **FIELD_SOP.zh-TW.md** | 現場短版 SOP（英文／繁中）：收集、初步判讀、多機關聯、交接與快速排錯 |
| **USER_MANUAL.md** / **USER_MANUAL.zh-TW.md** | 正式使用手冊（英文／繁中）：GUI / CLI / 匯入 / 調查流程 / 匯出 / 排錯 |
| **CHANGELOG.md** | 版本變更紀錄（Keep a Changelog 格式） |
| **ARTIFACTS.md** | 收集項目與可行性評估 |
| **SMOKE_RUN.md** | End-to-end smoke run 檢查清單（手動收集／匯入／檢視） |
| **REGRESSION_RUN.md** | review build + 內建 self-tests 的自動化回歸執行方式 |
| **SECURITY.md** | 潛在安全性風險檢測報告（輸入/路徑/敏感資料/命令/UI/規則/鑑識） |
| **CORRELATION_ARCHITECTURE.md** | Fact Store／Entity index／Timeline／Diff／Correlation／Graph 現行架構與歷史設計脈絡 |
| **SBOM.md** | 建置輸入、runtime dependencies、簽章與相依治理 |
| **DEMO.md** / **DEMO.zh-TW.md** | 合成雙主機案卷的離線分析導覽 |

**Agent 規則**以專案根目錄 `AGENTS.md` 為跨工具入口，並與 `.cursor/rules/ir-collect-agents.mdc` 保持同義。

### 2. 執行 (Usage)

#### 圖形介面 (GUI)
直接執行 `9SEC_Evidence_Workbench.exe` (建議以系統管理員身分執行以獲取完整資訊)。
- **Local Collect**: 開始在本機收集資訊；**收集完成後會自動將產出的 ZIP 載入平台**，無需手動 Import，可直接在左側主機列表與右側分頁檢視分析。
- **Import Case**: 匯入 ZIP、TAR、TAR.GZ/TGZ 或資料夾；可直接選擇 UAC (Unix-like Artifacts Collector) 原始封裝，不需先手動解壓。平台會先計算來源 archive SHA-256，安全解壓並建立 `uac_archive_entries.csv` 對照，再對原始檔建立逐檔 SHA-256 `uac_evidence_index.csv`。目前可正規化 `uac.log` / acquisition log、process snapshots、`bodyfile.txt`、auth/sudo logs、Linux auditd、Linux/macOS 系統文字日誌、Apache/nginx access/error logs、dpkg/RPM/DNF/YUM/pacman/apk/Flatpak/Snap/Homebrew 套件清單、`lsof` / `ss` / `netstat`、`passwd` / `group` / `shadow` 狀態、shell history、`last` / `lastb` / `lastlog` / `utmpdump` 登入歷程，以及 cron/anacron、systemd、`rc.local`、`ld.so.preload`、SSH `authorized_keys` 與 XML/binary launchd plist 持久化設定。`uac_web_server_events.csv` 解析 plain/gzip Common/Combined access log 與 Apache/nginx 預設 error envelope，保存 remote、virtual host、method、request target、status、referrer/user-agent、severity、PID 及來源行號；numeric offset 才產生 UTC。`uac_packages.csv` 保存 manager、name/version、architecture、state/scope、publisher 與來源行號；RPM queryformat epoch 可形成 install metadata time，其他套件輸出只以帶 offset 的 acquisition reference time 形成低信心 state observation，並非 row-level command time。一般系統日誌支援 plain/gzip `syslog`、`messages`、`kern.log`、`daemon.log`、`user.log`、`debug` 與 macOS `system.log`，解析 RFC 3164、RFC 5424 及 ISO timestamp；`auth.log` / `secure` 保留給認證解析器，不重複建立一般系統日誌 facts。Auditd 的 compound records 依相同 event ID 合併，保留 numeric/name syscall 原值、EXECVE command、CWD/PATH、identity、network 與 AVC policy result。Native `.journal` 另解析固定 header metadata，`journalctl --list-boots` 解析 boot range；逐筆 journal entry payload 仍保留為 raw evidence。登入、系統日誌、Web error 或套件觀察來源沒有可靠 numeric offset 時不虛構 UTC。
- **UAC file-hash intake**: `hash_executables.{md5,sha1,sha256}` 與 `hash_running_processes.{md5,sha1,sha256}` 會形成 `uac_file_hashes.csv`，保存演算法、digest、Unix path、來源類型與原始行號。支援 UAC 可能選用的 checksum-path 及 named-digest envelope；解析採 250,000 列、64 個來源檔、單檔 512 MiB、單行 65,536 字元上限。Facts 維持 untimed／低時間信心，只供 IOC、Diff、跨主機 correlation 與 graph pivot，不把 hash observation 當成執行或惡意 verdict。
- **Archive intake guardrails**: ZIP 先依 central directory 預掃，所有封裝皆受 entry、單檔、總展開量、壓縮比與可用空間限制。解壓先寫入同磁碟 `.partial-*` staging，僅在完整成功後發布；失敗、取消、截斷或超限不留下可載入的半成品案件。
- **Read-only analysis workspace**: Folder/archive 證據根目錄只讀；canonical CSV、離線重建 Event Log CSV、ShellBags、Fact Store cache 與 CLI 預設報告寫入獨立 `%TEMP%` 分析工作區。`analysis_workspace_v1.json` 記錄工具版本、來源 digest 及各衍生檔 SHA-256，可在 **Logs & Artifacts → Analysis Workspace Manifest** 檢視。UAC 來源內預先存在的同名 canonical 檔只保留為 raw evidence，不作為本次 parser 的可信輸出；analyst workflow 依來源 digest 保存於目前使用者 Local Application Data。
- **Atomic analysis outputs**: canonical CSV、離線 Event Log CSV、SQLite、workflow、workspace manifest 與 CLI JSON 先寫同目錄 temporary file，writer 完整關閉後才原子發布；失敗時保留既有完整版本並清理 partial file。
- **Case Diff / Baseline Diff**: 每個 host 的 **Diff** 分頁可選另一個已載入且 Fact Store ready 的 case 作 baseline，依 Process / Persistence / File / Identity / Network / Fact 與 Added / Modified / Removed 篩選，並可跳回 Facts 或 Timeline。CLI 可用 `-diff <baseline> <target> [out.json]` 直接比較 folder / ZIP / TAR / TAR.GZ / TGZ 並輸出 `diff_v1`。差異只代表兩側 facts 的觀察狀態，不把「未觀察到」宣稱為不存在。
- **Incremental Fact Store cache**: **Advanced → Settings** 可選擇把 normalized Fact Store 快取保存於目前使用者 Local Application Data（預設關閉）。輸入 SHA-256 全部相同時採 `Reused`；只有 `EventLogs/*_filtered.csv` 改變時採 `Incremental` 並只重跑受影響 EventLog normalizer；其他變更或快取異常會清楚降級為 `Full`。Summary、CLI、`summary_v3` 與 `full_log_v3` 會保留 build mode、時間、原因及 input manifest；快取含敏感 facts，可在 Settings 清除。
- **Deep Scan**: 於 File Check 頁面執行 System32 即時完整性掃描；`ForensicStrict` 預設阻擋此手動高 I/O 動作。
> 若設定 Upload Endpoint，Local Collect 結束後會自動上傳 ZIP 並顯示回應。**v0.22.0**：Upload 與 AI 各有 endpoint **allowlist**（**Advanced → Settings**）；清單為空時預設阻擋對應出站 POST。AI 摘要外送可選 **redaction profile**（僅影響 AI Analyze 的 JSON，不會改寫匯出之 `summary.json` 檔或 ZIP 內容）。**Collection mode profile**（Standard / TriageFast / ForensicStrict）亦在 Settings 設定：`ForensicStrict` 會分類預定輸出位置、強烈警示系統碟輸出、要求風險確認並預設要求第二次確認；同時預設略過已啟用的外部記憶體採集／分析 handoff，並阻擋 Deep Scan、ZIP 上傳與 **AI Analyze**。`collection_coverage.json` 與 analyst 匯出會記錄輸出分類、確認狀態、限制及 profile 略過項目。此模式不代表 zero-footprint、完整鑑識映像或絕對低擾動。

**建議流程**（詳見 **SPEC.md §4.3**）：取得案卷（Local Collect 或 Import）→ 載入時**自動建置 Fact Store**（預設開啟，可於 **Advanced → Settings** 關閉「Auto Build Fact Store when case is loaded」）→ 檢視/篩選各分頁與 Timeline → 使用 **Facts**、**Diff**、Entity search 與完整 LOG JSON 匯出。Dashboard 僅保留 **Export full LOG JSON** 與關聯分析按鈕；**File → Clear all hosts** 為移除所有已載入主機的資料（含解壓目錄與 Fact Store），非僅清除 Fact Store，不再提供「Build Fact Store (all hosts)」按鈕。
若需對單一主機手動重建分析資料，可使用 **Advanced → Rebuild Selected Host Event Logs / Fact Store (full) / Fact Store (changed artifacts only)**，或在 Hosts list 右鍵選單直接重建目前主機。Changed-artifacts-only 需先啟用持久化 Fact Store cache。

**設定檔與分析快取**：`config.ini` 內含 API Key、端點等敏感資料；持久化 Fact Store cache 則可能包含帳號、路徑、網路端點與命令列等 normalized facts。兩者都不應放在共用可寫位置。程式會嘗試把 cache ACL 限制為目前使用者；匯出設定時也會拒絕寫入系統目錄（如 Windows、Program Files）。詳見 **SECURITY.md**。

**記憶體採集（選用）**：於 **Advanced → Settings** 可開啟 `Memory acquisition` 區塊，指定外部工具路徑、**引數 preset**（`custom` = 下方欄位為完整模板；**非** `custom` = preset 先展開核心引數，再把下方欄位內容**接在後面**作額外參數，仍支援 `{OutputPath}` / `{OutputDir}`）。收集結果寫入 `memory_acquisition.json`，且出現在 `collection_coverage.json` 的 **Memory acquisition** 步驟；若 sidecar 宣稱 `complete` 但預期 dump 不存在，coverage 與寫入前的 sidecar reconcile 會標示失敗並以 `[Coverage]` / `[Reconciled]` 註記。Summary / HTML / `summary.json` / `full_log_v3` 會分開說明 `Coverage` 與 `Sidecar` 的語意。案卷內 `Memory\` 下為映像檔（可能很大）。`ForensicStrict` 預設略過已啟用的 memory acquisition，寫出 `skipped` sidecar 並將 coverage 降為 `partial`。本工具僅編排執行與稽核 metadata，不解析 dump。

**記憶體分析 handoff（選用）**：同一個 Settings 對話框內可再啟用 `Memory analysis handoff`，指定外部分析器、**dual-quoted / Custom preset** 與參考模板（`{InputPath}`、`{InputDir}`、`{OutputDir}`、`{CaseDir}`）。若案卷中已有 dump，平台會在收集階段把 dump 交給外部工具執行，並寫出 `memory_analysis.json` 與 `MemoryAnalysis\` 目錄下的工具輸出；輸出目錄必須是案卷下專用子目錄，平台會拒絕 case root 或既有保留證物目錄。寫入 sidecar 前會核對列舉的輸出檔是否仍存在於磁碟。`ForensicStrict` 預設略過已啟用的 handoff，並在 sidecar、coverage 與匯出中留下可稽核紀錄。Summary / HTML / `summary.json` / `full_log_v3` 只記錄 handoff 執行情況與輸出檔 accounting，並以統一說明區分 `Coverage` 與 `Sidecar`，不會把外部工具結果包裝成內建記憶體 verdict。

#### 命令列模式 (CLI)
在 Administrator CMD 或 PowerShell 中執行：
```cmd
9SEC_Evidence_Workbench.exe -c [EvidenceId]
```
若目前 profile 為 `ForensicStrict`，CLI 會先顯示輸出分類與受限步驟，要求輸入 `YES`；預設還需第二次輸入 `FORENSIC-STRICT`。任一確認失敗會以 exit code `3` 結束，且不建立收集輸出目錄。
或是查看說明：
```cmd
9SEC_Evidence_Workbench.exe --help
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
- [x] **Integrity**: System32 Baseline Check + Live Deep Scan；`ForensicStrict` 預設阻擋手動 Deep Scan。
- [x] **UI**: Grouped Navigation (Summary, Timeline Analysis, Basic, Persistence, Logs, Files, Integrity)；MFT/Event Log 篩選器；**Entity search**（含 Phase 3：`SubjectUser`、`TargetUser`、`ShareName`、`ShareLocalPath`、`Workstation`、`TargetServer`、`LogonType`、`LogonProcess`、`AuthenticationPackage`、`RemotePort`、`ProcessId` 等 lateral movement 實體，以及 Path/FileName/Hash/User/RegistryKey/Provider/EventId/RemoteIP/RemoteName/ServiceName/TaskName/ThreatName/CommandLine/Computer/BitsJob/WmiFilter/WmiConsumer/Query/AppId/Interface/Publisher/ProductName/ProgramName/ProgramId）。**WP-D**：`jump_lists.csv` 結構化進 Fact Store（`Source=JumpList`）；**BITS** `RemoteName` 可衍生與 Phase 3 對齊之 `ShareName`／`Workstation`／`RemoteIP`；Dashboard Correlation **Source** 可篩 **JumpList**。
- [x] **Signature Verification**: Process/Integrity CSV 加入簽章狀態與簽署者。
- [x] **Fact-based Analysis**: 以 Fact Store、Entity search、Timeline 與完整 LOG JSON 為主，避免內建 heuristic/rule 結論干擾分析判讀。
- [x] **Case Diff / Baseline Diff**: GUI host-level **Diff** 分頁與 CLI `-diff <baseline> <target> [out.json]` 共用 Fact Store 比較器；以主要 entity 分組，標示 Added / Modified / Removed，保留雙側 fact provenance、來源與 collection coverage 提示，最多輸出 50,000 筆並以 `changes_truncated` 明示截斷。`diff_v1` 契約見 `docs/schemas/diff_v1.schema.json`；不將未觀察到轉成存在性或惡意 verdict。
- [x] **Large Case / Incremental Fact Store**: 以每個 normalizer input 的相對路徑、大小、mtime、SHA-256 與 normalizer 名稱判斷 invalidation；exact match 可重用完整 facts，filtered Event Log 單獨變更可局部重建，其餘情況 fail-safe 回退 full rebuild。持久化 cache 預設關閉、位於 Local Application Data、原子寫入且可由 Settings 清除。
- [x] **UAC Evidence Intake**: GUI、`-analyze`、`-correlate`、`-graph` 共用 folder / ZIP / TAR / TAR.GZ / TGZ intake。所有 UAC 原始檔都會雜湊、分類、列入 UI Evidence Index 與 `UacEvidence` facts；process、bodyfile、auth/sudo、Linux auditd、Linux/macOS system-text logs、Apache/nginx web logs、package inventory、network、accounts、shell history、Linux/macOS persistence、journal header metadata、boot ranges 與 login events 另產生 canonical CSV 並進入 Fact Store / Timeline / Correlation / JSON export。`uac_web_server_events.csv` 支援 plain/gzip Apache/nginx Common/Combined access log 與預設 error envelope；每案最多 50,000 列、每檔最多解碼 268,435,456 個字元、每行最多 1,048,576 字元，request/header/message 有界限且保留 truncation marker。Access timestamp 含 numeric offset 才產生 `EventTime`；預設 error local time 維持 untimed。Remote address、referrer、user-agent 可能受 proxy/client 控制，HTTP status 只是 response outcome，均不形成惡意 verdict。自訂 JSON、ModSecurity audit、Tomcat 與不支援格式仍為 `indexed-raw`。`uac_packages.csv` 支援 UAC 官方 dpkg、RPM、DNF/YUM、pacman、apk、Flatpak、Snap 與 macOS Homebrew command outputs；每案最多 50,000 列、每個來源檔最多 64 MiB、每行最多 65,536 字元，canonical description/details 有界限且保留 truncation marker。RPM install epoch 是 package DB metadata time；其他輸出只以帶明確 offset 的 UAC acquisition reference time 作低信心 observation time，並非 row-level command time；缺少可靠時間則維持 untimed。錯誤/警告行不形成套件 fact，原始檔仍保留。套件存在不證明近期安裝、執行或惡意。`uac_system_log_events.csv` 支援 plain/gzip RFC 3164、RFC 5424 與 ISO timestamp，每案最多 50,000 列、每檔最多解碼 268,435,456 個字元、canonical message 最多 4,096 個字元；超限內容不改寫原始證據，並透過 warning / evidence index 保持可見。缺少年份或 numeric offset 時不產生 UTC；每列僅表示 message observed，不代表動作成功或惡意。`auth.log` / `secure` 僅走 auth normalizer，避免重複。`uac_audit_events.csv` 依 audit event ID 合併 SYSCALL / EXECVE / CWD / PATH / USER_* / AVC 等 records，支援 plain 與 gzip audit logs，並保留來源行號及 bounded-grouping 狀態；不將 audit/AVC 記錄轉成惡意 verdict。`uac_login_events.csv` 支援 UAC `last` / `lastb` / `lastlog` / `utmpdump` 文字輸出，無可靠 offset 的本地時間不轉成 UTC。`uac_persistence.csv` 支援 cron/anacron、systemd service/timer、`rc.local`、`ld.so.preload`、SSH `authorized_keys` 及 XML/binary launchd plist。`uac_journal_files.csv` 僅解析 native journal header，`uac_boot_sessions.csv` 解析 `journalctl --list-boots`；逐筆 binary journal entry、損壞/不支援 plist、瀏覽器資料庫與未實作格式仍為 `indexed-raw`；加密 ZIP 不在支援範圍。
- [x] **Fact Store**: 載入案卷時預設自動建置（可於 Settings 關閉）；含 Process/**LogonSession / NetworkResource / ServerConnection / StoredCredential / KerberosTicketCache**/Autorun/**Service**/ActivityTimeline/MFT/ScheduledTask/EventLog/USN/BAM/DAM/BITS/**Jump List**/WMI Persistence/**Amcache/ShimCache Entries/SRUM Network/SRUM App/ShellBags/Memory acquisition / Memory analysis handoff** Normalizer、實體索引與查詢，並保留 `TimeKind` / `TimeConfidence`；每筆 fact 另帶 `CollectionStep / CollectionStatus / CollectionPrivilege / ParseLevel / FallbackUsed / SourceFile / RawRef / ParserNote` provenance，不在工具內直接下判斷。UI 另提供 **Rebuild Selected Host Fact Store**，供分析師在單機層級手動刷新。
- [x] **Collection Coverage**: 收集完成時輸出 `collection_coverage.json`，標示 major artifact groups 為 `complete / partial / failed / skipped / missing`，並保留 `collector_user / collector_privilege_state / backup_privilege_status` runtime context；若有 `missing` 或啟用項目因 profile 略過，overall 會降為 `partial`。另記錄 `collection_mode_profile`、`operator_acknowledged_risks`、`restricted_steps`、`skipped_by_profile` 與 `output_target_class`。Event Logs 只有在每個 `.evtx` 都有對應 `*_filtered.csv` 時才會是 `complete`。Summary、HTML、Summary JSON 與 full LOG host 摘要都會帶出，避免把「沒看到」誤判成「不存在」。
- [x] **Low Impact / Forensic Strict**: 收集前分類輸出位置為 `system_disk / removable / network / unknown`，系統碟輸出有強警示並要求操作員確認，預設再要求第二次確認；已啟用的外部記憶體採集／分析 handoff 預設略過，手動 Deep Scan、收集後 ZIP 上傳與 AI Analyze 受阻擋。所有限制與略過項目可在 coverage 及分析匯出中稽核；此 profile 不宣稱 zero-footprint。
- [x] **Fact Store Cache Awareness**: 載入案卷時會檢查 `fact_store.db` 是否比目前 source artifacts 舊；若為 stale，Summary、匯出與 Load warnings 會標示，提醒分析師重建 Fact Store，而不是在不知情下沿用過期快取。
- [x] **Correlation / Investigation Workspace**: 以 Fact Store、Entity search 與時間範圍交叉比對為主，協助分析師自行判讀跨來源關聯；Dashboard 現含 **Find Shared Entities**、**Find Related Entities**、**Build Investigation Graph**、**Find Time-Window Entity Correlation**、**Back To Last Shared Pivot**，並支援 `Source / Confidence / Host / From / To / Window` 篩選。`Build Investigation Graph` 已升級為可持續探索的 workspace：可 `Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`、`Pin Edge`，且可用 host scope（all/edge hosts/host filter）限制後續展開；trail 上每一步會記住當時的篩選與 scope（導覽時先還原再重算 graph）。Selected edge 會隨結果集驗證，避免舊 edge 的主機列表在「Current edge hosts」下被誤用。`Open Timeline` 除切到該 host 外，會帶入 graph edge 的 entity 與 trail，並以**分鐘級**時間窗聚焦相關列；Timeline 會先做 structured entity match，只有在 row 沒有 entity ref 時才退回文字比對（可用「Show full timeline」還原）。
- [x] **Execution / Persistence Extensions**: 新增 `bam_dam.csv`、`bits_jobs.csv`、`wmi_persistence.csv`、`shimcache.csv`，並進一步補 `amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv`；同時保留 `ExecutionArtifacts\` raw `Amcache.hve` / `SRUDB.dat` / `SRUDB.log` / `SRUDB.jrs` 不被覆蓋。Host UI 可直接檢視上述結構化 CSV 與 raw execution artifacts。
- [x] **Parser Notes Visibility**: parser/fallback notes 不再只限於 Amcache；USN、ShimCache、Process 與 Event Log fallback 也會保留於 facts 與匯出。Summary/HTML/`summary.json`/`full_log_v3` 會用 dedicated parser-note 摘要顯示，不依賴 fact sample 截斷或時間排序。
- [x] **Amcache Parser Notes Dedup**: 同一批 `AmcacheParser.ParserNotes` 不再同時寫入 `amcache_programs.csv` 與 `amcache_files.csv`；normalizer 亦以 note 文字去重，避免同一 note 產生重複 facts 與膨脹 source counts。
- [x] **Analyst Workflow**: Summary 分頁新增 workflow sidecar（優先寫入 `<case>.zip.analyst.json`；若僅有解壓資料夾則寫入 `analyst_workflow.json`），保存 bookmark / priority / tags / hypothesis / notes，不修改原始證據 ZIP。
- [x] **AI Entry**: Summary JSON 匯出、AI 分析入口、**Export HTML Report**。Summary JSON 會帶 `export_schema=summary_v3`、`analysis_mode=facts_only`、`parser_notes`、Fact source/entity type 統計、`collection_coverage`、`fact_store_freshness_status/detail`、`analyst_workflow`，以及含 provenance 欄位的 fact samples；缺失 artifact counts 會正規化為 `0`，而不是負數 sentinel。**Export full LOG JSON** 亦改為 `full_log_v3` envelope，包含 host 摘要、workflow、load warnings、parser notes、collection coverage / fact store freshness 摘要與完整 facts，方便分析師或外部 AI 後續接手。
- [x] **Memory acquisition / analysis handoff**: 外部採集工具會寫 `memory_acquisition.json` 與 `Memory\*.raw|*.dmp`；若再啟用 handoff，外部分析器會針對既有 dump 產出 `memory_analysis.json` 與 `MemoryAnalysis\*`。兩者皆進入 `collection_coverage.json`、Summary / HTML / `summary.json` / `full_log_v3`，且 analyst-facing 輸出會同時顯示 coverage 與 raw sidecar 狀態，避免把外部工具 `complete` 誤解成平台已完成記憶體分析。平台本身仍不解析 dump、不輸出記憶體 verdict。
- [x] **Guided Hunt Pack (v1)**: 在 facts-only 模型之上新增可關閉的 explainable overlay；目前提供 ATT&CK-mapped 規則、evidence lines 與 hypothesis templates，涵蓋 RDP、SMB admin share、BITS、WMI、Autorun、Scheduled Task、Service path 與 credential-backed remote access 等調查 lead；`GH-CRED-001` 會同時參考 Event Log、`stored_credentials.txt` (`cmdkey /list`) 與 `kerberos_tickets.txt` (`klist`) 等 facts，但不回寫 Fact Store、也不輸出 verdict。
- [x] **Timeline Analysis (全方位時間軸)**: Process + MFT + EventLog + USN + BAM/DAM + BITS + **Amcache + ShimCache Entries + SRUM Network/App + Activity**（activity_timeline.csv；其中 **Jump List** 跡證已由 builder 併入，`Source=JumpList`，**不**再對 `jump_lists.csv` 重複匯入 Timeline）合併為單一時間軸；支援 **Time Type / Confidence**、**Source / 時間區間篩選**、**Export CSV/JSON**。時間篩選會 honor 到分鐘，不再把 graph handoff 視窗擴大成整天。（原 Activity Timeline 分頁已移除，活動資料於此檢視。）
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
