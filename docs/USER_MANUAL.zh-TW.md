# 9SEC Evidence Workbench 使用手冊

[English](USER_MANUAL.md) | **繁體中文**

本手冊面向操作人員與事件調查分析師，重點是「如何使用工具完成收集、匯入、檢視與匯出」，不涵蓋開發與發版細節。若只需要現場短版流程，請先看 **[FIELD_SOP.zh-TW.md](FIELD_SOP.zh-TW.md)**（繁體）或 **[FIELD_SOP.md](FIELD_SOP.md)**（英文）。規格與版本歷程見 `SPEC.md`，變更紀錄見 `CHANGELOG.md`，技術文件索引見 `README.md`。本手冊對齊 `v0.25.1`。閱讀其他 tag 或使用其他 binary 時，請以其 `-version`、release notes 與同 tag 文件為準。

## 1. 工具定位

`9SEC Evidence Workbench` 是一個在 Windows 執行的事件回應與證據分析工具，支援：

- Windows 本機證據收集
- Windows 案卷與 UAC Linux/macOS folder/archive 匯入
- GUI / CLI 雙模式操作
- 多主機案件管理
- Fact Store、Entity search、Timeline、Investigation Graph 關聯分析
- Summary JSON、完整 LOG JSON、HTML 報告匯出
- 選用的外部記憶體採集與外部記憶體分析 handoff

Local Collect 屬於 **Live Response**；folder/archive 分析會維持 evidence root 唯讀，但本工具
仍不是完整的離線磁碟映像鑑識平台。

## 2. 使用前準備

### 2.1 建議環境

- Windows 7 到 Windows 11
- 建議以系統管理員執行，才能取得較完整的 Event Log、Registry、Prefetch、MFT 等資料
- 建議從外接儲存裝置執行，並讓輸出寫到外接儲存裝置

### 2.2 現場操作注意事項

- 工具會讀取系統資料，但仍會在輸出目錄寫入新檔案
- 執行工具本身可能留下 Prefetch、頁面檔等執行痕跡
- 若輸出寫到受調查磁碟，可能增加現場變動
- 高嚴謹鑑識場景下，建議先做記憶體擷取，再進行後續分析

### 2.3 敏感設定

`config.ini` 可能包含：

- `VirusTotalApiKey`
- `AiApiKey`
- `UploadApiKey`
- Upload / AI endpoint
- `AiEndpointAllowlist` / `UploadEndpointAllowlist`（以 `|` 分隔的 URL 前綴；**空清單**則阻擋該管道出站 POST）
- `CollectionModeProfile`（`Standard` / `TriageFast` / `ForensicStrict`；與其他選項一併於 **Advanced → Settings** 設定）
- `AiExportRedactionProfile`（`None` / `Basic` / `Strict`；**僅**影響 **AI Analyze** 要 POST 的 JSON）
- Event Log 視窗與上限
- 暫存目錄是否在打包後刪除

建議：

- 將 `config.ini` 放在僅當前操作者可讀寫的位置
- 不要將 `config.ini` 放在共用且可寫的目錄
- 不要把 AI / Upload endpoint 指向未受控的外部服務
- 於 **Advanced → Settings** 設定 **AI** 與 **Upload** 各自允許的 `http(s)://主機:埠/路徑前綴`；**allowlist 為空時，該管道預設不允許 POST**，直到至少加入一筆與設定之 endpoint 相符的前綴
- **AI Analyze** 會依 **redaction profile** 處理「即將送出」的 JSON；**匯出 Summary JSON** 與 **ZIP 上傳**不會被 profile 改寫內容（上傳僅做允許／拒絕目的地）
- **Collection mode profile**：`collection_coverage.json` 與 analyst 匯出（`summary.json`、`full_log_v3` 的 host 摘要、以及 Summary／HTML／parser notes 於有案卷紀錄時）會帶入本次模式。**TriageFast** 以標記與收集前提示為主。**ForensicStrict** 會分類預定輸出位置、強烈警示系統碟輸出、要求明確風險確認，且預設再做第二次確認；同時預設略過已啟用的外部記憶體採集／分析 handoff，並禁止手動 **Deep Scan**、**AI Analyze** 與 Local Collect 後自動 **ZIP 上傳**。限制與 profile 略過項目會保留於 coverage 和匯出。此模式**不**主張 zero-footprint、鑑識映像或單靠本工具即構成完整低擾動鑑識方案。

## 3. 五分鐘快速上手

### 3.1 GUI 快速流程

1. 執行 `9SEC_EvidW.exe`
2. 建議接受 UAC 並以系統管理員身分執行
3. 在 Dashboard 按 `Local Collect`
4. 輸入 `Evidence ID`
5. 等待收集完成
6. 工具會自動載入剛產生的 ZIP
7. 先看 `Summary`
8. 再看 `Timeline Analysis`、`Facts`、`Event Logs`
9. 需要交接時匯出 `Summary JSON`、`HTML` 或 `Export full LOG JSON`

### 3.2 CLI 快速流程

```cmd
9SEC_EvidW.exe -c
9SEC_EvidW.exe -c Case001
9SEC_EvidW.exe --help
```

說明：

- `-c` 不帶參數時會自動產生 `Evidence ID`
- `-c <ID>` 會使用指定的證物編號
- `ForensicStrict` 下需先輸入 `YES`，預設再輸入 `FORENSIC-STRICT`；任一確認取消會以 exit code `3` 結束，且 Collector 尚未建立輸出目錄
- 收集完成後會產生 ZIP 與對應的 `.sha256`

## 4. GUI 操作說明

### 4.1 啟動後主畫面

主畫面分成兩個區域：

- 左側 `Hosts List`：顯示已載入的主機或案卷
- 右側分析區：依主機顯示對應分頁

尚未載入案卷時，右側主要是 Dashboard 與功能入口。

### 4.2 Local Collect

用途：

- 在目前主機直接執行收集
- 適合現場 first-response

操作：

1. 按 `Local Collect`
2. 輸入 `Evidence ID`
3. 等待收集完成與打包
4. 完成後工具會自動匯入剛生成的 ZIP

完成後通常會得到：

- `<EvidenceId>.zip`
- `<EvidenceId>.zip.sha256`
- 若 `DeleteOutputDirAfterZip=1`，中間輸出目錄會被刪除

### 4.3 Import Case

用途：

- 匯入先前收集好的 ZIP
- 匯入已解壓的案卷資料夾
- 匯入多個主機後進行跨主機比對

匯入後預設會：

- 將案卷解壓到暫存位置
- 自動建立 Fact Store
- 在 Hosts List 中新增主機

若已關閉 `Auto Build Fact Store when case is loaded`，則匯入後不會自動建立 Fact Store。

UAC 證據中的 executable 與 running-process checksum lists 會顯示為
`uac_file_hashes.csv` 及 `UacFileHash` facts。這些是 untimed 的路徑／digest observation，
可供 IOC 與跨主機 pivot，但不證明檔案已執行或具有惡意性。

### 4.4 Dashboard 常用功能

Dashboard 是全域分析入口，常用按鈕如下：

- `Find Shared Entities`
- `Find Related Entities`
- `Build Investigation Graph`
- `Find Time-Window Entity Correlation`
- `Back To Last Shared Pivot`
- `Export full LOG JSON`

建議先匯入所有需要比對的主機，再進行 Dashboard 層級的跨主機關聯分析。

### 4.5 Summary

Summary 是每台主機最先要看的分頁。建議閱讀順序：

1. `collection_coverage`
2. `load warnings`
3. `parser notes`
4. `event highlights`
5. `memory acquisition / memory analysis`
6. `fact store freshness`
7. `analyst workflow`

Summary 可做的事：

- 看本機收集是否完整
- 看哪些步驟為 `partial`、`failed`、`missing`
- 看 parser fallback 是否影響判讀
- 編輯 analyst workflow sidecar
- 匯出 `Summary JSON`
- 匯出 `HTML Report`
- 進入 AI 分析入口（若 endpoint 不在 **AI allowlist**，將無法 POST；送出前會顯示 endpoint 與 redaction profile）

### 4.6 Timeline Analysis

用途：

- 將多來源資料合併成單一時間軸
- 依來源、時間窗、Time Type / Confidence 篩選
- 匯出 CSV / JSON

目前 Timeline 會整合的重點來源包含：

- Process
- MFT
- Event Log
- USN
- BAM / DAM
- BITS
- Amcache
- ShimCache Entries
- SRUM Network / App
- Activity Timeline
- **ShellBags**（當案卷內已有 `Registry\shellbags.csv` 時）

ShellBags 列於時間軸時，若 CSV 帶有時間戳，屬 **ObservedTime** 且信心為 **low**：該時間為來源 `ShellBags_*.reg` 匯出檔之 **UTC LastWriteTime**，**並非**登錄機碼在系統上的 LastWriteTime（`.reg` 匯出不包含逐鍵時間戳）。

若是從 Investigation Graph 按 `Open Timeline` 開啟：

- 工具會帶入 graph edge 對應的 entity 與 trail
- 預設以分鐘級時間窗聚焦
- 可用 `Show full timeline` 還原完整時間軸

### 4.7 Facts

`Facts` 分頁是正規化後的觀察事實，不是工具下的結論。建議將它視為：

- 快速檢視同一主機上可關聯的結構化事件
- 驗證某一個 Entity 是否在多個來源同時出現
- 檢查 provenance 與 parser note

每筆 Fact 可能包含：

- Time
- Time Type / Confidence
- Source
- Action
- Entities
- Details
- CollectionStep / CollectionStatus / CollectionPrivilege
- ParseLevel / FallbackUsed / ParserNote
- SourceFile / RawRef

### 4.8 Diff

先載入至少兩個案卷，並等兩側 Fact Store 都 ready。在 target host 的 **Diff** 分頁：

1. 選另一個案卷作為 **Baseline**
2. 選 `All`、`Process`、`Persistence`、`File`、`Identity`、`Network` 或 `Fact`
3. 依 `Added`、`Modified`、`Removed` 與可選 source 文字篩選
4. 雙擊結果或按 `Open Facts`；需要確認時間關係時按 `Open Timeline`
5. 用 `Export JSON` 匯出 `diff_v1`

`Added`、`Modified` 會導向 target；`Removed` 會導向 baseline。若雙側都有對應觀察，
change 會保留兩側 fact reference 與 provenance。

這些結果是觀察狀態差異。某側缺少 fact 可能來自收集覆蓋率、parser 支援、收集時間或
保留週期不同，不能直接當成 artifact 不存在的證明。

### 4.9 Event Logs

Event Logs 分頁可檢視：

- 原始 `.evtx`
- 離線重建或收集時生成的 `*_filtered.csv`

事件詳情支援：

- `Description`
- `Parsed fields`
- `Raw XML`

若案卷只有 `.evtx` 而沒有 `*_filtered.csv`，工具會在匯入時嘗試離線重建分析用 CSV。

### 4.10 Investigation Graph

適合用來追：

- 橫向移動
- 帳號濫用
- 共用 Path / Hash / User / RemoteIP
- 同時間窗異常活動

常用操作：

- `Expand From Selected Edge`
- `Back`
- `Forward`
- `Reset To Original Seed`
- `Pin Edge`
- `Open Facts`
- `Open Timeline`

建議做法：

1. 先用 `Find Shared Entities` 找共同實體
2. 挑出可疑 entity 建圖
3. 用 `Expand From Selected Edge` 逐步展開
4. 適時用 `Open Timeline` 回到時間軸驗證

### 4.11 Rebuild Selected Host Event Logs / Fact Store

功能項目：

- `Rebuild Selected Host Event Logs`：重建該主機的 `*_filtered.csv`
- `Rebuild Selected Host Fact Store (full)`：重跑所有 normalizer
- `Rebuild Selected Host Fact Store (changed artifacts only)`：使用持久化 cache；exact match 直接重用，只有 filtered Event Log 變更時局部重建

適用情境：

- 匯入的是舊案卷
- 更新了 `EventLogDays` 或 `EventLogMaxEvents`
- Summary 提示 `fact_store.db` 已 stale
- 想重新整理單一主機分析資料，而不是清掉所有案卷

Changed-artifacts-only 必須先在 Settings 啟用 **Persist Fact Store cache in Local AppData**。
若變更的是非 Event Log input、cache metadata 不相容或 cache 無法讀取，系統會自動回退
Full rebuild 並顯示原因。這是為了維持正確性，不是 partial-success。

### 4.12 Clear all hosts

`File -> Clear all hosts` 會：

- 清除所有已載入主機
- 移除暫存解壓資料
- 一併清除對應 Fact Store

這不是只清掉分析結果，而是整批移除已載入資料。

## 5. CLI 操作說明

### 5.1 基本命令

```cmd
9SEC_EvidW.exe -c
9SEC_EvidW.exe -c Case001
9SEC_EvidW.exe -analyze <資料夾或封裝> [out.json]
9SEC_EvidW.exe -diff <基線> <目標> [out.json]
9SEC_EvidW.exe -correlate <out.json> <路徑A> <路徑B> [...]
9SEC_EvidW.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <路徑...>
9SEC_EvidW.exe -version
9SEC_EvidW.exe --help
```

`--collect` 是 `-c` 的 alias；`--version` 是 `-version` 的 alias；`-h` 是 `--help` 的
alias。

### 5.2 CLI 典型用途

- 遠端桌面到主機後快速落地收集
- 用既有工具鏈批次呼叫
- 現場只想要案卷，不需要馬上進 GUI 分析
- 不開 GUI，直接對 folder/archive 做唯讀分析與 baseline 比較

`-diff` 的 baseline 與 target 都可使用 folder、ZIP、TAR、TAR.GZ 或 TGZ。省略輸出路徑時，
工具會在目前目錄把完整報告原子發布為 `ir_diff.json`。

分析 CLI 會顯示 Fact Store build mode（`Full`、`Incremental` 或 `Reused`）及重用／回退原因。
只有目前使用者啟用持久化 cache 時才可能重用；預設仍是完整的記憶體內建置。

`-c` 在 `ForensicStrict` 下會先列出輸出分類與受限步驟。需輸入 `YES`，若啟用第二次
確認則再輸入 `FORENSIC-STRICT`；取消會以 exit code `3` 在收集輸出建立前結束。

### 5.3 CLI 產出

收集完成後應至少看到：

- `Case001.zip`
- `Case001.zip.sha256`

若部分步驟失敗：

- 收集不會因單一子項失敗而整體中斷
- 請檢查終端機摘要與 `logs/ir_collect.log`
- 後續在 GUI Summary 中查看 `collection_coverage`

## 6. 輸出與檔案說明

### 6.1 收集階段核心產物

- `*.zip`：證據包
- `*.zip.sha256`：ZIP SHA256
- `collection_coverage.json`：各步驟收集狀態，以及 profile、風險確認、受限步驟、profile 略過與輸出分類
- `logs/ir_collect.log`：執行紀錄

### 6.2 常見 artifact 類型

- `system_info_full.txt`
- `process_list.csv`
- `services.csv`
- `autoruns_registry.csv`
- `scheduled_tasks.xml`
- `EventLogs\*.evtx`
- `EventLogs\*_filtered.csv`
- `MFT_Dump.bin`
- `mft_preview.csv`
- `usn_journal.csv`
- `recent_files.csv`
- `filesystem_7days.csv`
- `jump_lists.csv`
- `file_integrity.csv`
- `Registry\ShellBags_*.reg`、`Registry\shellbags.csv`（後者為平台解析列，供 UI／Fact Store；若 `.reg` 較新會於匯入時重算）
- `bam_dam.csv`
- `bits_jobs.csv`
- `wmi_persistence.csv`
- `amcache_programs.csv`
- `amcache_files.csv`
- `shimcache.csv`
- `shimcache_entries.csv`
- `srum_network_usage.csv`
- `srum_app_usage.csv`

匯入 UAC 證據時，analysis workspace 可能另含：

- `uac_evidence_index.csv`；archive input 另有 `uac_archive_entries.csv`
- `analysis_workspace_v1.json`（來源 digest、工具身分與衍生輸出 SHA-256 manifest）
- `uac_auth_events.csv`、`uac_audit_events.csv`、`uac_system_log_events.csv`、`uac_web_server_events.csv`
- `uac_network_connections.csv`、`uac_accounts.csv`、`uac_packages.csv`、`uac_shell_history.csv`
- `uac_persistence.csv`、`uac_journal_files.csv`、`uac_boot_sessions.csv`、`uac_login_events.csv`
- `uac_file_hashes.csv`（支援 executable/running-process 的 MD5、SHA-1 與 SHA-256 清單）

以上皆為 parser 在唯讀 evidence root 之外建立的衍生檔；不支援的輸入仍會在
`uac_evidence_index.csv` 中以 `indexed-raw` 保持可見。

### 6.3 分析與匯出產物

下列檔案多數是匯入後或由 GUI 匯出產生，不一定存在於原始收集 ZIP：

- `summary.json`
- `full_log_v3` 對應 JSON 匯出
- HTML report
- `fact_store.db`
- `analyst_workflow.json`
- `<case>.zip.analyst.json`

### 6.4 Memory 相關產物

若啟用外部記憶體採集：

- `Memory\*.raw`
- `Memory\*.dmp`
- `memory_acquisition.json`

若再啟用外部分析 handoff：

- `MemoryAnalysis\*`
- `memory_analysis.json`

重點：

- `memory_acquisition.json` / `memory_analysis.json` 是 orchestration 與 metadata
- 外部工具 sidecar 顯示 `complete` 不等於實際輸出一定存在
- 以 `collection_coverage` 的 `Coverage` 為準確認實際收集是否完整

## 7. collection_coverage 狀態判讀

`collection_coverage.json` 會標示每個 major step 的狀態：

- `complete`：預期 artifact 都在
- `partial`：有收成功，但不完整
- `failed`：執行失敗
- `skipped`：被略過或未啟用
- `missing`：預期有東西，但實際找不到對應 artifact

建議判讀原則：

- 先看 `overall_status`
- 再看 `collection_mode_profile`、`output_target_class`、`operator_acknowledged_risks`
- 檢查 `restricted_steps` 與 `skipped_by_profile`
- 再看哪一個 step 不是 `complete`
- 最後對照 `artifacts_missing`、`detail` 與 `logs/ir_collect.log`

對調查最重要的是，不要把 `missing` 解讀成「該活動不存在」。
若 enabled step 因 profile 略過，overall 會刻意標為 `partial`；這不是 collector failure，
但仍是必須納入判讀的證據覆蓋限制。

## 8. 建議調查流程

### 8.1 單機 triage

1. 執行 `Local Collect`
2. 看 `Summary`
3. 看 `Timeline Analysis`
4. 看 `Facts`
5. 查 `Event Logs`
6. 必要時匯出 `Summary JSON` 與 HTML

### 8.2 橫向移動調查

1. 匯入多台主機
2. 先用 `Find Shared Entities`
3. 聚焦可疑帳號、RemoteIP、Share、Service、Task
4. 建 `Investigation Graph`
5. 用 `Open Timeline` 驗證時間關係
6. 匯出完整 LOG JSON 交由他人或外部流程接手

**缺少關鍵 Event Log**（例如無 Security／TerminalServices 篩選匯出）時，可改以非日誌 facts 做 pivot：**Entity search**／Dashboard **Source** 選 **JumpList**（`jump_lists.csv`：`Path`、`User`、`AppId`、UNC 衍生欄位）、**BITS**（工作 `RemoteName` 衍生之 `ShareName`、`Workstation`、`RemoteIP`）、**SRUM**（`RemoteIP`、`AppId`、`Path`）。皆為跡證觀察事實，工具內建不輸出惡意判定。

### 8.3 可疑程式執行調查

1. 看 `Processes`
2. 看 `Timeline Analysis` 是否出現同一路徑、Hash、User
3. 看 `Prefetch`、`Jump Lists`、`Recent Files`
4. 看 `Amcache`、`ShimCache Entries`
5. 必要時檢查 `MFT` 與 `USN`

### 8.4 Persistence 調查

1. 看 `Autoruns`
2. 看 `Scheduled Tasks`
3. 看 `Services`
4. 看 `BAM / DAM`
5. 看 `WMI Persistence`
6. 最後回到 `Facts` 做關聯

## 9. 進階功能

### 9.1 Auto Build Fact Store

預設為開啟。優點：

- 匯入後可以直接查 Facts
- 可以直接做 Entity search
- 可以直接做完整 LOG JSON 匯出

若關閉：

- 匯入速度可能較快
- 但關聯分析功能會受限

### 9.2 Write Fact Store to SQLite when building

啟用後會在每台主機的獨立 analysis workspace 寫入 `fact_store.db`，不修改 evidence root。匯入證據中已存在的 DB 只保留為 raw evidence，必須由 source artifacts 重建後才使用。

適合：

- 大型案卷
- 後續重複分析
- 需要保存分析中介層

注意：

- 若未提供 `System.Data.SQLite.dll`，SQLite 寫入可能會被略過
- GUI 仍可運作，但會少一層持久化

### 9.3 Persist Fact Store cache in Local AppData

預設**關閉**。啟用後，normalized facts 與 input fingerprint manifest 會寫入：

```text
%LOCALAPPDATA%\9SEC Evidence Workbench\FactStoreCache\
```

建置模式：

- `Reused`：所有 input SHA-256 fingerprints 完全相符
- `Incremental`：只有 filtered Event Log CSV inputs 改變
- `Full`：無 cache、強制重建、其他 input 改變、metadata 不相容或 cache 無法讀取

Cache 採原子發布，並以 best effort 將 ACL 限制為目前使用者。內容可能包含帳號、路徑、
命令列、網路端點及其他 normalized evidence。案件結束或交接前，可使用
**Clear persistent Fact Store cache** 清除；此操作不會刪除來源證據、analysis workspace
或 `fact_store.db`。

目前限制：source-level partial rebuild 只支援 filtered Event Log CSV。其他來源一旦改變，
會刻意回退完整重建。

### 9.4 ForensicStrict 保護措施

下列五項都可在 **Advanced → Settings** 看見並由 `ConfigManager` 保存：

- 輸出不是 removable media 時要求確認
- 輸出位於 Windows 系統碟時警示
- 略過外部 memory acquisition 與 analysis handoff
- 阻擋手動 Deep Scan
- 要求第二次 `ForensicStrict` 確認

輸出分類為 `system_disk`、`removable`、`network`、`unknown`。一般非系統本機固定磁碟
仍分類為 `unknown`，工具不會假設它是可信任的外接媒體。Collector 會依實際輸出路徑
重新計算 policy，Strict 未確認時會在建立輸出目錄前拒絕執行。這些措施用來降低可避免
的現場活動，但不會讓 live response 成為 zero-footprint。

### 9.5 Memory acquisition

用途：

- 呼叫外部工具做記憶體擷取
- 由本工具統一記錄時間、輸出、exit code、SHA256、權限脈絡

設定：

- **Arguments preset**：`custom` 時下方欄位為**完整**引數模板；**非** `custom` 時下方欄位為接在 preset 核心之後的**額外**參數（仍可做 `{OutputPath}` / `{OutputDir}` 展開）
- `collection_coverage.json` 的 **Coverage** 會以磁碟為準與 `memory_acquisition.json` 交叉檢查；不一致時 Detail 會含 `[Coverage]`
- 寫入 sidecar 前若預期 dump 仍不存在，可能另註記 `[Reconciled]`（與 `[Coverage]` 的說明並列於 Summary / HTML / `summary.json` / `full_log_v3` 的共用提示）
- 預設 `ForensicStrict` policy 會在不啟動外部工具的情況下寫出 `skipped` sidecar，並列入 `skipped_by_profile`

限制：

- 不內建採集驅動
- 不解析 dump
- 可能需要大量磁碟空間

### 9.6 Memory analysis handoff

用途：

- 把已有 dump 交給外部分析器
- 將外部工具輸出收進案卷

設定：

- **Arguments preset** 可選預設雙引號（輸入檔 + 分析輸出目錄）或 **Custom** 模板
- **Coverage** 會核對 sidecar 列舉的輸出檔與磁碟；若列了檔案但磁碟為空，寫入前可能降級並加上 `[Reconciled]`
- 預設 `ForensicStrict` policy 同樣會寫出 `skipped` sidecar，而不啟動外部分析器

限制：

- 本工具只做 orchestration，不做記憶體 verdict
- 請不要把外部工具 sidecar 的狀態直接當成最終調查結論

## 10. 常見問題排除

### 10.1 MFT 分頁是空的

可能原因：

- 這個案卷沒有 `MFT_Dump.bin` 或 `mft_preview.csv`
- 收集時 MFT 步驟失敗
- 沒有以系統管理員執行
- 防毒或系統鎖定阻止了 `$MFT` 存取

建議：

- 重新以系統管理員執行 `Local Collect`
- 檢查 `logs/ir_collect.log`
- 檢查 Summary 的 `collection_coverage`

### 10.2 Event Logs 顯示不完整

可能原因：

- 只有 `.evtx` 沒有 `*_filtered.csv`
- 單一 log 匯出失敗
- `EventLogDays` / `EventLogMaxEvents` 太小

建議：

- 在 Summary 看 Event Logs 的 coverage 與 detail
- 使用 `Rebuild Selected Host Event Logs`
- 查看 `logs/ir_collect.log`

### 10.3 Facts / Entity search 不能用

通常表示：

- Fact Store 尚未建立
- Fact Store 已 stale
- 目前主機資料不完整

建議：

- 確認 `Auto Build Fact Store when case is loaded` 是否開啟
- 使用 `Rebuild Selected Host Fact Store`
- 在 Summary 檢查 freshness warning

### 10.4 Memory sidecar 顯示 complete，但找不到 dump

這表示：

- 外部工具 sidecar 回報完成
- 但預期輸出檔並不存在

正確做法：

- 以 Summary / `collection_coverage` 的 **Coverage**（磁碟核對）為準；**Sidecar** 僅代表工具執行脈絡
- Detail 可能出現 `[Coverage]`（coverage 步驟加注）或 `[Reconciled]`（寫入 sidecar 前磁碟核對）
- 檢查工具路徑、是否因未提高權限而跳過（`MemoryAcquireSkipIfNotElevated`）、逾時、輸出目錄權限
- 讀取 `memory_acquisition.json` / `memory_analysis.json` 的 stdout/stderr 尾段與 `ToolArgs`

### 10.5 匯入後速度變慢或記憶體占用偏高

可能原因：

- 案卷很大
- Timeline / Event Logs / CSV 類重型分頁首次開啟
- 啟用了自動 Fact Store 建立

建議：

- 先完成必要檢視，再開啟重型分頁
- 大案卷可考慮啟用 SQLite 持久化

### 10.6 ShellBags 內容看不懂

這是正常的。

目前工具會收：

- `Registry\ShellBags_<SID>.reg`

但還原資料夾路徑與時間建議使用外部工具，例如 Eric Zimmerman 的 ShellBags Explorer。

## 11. 操作建議

- 現場執行優先使用系統管理員權限
- 優先將輸出寫到外接儲存裝置
- 先看 Summary，不要直接跳 Event Log
- 先確認 `collection_coverage`，再做推論
- 看到 parser notes 時，要把 fallback 納入判讀
- 做跨主機關聯前，先確認每台主機的 Fact Store 已建立且不是 stale
- 需要交接時，優先匯出 `Summary JSON`、HTML 與完整 LOG JSON

## 12. 相關文件

- `README.md`：文件總覽與版本摘要
- `ARTIFACTS.md`：artifact 類型與可行性範圍（完整樹）
- `SMOKE_RUN.md`：手動驗證流程（完整樹）
- `REGRESSION_RUN.md`：回歸測試流程（完整樹）
- `SECURITY.md`：設定與輸入安全注意事項（完整樹）
- `SPEC.md`：完整輸出格式與規格
