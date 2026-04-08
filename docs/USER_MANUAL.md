# IR_Collect 使用手冊

本手冊面向操作人員與事件調查分析師，重點是「如何使用工具完成收集、匯入、檢視與匯出」，不涵蓋開發與發版細節。若只需要現場短版流程，請先看 `docs/FIELD_SOP.md`。規格與版本歷程見 `docs/SPEC.md`，變更紀錄見 `docs/CHANGELOG.md`，技術文件索引見 `docs/README.md`。若你使用僅鏡像部分文件的公開 repo（例如 GitHub），以開發工作區內完整 `docs/` 為準；未列於該鏡像的檔案（如 `ARTIFACTS.md`）請至完整原始碼樹取得。

## 1. 工具定位

`IR_Collect` 是一個 Windows Incident Response 工具，支援：

- 本機證據收集
- 既有案卷匯入
- GUI / CLI 雙模式操作
- 多主機案件管理
- Fact Store、Entity search、Timeline、Investigation Graph 關聯分析
- Summary JSON、完整 LOG JSON、HTML 報告匯出
- 選用的外部記憶體採集與外部記憶體分析 handoff

本工具是 **Live Response** 工具，不是完整的離線鑑識映像平台。

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
- Event Log 視窗與上限
- 暫存目錄是否在打包後刪除

建議：

- 將 `config.ini` 放在僅當前操作者可讀寫的位置
- 不要將 `config.ini` 放在共用且可寫的目錄
- 不要把 AI / Upload endpoint 指向未受控的外部服務

## 3. 五分鐘快速上手

### 3.1 GUI 快速流程

1. 執行 `IR_Collect.exe`
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
IR_Collect.exe -c
IR_Collect.exe -c Case001
IR_Collect.exe --help
```

說明：

- `-c` 不帶參數時會自動產生 `Evidence ID`
- `-c <ID>` 會使用指定的證物編號
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
- 進入 AI 分析入口

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

### 4.8 Event Logs

Event Logs 分頁可檢視：

- 原始 `.evtx`
- 離線重建或收集時生成的 `*_filtered.csv`

事件詳情支援：

- `Description`
- `Parsed fields`
- `Raw XML`

若案卷只有 `.evtx` 而沒有 `*_filtered.csv`，工具會在匯入時嘗試離線重建分析用 CSV。

### 4.9 Investigation Graph

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

### 4.10 Rebuild Selected Host Event Logs / Fact Store

用途：

- 重建某一台主機的 `*_filtered.csv`
- 重建某一台主機的 Fact Store

適用情境：

- 匯入的是舊案卷
- 更新了 `EventLogDays` 或 `EventLogMaxEvents`
- Summary 提示 `fact_store.db` 已 stale
- 想重新整理單一主機分析資料，而不是清掉所有案卷

### 4.11 Clear all hosts

`File -> Clear all hosts` 會：

- 清除所有已載入主機
- 移除暫存解壓資料
- 一併清除對應 Fact Store

這不是只清掉分析結果，而是整批移除已載入資料。

## 5. CLI 操作說明

### 5.1 基本命令

```cmd
IR_Collect.exe -c
IR_Collect.exe -c Case001
IR_Collect.exe --help
```

### 5.2 CLI 典型用途

- 遠端桌面到主機後快速落地收集
- 用既有工具鏈批次呼叫
- 現場只想要案卷，不需要馬上進 GUI 分析

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
- `collection_coverage.json`：各步驟收集狀態
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
- `bam_dam.csv`
- `bits_jobs.csv`
- `wmi_persistence.csv`
- `amcache_programs.csv`
- `amcache_files.csv`
- `shimcache.csv`
- `shimcache_entries.csv`
- `srum_network_usage.csv`
- `srum_app_usage.csv`

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
- 再看哪一個 step 不是 `complete`
- 最後對照 `artifacts_missing`、`detail` 與 `logs/ir_collect.log`

對調查最重要的是，不要把 `missing` 解讀成「該活動不存在」。

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

啟用後會在每台主機的 ExtractPath 下寫入 `fact_store.db`。

適合：

- 大型案卷
- 後續重複分析
- 需要保存分析中介層

注意：

- 若未提供 `System.Data.SQLite.dll`，SQLite 寫入可能會被略過
- GUI 仍可運作，但會少一層持久化

### 9.3 Memory acquisition

用途：

- 呼叫外部工具做記憶體擷取
- 由本工具統一記錄時間、輸出、exit code、SHA256、權限脈絡

限制：

- 不內建採集驅動
- 不解析 dump
- 可能需要大量磁碟空間

### 9.4 Memory analysis handoff

用途：

- 把已有 dump 交給外部分析器
- 將外部工具輸出收進案卷

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

- 以 Summary / `collection_coverage` 的 `Coverage` 為準
- 檢查外部工具實際輸出路徑
- 檢查 `memory_acquisition.json` 或 `memory_analysis.json`

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

- `docs/README.md`：文件總覽與版本摘要
- `docs/ARTIFACTS.md`：artifact 類型與可行性範圍
- `docs/SMOKE_RUN.md`：手動驗證流程
- `docs/REGRESSION_RUN.md`：回歸測試流程
- `docs/SECURITY.md`：設定與輸入安全注意事項
- `docs/SPEC.md`：完整輸出格式與規格
