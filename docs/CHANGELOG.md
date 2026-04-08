# Changelog — IR_Collect

所有版本變更依日期倒序排列。格式參考 [Keep a Changelog](https://keepachangelog.com/)。

---

## [Unreleased]

### Fixed
- **Strict acceptance hardening**：`collection_coverage.json` 的 Event Logs 狀態改為逐一比對 `.evtx` 與 `*_filtered.csv`，缺任何一對即降為 `partial`；若 overall 存在 `missing` 也不再誤顯示為 `complete`。
- **Memory orchestration clarity**：Memory acquisition / analysis handoff 的 analyst-facing 輸出改為同時列出 `Coverage` 與 `Sidecar`，避免把外部工具回傳的 `complete` 誤讀成實際成功；memory-analysis handoff 另拒絕 case root 與保留證物目錄作為輸出路徑。
- **Summary / HTML / summary_v3 consistency**：Summary 文字區、HTML report、`summary.json` 現在一致保留跨來源 parser notes；HTML 不再把缺失 artifact count 顯示為 `-1`；`summary_v3` 對缺失 artifact counts 會輸出 `0`，並持續保留 `collection_coverage` 作為缺失語意來源。
- **Timeline graph handoff**：由 graph 開啟 Timeline 時改為 structured entity match 優先，且沿用分鐘級時間窗，而不是把 `From / To` 放大成整天。

### Docs
- 同步更新 `README.md`、`docs/README.md`、`docs/SPEC.md`、`docs/REGRESSION_RUN.md`、`docs/SMOKE_RUN.md`，使文件與目前 acceptance-hardened 行為一致。
- 新增 `docs/USER_MANUAL.md` 正式使用手冊與 `docs/FIELD_SOP.md` 現場短版 SOP，分離完整操作說明與現場應變流程。
- `FIELD_SOP` / `USER_MANUAL` 增補 **繁體中文版**（`FIELD_SOP.zh-TW.md`、`USER_MANUAL.zh-TW.md`）；英文主檔維持 `FIELD_SOP.md`、`USER_MANUAL.md`，各檔頂端可切換語言。
- `docs/SPEC.md` 補入下一版本候選更新項目（v0.22.0 draft），將低擾動模式、Memory handoff 強化、非 Event Log 補強、ShellBags 內建解析、Guided Hunt Pack、治理控制與 Case Diff 明確列入規劃。

---

## [0.21.0] — 2026-04-08

### Added
- **Memory acquisition（collection-only）**：外部工具編排、`memory_acquisition.json` sidecar、`collection_coverage.json` 內 Memory 步驟與 `skipped_steps`/`missing_steps`、Settings 納入所有參數、平台收容與 Summary/HTML/summary.json/full_log_v3 可見性。
- **Regression / Release Hardening（part 1）**：新增 `run_review_regression.bat` 與 `docs/REGRESSION_RUN.md`，並擴充 `IRCollectSelfTests` 覆蓋 Phase 3 Event Log 1149/5145 行為、memory acquisition coverage downgrade、shared/related/investigation-graph/time-window synthetic pivots，以及 `summary_v3` / `full_log_v3` export-schema 穩定欄位。
- **Memory analysis handoff**：新增外部分析器編排、`memory_analysis.json` sidecar、`MemoryAnalysis\*` 輸出目錄、`collection_coverage.json` 的 **Memory analysis handoff** 步驟、Summary/HTML/`summary.json`/`full_log_v3` host 摘要可見性，以及 `IRCollectSelfTests` 對 memory-analysis coverage / export 的回歸驗證。
- **Endpoint gate**：新增 `run_endpoint_gate.bat`，將 `run_review_regression.bat` 與正式 `build.bat` 串成單一最終收斂入口；同時同步 AssemblyInfo / About fallback 與文件版本到 `v0.21.0`。

---

## [0.18.6] — 2026-03-13

### Fixed
- **Event Log**：可拉伸分隔線改為「資訊區(表格)」與「Per page」之間；Panel1=表格、Panel2=Per page+Event detail，不再在 Per page 與 Event detail 之間。
- **MFT View**：Path、Max size 標籤顯示完整（欄寬 50/80、MaximumSize 48/78），避免裁切為「Pat」「Max」。

---

## [0.18.5] — 2026-03-13

### Fixed
- **Event Logs**：Event ID、Source 標籤顯示完整（MaximumSize 放寬為 68/52），輸入框與 User/Contains/Apply/Reset 右移避免重疊。
- **Event detail**：資訊區可拉伸（SplitContainer Panel1MinSize/Panel2MinSize）、RichTextBox 垂直捲軸，內容可捲動不裁切。
- **MFT View**：標籤改為 Path / Min size / Max size 簡短不重疊；篩選列 AutoScroll、MinimumSize 使 Apply/Reset 在窄視窗下可捲動可見。

---

## [0.18.4] — 2026-03-13

### Fixed
- **Dashboard**：Correlation / Export 改圖示 50×50 並排；Entity search 上移、與按鈕間隔縮小。
- **Timeline Analysis**：Source/From/To 標籤不裁切、與控制項間隔 4–6px；Per page 不裁切、與下拉間隔剛好；一次到位欄寬與 MaximumSize。
- **MFT View**：Path/Min/Max 與輸入框間隔縮小、Path 固定 220px；Min/Max 篩選套用後 Refresh 生效。
- **Per page**：兩處分頁列標籤 MaximumSize 72、combo Left 84，不遮、間隔剛好。
- **Event Log 篩選**：Event ID / Source / User / Contains 標籤 MaximumSize、輸入框右移不遮；搜尋邏輯已確認正常。
- **Event detail View**：View 標籤不遮選單；按鈕與下拉選項文字一致；一律不顯示 "View:" 前綴（僅選項文字）。

---

## [0.18.3] — 2026-03-13

### Fixed
- **Timeline Analysis**：From: 標籤 MaximumSize、dtFrom 右移避免遮到日期框；To: 與日期框間距縮小（dtTo Left 442）；Source: 標籤 MaximumSize 58、comboSource Left 72 避免字顯示異常與遮到方框。
- **Per page**：MainFormTimeline 與 MainForm.CreatePagingBar 之「Per page:」標籤 MaximumSize 64、combo Left 84 避免遮到下拉框；分頁列後方控制項右移 8px。
- **MFT View**：Path 與輸入框間距縮小（標籤欄 82px）、Path 輸入框改固定寬 220px；Min/Max 與輸入框間距縮小（標籤欄 98px、輸入 82px）；套用篩選與 Reset 後增加 Refresh() 使 Min/Max Size 篩選正確重繪生效。

---

## [0.18.2] — 2026-03-12

### Fixed
- **Recent Files**：排除 desktop.ini、Thumbs.db；Recent 資料夾僅輸出 .lnk 至 CSV（符合 SPEC），避免只顯示一筆 desktop.ini。
- **Lnk Files (Dump)**：改為先依副檔名複製 .lnk 再取 FileInfo 寫 CSV，權限或 metadata 失敗時仍可產出 Dump，避免 Lnk Files (Dump) 為空。
- **MFT View**：篩選區改為 TableLayoutPanel，Path contains 不再遮住輸入；Min Size / Max Size 套用後呼叫 Invalidate 使篩選生效；Min/Max 防呆（僅允許數字、非負整數、Min≤Max 提示）；Min/Max 標籤欄寬 118px、MaximumSize 避免標籤遮住輸入框。
- **Timeline Analysis**：Source 標籤設 MaximumSize 避免遮住下拉；comboSource 與 From 間距調整；CSV/JSON 匯出按鈕同高、同 Margin、WrapContents=false 使按鈕對齊。
- **USN Journal**：篩選區改 Dock Top 僅佔實際高度不自動填滿；Reset 按鈕寬度 60px 避免「Reset」被裁切；Exclude/Include ComboBox 寬度 84px、IntegralHeight 避免選單字被遮。

---

## [0.18.1] — 2026-03-12

### Added
- **ArtifactNames**：集中產出檔名常數（`src/ArtifactNames.cs`），供 CaseManager、FactStore、MainForm、RuleEngine、Collectors、Normalizers 共用；含 `IsEventLogFilteredCsv`、`GetEventLogLabelFromFileName` 輔助方法；build.bat / build_release.bat 加入 ArtifactNames.cs。
- **ArtifactNames 擴充**：新增 ServicesCsv、UsnJournalCsv、Filesystem7DaysCsv、InstalledSoftwareCsv、RecentFilesCsv、JumpListsCsv、FileIntegrityCsv，並全面替換字串常數。
- **CSV 讀取上限**：CorrelationCsvHelper.ReadCsv 增加檔案大小上限 100MB、列數上限 500000，逾限記錄 Logger。

### Changed
- **讀取編碼**：凡確定為本工具產出的檔案（system_info、process_list、activity_timeline、autoruns、scheduled_tasks、EventLog *_filtered.csv、視覺化 txt、USN CSV），讀取改為優先 `Encoding.UTF8`，失敗再 fallback Default；CaseManager 讀 system_info.txt、MainForm 文字/CSV/XML、MainFormAnalysis、MainFormTimeline、MainFormVisualization、RuleEngine、ScheduledTaskNormalizer 已統一。
- **Logger**：寫入 log 檔改為 `UTF8Encoding(false)`（no BOM），與 SPEC 輸出一致。
- **空 catch**：Collector（DeleteOutputDirAfterZip 讀取）、RegistryCollector（EnableBackupPrivilege）、FactStore（MftMaxEntries 讀取）、RuleEngine（FindArtifactPath）、MainFormTimeline（process list / EventLog CSV 解析）、MainForm（GetArtifactPath、CountCsvRows、CountXmlTasks、ReadCsvRows）改為 `catch (Exception ex)` 並呼叫 `Logger.Warning`，便於除錯。
- **安全性**：LogCollector wevtutil 路徑改為 CommandHelper.EscapeArgForCmd；UsnCollector 磁碟代號驗證為單一 A–Z；拖放路徑正規化並拒絕含 `..`。
- **Auto Build Fact Store**：載入案卷時若開啟 Auto Build，改為 BackgroundWorker 背景執行，避免大案卷卡住 UI；完成後於 UI 執行緒寫入 FactStore 並 UpdateSummary。
- **CSV 解析**：MainForm.SplitCsvLine 改為委派 `CsvUtils.SplitLine`（RFC 4180，含 `""` 跳脫），與 CorrelationCsvHelper 一致。
- **Event Log 大檔**：LoadEventLogTabAsync 開檔前檢查 .evtx 大小，>50MB 則跳過並顯示提示。
- **Fact Store 建置中**：CaseData.FactStoreBuilding；Export/Entity Search 略過建置中主機；手動 Build 時設 flag 並於完成或失敗時清除。
- **證據 ID**：NormalizeEvidenceId 限制長度 64、僅允許英數字與 `-`/`_`。
- **ReadScheduledTasks**：讀取前檢查 XML 檔案大小 20MB 上限。
- **MainFormAnalysis**：MaxProcessListBytes / MaxScheduledTasksXmlBytes 常數取代魔術數字。
- **測試**：新增 CaseManagerTests.RunLoadCaseMinimalZip、RunBuildFromCaseMinimal；CommandHelperTests.RunEscapeArgForCmd、RunCommandHelperRunSafe；build.bat 加入 CaseManagerTests.cs、CommandHelperTests.cs。
- **規則引擎**：載入 ir_rules.json 後 ValidateAndSanitizeRuleFile（Id 空則補、Regex 逾 500 字元截斷並記錄）。
- **ConfigManager**：Import 僅接受 .ini、且目錄須通過 IsPathSafeForExport。
- **Settings**：VirusTotal / AI / Upload API Key 欄位改為 UseSystemPasswordChar。
- **Scheduled Tasks 分頁**：CreateScheduledTaskTab 以 ResolveArtifactPathFlexible 解析路徑，XML 逾 20MB 不載入。
- **規則引擎**：correlation_rules 的 condition.Regex 逾 500 字元時一併截斷並記錄（ReDoS 緩解）。
- **CaseManager**：LoadCase 於檢查 zip 存在後以 GetFullPath 正規化 zipPath。
- **文件**：README 設定檔段落補述 config.ini 敏感資料與檔案權限建議。

---

## [0.18.0] — 2026-03-12

### Added
- **File 選單「Clear all hosts」**：清除所有主機 Fact Store 改由 **File → Clear all hosts** 觸發，Dashboard 不再顯示「Clear Fact Store (all hosts)」按鈕。
- **Dashboard 右/下邊界**：結果表單 (listCorrelation) 於 Resize 時保留右、下各 24px 留白；最後一欄 (Hosts/Window) 設為 -2 填滿剩餘寬度，拉伸視窗時有明確邊界感。

### Changed
- **Global Correlation Overview**：移除「尚無案卷…」「建議以系統管理員…」「建議流程…」等說明文字，僅保留標題與按鈕區。
- **Dashboard 按鈕**：五顆按鈕統一為 300×50，上列 2 顆（Find Common Artifacts、Find Timeline Correlation）、下列 1 顆（Export full LOG JSON）；**Build Fact Store (all hosts)** 按鈕已移除。
- **Auto Build Fact Store**：預設改為勾選（ConfigManager 預設 `FactStoreAutoBuild=1`）；載入案卷時預設自動建置 Fact Store。
- **Entity search / Correlation 結果表**：Find Common Artifacts 與 Find Timeline Correlation 之最後一欄改為自動填滿 (-2)。
- **文件**：README/SPEC 更新建議流程、File 選單說明、Clear all hosts、Dashboard 邊界與按鈕說明；TODO 標註 UI 說明文字移除完成。

### Removed
- **Build Fact Store (all hosts)** 按鈕（改為載入時自動建置，Settings 可關閉）。
- **Clear Fact Store (all hosts)** 按鈕（改為 File → Clear all hosts）。

---

## [0.17.9] — 2026-03-06

### Added
- **Settings 對話框補齊**：AI API Endpoint、Upload Endpoint、Upload API Key、Event log days、Event log max events per log、Delete output dir after ZIP 均可在 Advanced → Settings 中設定（符合「所有可調選項均於 Settings 露出」）。
- **docs/IMPLEMENTATION_STATUS.md**：功能實作完整性檢查報告（Settings 補齊、About 版本、設計取捨與對照）；後續內容已整理進一般專案文件。

### Changed
- **Activity Timeline 日期防呆**：From/To 之 DateTimePicker 設 MinDate=1980-01-01、MaxDate=2100-12-31，避免無效年（如 026）；Apply 時若 From > To 自動對調並提示。
- **About / AssemblyInfo**：版本同步為 0.17.8（fallback 與 AssemblyVersion/AssemblyFileVersion）。
- **Settings**：表單增高以容納新欄位；VirusTotal API Key 說明改為「for future API use; Query VT opens browser」。

---

## [0.17.8] — 2026-03-06

### Security
- **VirusTotal**：右鍵「Query VirusTotal」僅接受 32（MD5）或 64（SHA256）字元十六進位 hash，不符時提示且不開啟瀏覽器，避免 URL/命令注入。
- **MFT 磁碟代號**：`MftDumper.NormalizeDriveLetter` 與 `RawDiskReader` 建構子強制驗證單一 A–Z，防止路徑遍歷。
- **設定匯出**：`ConfigManager.Export` 經 `IsPathSafeForExport` 拒絕寫入系統目錄（SystemDirectory、Windows、ProgramFiles）；回傳 `bool`，UI 於拒絕時顯示警告。
- **規則引擎 ReDoS**：`RuleEngine.SafeRegexIsMatch` 以 2 秒逾時執行規則/關聯之 Regex，逾時或 `ArgumentException` 視為不匹配。

### Changed
- **ConfigManager.Export**：簽名改為 `bool Export(string path)`，呼叫端依回傳值顯示成功或「Export refused」訊息。
- **docs/SECURITY.md**：更新為 v1.1，標註上述項目已實作。
- **docs/README.md**：補充「設定檔 (config.ini)」放置與匯出限制說明。

---

## [0.17.6] — 2026-03-06

### Added
- **CommandHelper.EscapeArgForCmd**：路徑／參數含 `"`、`&`、空格時跳脫後再傳給 cmd；RegistryCollector 之 reg export／reg save 改用此方法，避免路徑特殊字元破壞指令解析。
- **docs/SMOKE_RUN.md**：End-to-end smoke run 檢查清單（手動收集／匯入／檢視流程）。

### Changed
- **延遲分頁**：DeferredTab_Enter 兩處 `tab.BeginInvoke` 改為 `SafeInvoke`，與表單 Dispose 防護一致。
- **GetCaseRootPath**：`c.Artifacts.First()` 改為 `FirstOrDefault()`。
- **MainForm**：LoadNormalCsvData、TryLoadUsnJournalData、CreateActivityTimelineTab 之空 catch 改為 `Logger.Warning`。
- **CaseManager.LoadCase**：掃描解壓目錄時檔數上限 200000，達限記錄 log 並 break。
- **MainForm.CountFiles**：改為 `Directory.EnumerateFiles` 計數、上限 50000，catch 改為 `Logger.Warning`。
- **Event ID 掃描**：evtxFiles 僅單次迭代，移除多餘 `.ToList()`。
- **CODE_REVIEW**：CommandHelper 標為已處理；中期／長期項目結案。

---

## [0.17.5] — 2026-03-06

### Changed
- **分頁列**：所有 LOG 分頁與 Timeline Analysis 之分頁列改為 Dock Bottom，顯示於表格下方。
- **Code Review**：File.ReadAllLines 加檔案大小上限（Visualization 5MB、Analysis 50MB/20MB、CaseManager 5MB）；關鍵路徑空 catch 改為 `Logger.Warning`（Create*Tab、FactStorePersistence、MainFormAnalysis 關聯讀取）。
- **USN 篩選區**：單行 Contains→輸入→then Exclude→[+][Reset]；按 [+] 時該列結尾改為 [-] 並在下一列新增 [+][Reset]；篩選區可拖曳分隔線調整高度，依條件列數自動增高，預設僅一行（約 48px）。
- **延遲載入分頁**：內容掛上後以 BeginInvoke 執行 PerformLayout + Refresh，避免篩選區按鈕裁切（如 Reset 顯示為 Rese）。

---

## [0.17.4] — 2026-03-06

### Added
- **LOG 分頁 (五類)**：USN Journal、Activity Timeline、Event Log、Processes（及所有 CSV 表格分頁）、Timeline Analysis。
- **自動切頁**：筆數超過 500 時自動顯示分頁列，僅顯示當前頁以減輕卡頓。
- **每頁筆數**：預設 150 筆，可選 200 / 250 / 300（Per page 下拉）。
- **導航**：分頁列顯示「Page X of Y」、Prev/Next、Go to 頁碼輸入＋Go 按鈕。

### Changed
- **CreatePagingBar**（MainForm）：共用分頁列，支援可選 row Tag（Event Log 詳情綁定）。
- **Timeline Analysis**：維持 VirtualMode，筆數 > 500 時顯示分頁列並依頁偏移顯示。

---

## [0.17.0] — 2026-03-06

### Added
- **BrowsingHistoryView 瀏覽時間**：Chrome/Chromium History 改為以 SQLite 查詢（`FactStorePersistence.TryGetChromeHistory`），表格新增「Last visit」欄位；無 System.Data.SQLite.dll 或非 Chrome 格式時沿用 Regex 僅顯示 URL。
- **Jump Lists Path 解析**：依 MS-SHLLINK 自 .automaticDestinations-ms / .customDestinations-ms 掃描 LNK 標頭，自 LinkInfo 讀取 LocalBasePath（UTF-16/ANSI），並於區段內掃描 C:\ / D:\ UTF-16 作為後備；與既有啟發式合併去重，減少 Custom 項目 Path 為空。
- **Import 案卷 Temp 自動清理**：關閉主視窗（含 File → Exit、按 X）時呼叫 `CaseManager.CleanupAll()` 刪除 %TEMP% 下解壓目錄；右鍵「Clear Host Data」時呼叫 `CaseManager.RemoveCase(c)` 刪除該案 Temp 目錄並自清單移除。

### Changed
- **Event Log 詳情 View**：ComboBox 改為 Button + ToolStripDropDown（Description / Parsed fields / Raw XML），選單改為浮動視窗，不再被 GroupBox 裁切。
- **Event Log 分頁載入**：切換至單一 log 分頁時改為背景載入（`LoadEventLogTabAsync` + BackgroundWorker），避免大量 EVTX 解析造成主視窗「沒有回應」。
- **CSV / USN Journal 表格**：`CreateCsvTab` 建立後將所有欄位設為 `SortMode = NotSortable`，避免欄位標題快速連點觸發重複排序導致沒有回應。

---

## [0.16.0] — 2026-03-06

### Fixed
- **Find Common Artifacts**：`CaseManager.FindCommonFiles` 對 `MftEntries == null` 的 case 跳過，避免 NRE；顯示主機名改為 `Hostname ?? "host"`。無 host 時先提示「No host loaded」。
- **Find Timeline Correlation**：事件主機改為 `e.Host ?? "host"`；`ReadProcessEvents` / `ReadAutorunEvents` / `ReadScheduledTaskEvents` 開頭檢查 `ExtractPath` 為空則直接回傳；`ReadEventLogEvents` 檢查 `Artifacts == null`。無 host 時先提示。
- **Build Fact Store**：建置期間停用「Export full LOG JSON」與「Clear Fact Store」按鈕，避免背景建置中誤觸造成 race；`MainForm` 新增 `btnExportFullLogJson`、`btnClearFactStore` 欄位。
- **RunCorrelation**：清單欄位改為每次執行時重設為 File/Artifact、Count、Hosts，避免先使用 Entity Search 或 Timeline 後欄位與內容不對齊。
- **RunEntitySearch** / **RunExportFullLogJson**：無 host 時先提示「No host loaded」。

---

## [0.15.0] — 2026-03-06

### Changed
- **`MainFormVisualization.cs`**（新增 partial class）：從 `MainForm.cs` 提取 System Info / IP Config / Connections / ARP / DNS 視覺化分頁方法，`MainForm.cs` 縮至 2865 行（原始 4028 行，共減少 1163 行）。
- **`MainFormTimeline.cs`**（新增 partial class）：從 `MainForm.cs` 提取 `TimelineEvent` 類別、`BuildTimelineEvents`、`CreateTimelineTab`。
- **`CorrelationCsvHelper.SplitCsvLine`**：改為委派 `CsvUtils.SplitLine`，消除重複實作；順帶修正原版不處理 escaped quote（`""`）的解析 bug。

### Fixed
- CSV 解析中含 `""` escaped quote 的欄位現在能正確還原為 `"`（影響 EVTX Description、CommandLine 等可能含引號的欄位）。

---

## [0.14.0] — 2026-03-06

### Changed (Architecture)
- **`ConfigManager`**：路徑改用 `AppDomain.CurrentDomain.BaseDirectory`，不再依賴 CWD；`LogCollector`、`CaseManager.GetMftMaxEntries` 改為透過 `ConfigManager` 讀取設定，消除三處各自讀 config.ini 的不一致。
- **`CaseManager.LoadedCases`**：改為執行緒安全快照屬性（`private _cases` + `_lock`），呼叫端取得副本，避免 race condition。
- **`MainForm.cs`** 拆為 5 個 partial class：`MainForm.cs`、`MainFormAnalysis.cs`、`MainFormCollection.cs`、`MainFormSettings.cs`（本版）；v0.15 再加 `MainFormVisualization.cs`、`MainFormTimeline.cs`。
- **`Utils/CsvUtils.cs`**（新增）：`EscapeField`（RFC 4180）與 `SplitLine`（支援 escaped quote）集中實作；7 個 Collector 移除各自私有的 `EscapeCsv`，統一呼叫 `CsvUtils.EscapeField`；`RuleEngine.ReadCsvRecords` 改委派 `CorrelationCsvHelper`。
- **`RuleEngine`**：新增 `LoadRuleFile()`（含修改時間快取），`EvaluateCase` 與 `EvaluateCorrelationRules` 共用同一次 `ir_rules.json` 讀取。
- **`FactStorePersistence`**：SQLite Reflection `Type`/`MethodInfo` 改為靜態快取，大幅降低 Build Fact Store 時的 Reflection 開銷。

### Fixed
- **`LogCollector.CollectFiltered`**：整批失敗時改為實際執行 full `.evtx` fallback（原版只印訊息，不執行）。
- **`FactStore.BuildFromCase`**：MFT Normalizer 上限從 `ConfigManager.MftMaxEntries` 讀取，不再硬寫 50000。
- **`SystemCollector.GetProcessWmiInfo`**：WMI `GetOwner` 回傳的 `outParams` 包在 `using` 內釋放，避免 COM 資源洩漏。
- **`MftParser.fileSize`** 初始值 `-1` 改為 `0`，避免表格顯示 `-1` 及影響大小篩選。
- **`ConfigManager.Save`**：改用 no-BOM UTF-8（`new UTF8Encoding(false)`），與其他輸出一致。
- **`MftParser.Parse`**：靜默 `catch` 改為 `Logger.Warning`，損毀記錄不再靜默跳過。
- **全域**：`catch` 內移除 `(ex != null ? ex.Message : "")` 冗余防衛（18 個 .cs 檔），改為直接使用 `ex.Message`。

### Removed
- `src/PngToIco.cs`、`src/ImgToIco.cs`（孤立殘留工具，已從 src/ 刪除）。
- `Collector.cs` 舊 "Placeholder logic" 注解。
- 各 Collector 私有 `EscapeCsv` 方法定義（共 7 個，統一改用 `CsvUtils.EscapeField`）。

---

## [0.13.0] — 2026-02-10

### Fixed (Security)
- Zip Slip 修正：解壓改為 `ExtractZipSafely`，驗證每個 entry 不超出目標目錄。
- `GetArtifactPath`/`FindArtifactPath` 加入路徑驗證，防止路徑穿越。
- `CleanupAll` 加入 null 檢查；DragDrop 加入安全驗證；VT 連結限定 https。
- `FillGridFromCsv` 欄數不足時補空白，防止陣列越界。

### Changed
- 打包後預設刪除暫存目錄（config `DeleteOutputDirAfterZip`，可設為 0 保留）。
- Recent Files 排除 Jump List 子目錄（`AutomaticDestinations`/`CustomDestinations`）。
- Recent Mod（7d）改為不跟隨 junction/symlink，避免重複路徑。
- 分頁改名：MFT View、BrowsingHistoryView、Registry exports。
- USN Journal 跳過 fsutil metadata，改為顯示檔名/原因/時間表格。

---

## [0.12.0] — 2026-02-10

### Fixed
- MFT 從 GUI 收集必失敗：修正無主控台時 `Console.OutputEncoding` 拋錯，改為 try-catch 略過。
- MFT Browser 無資料時顯示說明與 logs 路徑。
- UserActivity 拒絕存取/路徑太長改彙總計數，不再對每一筆寫 log；結束時輸出 Skipped 摘要。
- Prefetch 略過時寫入 `logs/ir_collect.log`。
- Registry 啟用 `SeBackupPrivilege`，收集結束輸出「System hives: X/4」。
- Event Log 匯出失敗時自動重試一次，結束時輸出「N exported, M failed」。

### Added
- README 新增「DFIR 現場保護」與「收集階段部分失敗的處理」說明。

---

## [0.11.0] — 2026-02-10

### Added
- **Phase B3**：Fact Store 可選寫入 SQLite（Settings 勾選 `FactStoreWriteSqlite`），各 host 寫入 `fact_store.db`。
- Dashboard「Export full LOG JSON」匯出全量 Facts（含 DateTime 正規化，避免 JSON 序列化錯誤）。
- Settings 新增「Auto Build Fact Store when case is loaded」選項。
- 新增「Clear Fact Store (all hosts)」按鈕。

### Changed
- Build Fact Store 改背景執行（`BackgroundWorker`），不再凍結 UI。
- `FactStore` 索引改用 `HashSet<Fact>` 與 `AddRange`，提升建立效能。

### Fixed
- Build 防呆：若任一 host 已有 Fact Store 資料則不覆寫，提示先 Clear。

---

## [0.10.0] — 2026-02-09

### Added
- **Fact Store**：記憶體 `FactStore`、Entity 索引（`HashSet`）、`GetByEntity`/`GetByTimeRange`。
- **Normalizers**：Process、Autorun、ActivityTimeline、MFT、ScheduledTask、EventLog（*_filtered.csv）。
- **Entity search**：支援 Path / Hash / User / RegistryKey / Provider / EventId。
- **Correlation rules**：`ir_rules.json` 跨來源關聯（Source 前綴匹配）、`process_and_eventlog`、`mft_and_process`、`autorun_and_eventlog`、`time_window_minutes`。
- **Timeline**：整合 EventLog（*_filtered.csv）；Export CSV/JSON。
- **EVTX 詳情**：View 切換 Description｜Parsed fields｜Raw XML。
- **Export HTML Report**：Summary 分頁一鍵匯出單一 HTML（Host、Counts、Highlights、Rule/Correlation findings）。
- **Event Log 收集優化**：`EventLogDays`/`EventLogMaxEvents`（config.ini）可選篩選模式，產出 `*_filtered.csv`。
- **Logger**（`Utils/Logger.cs`）：集中式日誌，取代分散的 silent catch。
- **ZipFile**：改用 `ZipFile.CreateFromDirectory`/`ExtractToDirectory`，不再依賴 PowerShell。

---

## [0.9.0] — 2026-02-09

### Changed
- MFT：使用動態系統碟；`mft_preview.csv` 含完整 MACB（8 個時間戳）。
- `process_list.csv`：補齊 CommandLine、Hash、Signature、User（WMI GetOwner）、PPID/SessionId/ThreadCount/WorkingSetSize。
- 文件（SPEC/PLAN/README）與程式碼狀態同步。

---

## [0.8.0] — 2026-01-25

### Added
- **Timeline Analysis** 分頁：整合 Process StartTime 與 MFT Created/Modified，提供單一時間軸視圖。

---

## [0.7.1.0] — 2026-01-24

### Added
- **ConfigManager**（`ConfigManager.cs`）：VirusTotal/AI API Key 儲存。
- Advanced 選單：Settings / Import / Export 功能。
- 主機列表與資料表格右鍵選單（Clear、Summary、Copy、VT Query）。

### Fixed
- 部分 UI 邏輯重複與 C# 5.0 相容性問題。

---

## [0.7.0] — 2026-01-24

### Added
- **MenuStrip**：File（Open Case / Exit）、Advanced、Help（About）。
- 側邊欄收合按鈕、寬度調整、Dashboard 分離。
- System Info/Network 自動解析與視覺化（Grid/TreeView）。
- **MFT Browser**：Virtual Mode 支援大數據（100k+ 筆）。
- **build.bat**：自動簽章（Self-Signed "nine-security Inc"）。

---

## [0.6.0] — 2026-01-23

### Added
- **Dynamic Host Tabs**：根據 Artifact 動態顯示分頁。
- Scheduled Tasks：改為 XML 收集與解析（含 Command/Args 欄位拆分）。

### Fixed
- 亂碼修正（`chcp 65001`）。
- 介面字體放大優化。

---

## [0.5.0] — 2026-01-22

### Added
- 全面收集模組：Process、Network、Registry（Autoruns）、Services、Scheduled Tasks、Event Logs。
- 自動驗證測試。

---

## [0.4.0] — 2026-01-22

### Added
- GUI 全面翻新：Dashboard、雙欄式佈局、Async 收集、Drag & Drop 多檔匯入。

---

## [0.3.0] — 2026-01-22

### Added
- **CaseManager**：多主機分析，可同時載入多個 ZIP 案卷。
- **Correlation Engine**：尋找跨主機共同檔案。

---

## [0.2.0] — 2026-01-22

### Added
- **MFT 收集**：`RawDiskReader` 直接讀取磁區，匯出 `$MFT`；MFT Parser 產出預覽 CSV。

---

## [0.1.0] — 2026-01-22

### Added
- 專案初始化：C# Solution 結構、`build.bat` 編譯腳本、GUI/CLI 雙模式架構。
