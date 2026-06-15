# Changelog — IR_Collect

所有版本變更依日期倒序排列。格式參考 [Keep a Changelog](https://keepachangelog.com/)。

---

## [Unreleased]

## [0.23.1] — 2026-06-15

> 本版主題:**Local Collect 收集速度大幅提升（實機驗證 ~16 分 → ~5.5 分）**，鑑識零妥協。

### Changed
- **事件日誌過濾跨 log 平行化（實測:Event Logs 為收集最大宗）**：實機計時顯示 `Event Logs` 達 **200.8 秒**（收集器總計 378 秒中最大宗）——因每個 log 各自吃滿 90 秒格式化預算、又**逐一序列跑**。`LogCollector.TryCollectFiltered` 改用 `Parallel.ForEach`（degree = min(4, CPU 數)）平行過濾各 log：每個 log 各自獨立的 reader + 輸出 CSV、各自的格式化預算,彼此不相干;`successCount` 改用 `Interlocked`、`Logger` 本就 thread-safe（`lock`）。對 live log 唯讀。預期 Event Logs 由 ~200 秒降到 ~單一最慢 log（~90 秒）。
- **打包壓縮改用 Fastest（預設；6.7× 快、體積僅 +2%）**：`PackDir` 原本對整個輸出（含 2.8 GB MFT）用 `CompressionLevel.Optimal`。實測 400 MB MFT-like 資料：**Optimal 43.6s→198MB vs Fastest 6.5s→202MB**（6.7× 快、僅大 2%）；對 ~3 GB 收集約由 ~5 分鐘降到 ~50 秒、體積幾乎不變。改為可由 `config.ini` 的 `CollectionZipCompression`（`Fastest`｜`Optimal`｜`NoCompression`）設定，**預設 `Fastest`**（live response 重速度；ZIP 為傳輸用暫存物）。打包時 console 提示目前壓縮等級。
- **收集每步加上計時**：`RunCollectorStep` 與打包步驟現在印出各步耗時（`[t] <step> done in N.Ns`），並把各步耗時（slowest-first + 總計）寫入收集輸出的 `collection_timing.txt`（GUI 模式不顯示 console，改由此檔取得），讓最慢的收集器一目了然、便於後續針對性優化。
- **事件日誌過濾大幅加速（不丟事件）**：`EventLogFilteredCsvExporter` 每筆事件呼叫 `record.FormatDescription()` + `LevelDisplayName` + `TaskDisplayName`（皆需載入發行者資源範本），在大型 log（尤其 Security）成為瓶頸——對真實 20 MB Security.evtx 實測 **113.7 ms/筆**（≈ 1 萬筆要 ~19 分鐘）。新增**每個 log 的格式化時間預算**（`config.ini` 的 `EventLogMessageFormatBudgetSeconds`，預設 90 秒；`0`=不限）：超過預算後仍**保留每一筆事件與完整結構化 EventData**（normalizer 實際使用的欄位、不受影響），僅把 message／level／task 的「人類可讀顯示字串」降級為便宜的結構化／數值等價值。實測降級模式 **0.1 ms/筆（約 1022× 加速）**，Security log 由 ~19 分鐘降到 ~90 秒。超出預算時於 console 提示。既有 EventLog normalizer 自測全綠（契約不變）。

## [0.23.0] — 2026-06-15

### Fixed
- **Local Collect 7 天檔案掃描加上時間上限（避免大型 profile 失控）**：`UserActivityCollector.CollectRecentModifications`（`filesystem_7days.csv`）原本遞迴掃 `C:\Users`+`Windows\Temp`+`ProgramData` 並對每個近期檔算 SHA-256，上限僅 500k 檔——在開發機（scoop／AppData 大量 cache）實測跑 24 分鐘仍未完。新增**牆鐘時間上限**（`config.ini` 的 `RecentFileScanMaxSeconds`，預設 120 秒；`0`=不限、完整掃描），超時即停並在 CSV／console 留一條誠實的 `[TRUNCATED…]` 註記；另多跳數個瀏覽器／Electron 快取目錄（GPUCache、ShaderCache、Service Worker、Crashpad、CacheStorage…）。實機驗證：原本卡住的 collection 現可完成（掃描 120 秒截斷、抓 4,246 近期檔、產出 ZIP）。新增自測 `RecentFileScan_respects_time_budget`。
- **ShimCache 新增離線 SYSTEM hive 檔案模式（Phase 2.3）**：`ShimCacheParser` 原本僅能讀 live registry，無法對 triage 取得的 SYSTEM hive 做解析或差異驗證。新增 `ParseFromHiveFile`（reg load SYSTEM hive、依 `Select\Current` 取 ControlSet、讀 `AppCompatCache` 值，與 live 模式共用解析邏輯；需提權）。`-parse shimcache <SYSTEM>` 與 `DiffValidate.ps1 -Kind shimcache`（對 AppCompatCacheParser 做 path recall）。
- **ShimCache 結構化 Win8/Win10 解析 + 每筆 LastModified（Phase 2.3）**：`ShimCacheParser` 原本只有 path byte-scan heuristic（無時間戳）。新增結構化 `00ts`／`10ts` entry 解析：自 header DWORD（或掃描簽章）定位首筆，依各 entry 自述長度逐筆走訪，還原 UTF-16 路徑與每筆 `LastModified` FILETIME（UTC）。優先走結構化路徑，無法辨識的舊版/未知格式才退回原 heuristic。新增單元測試 `ShimCache_structured_win10_entry_recovers_path_and_filetime`（合成 `10ts` value，斷言路徑 + FILETIME 還原）。
- **ShimCache 只讀正規 `AppCompatCache` 值（修真實 hive 上的假 fallback，Phase 2.3）**：差異化驗證實機發現 `Session Manager\AppCompatCache` key 下有三個值——`AppCompatCache`（真快取）、`CacheMainSdb`、`SdbTime`。`ParseKeyValues` 原本三個全解析：`CacheMainSdb` 被亂讀成裸 apphelp 檔名、`SdbTime`（96 B、無路徑）落入佔位分支設了 `FallbackUsed=true` 但無 note → 即使主值已解出 1,161 筆真實 entries，`-parse shimcache` 仍回 `fallback:true`、harness 一律 SKIP。改為只讀 `AppCompatCache` 正規值（與 AppCompatCacheParser 一致），消除假 fallback 與雜訊。`-parse shimcache` 另輸出 `rows[]`（每筆 `{path,LastModified}`）供時間戳抽查，`paths[]` 維持字串陣列供 recall 比對。修復後對真實 Win11 SYSTEM hive 驗證：**entries 1,024/1,024 完整涵蓋**、**path recall 對 AppCompatCacheParser 881/1,024 = 86%**、**還原 LastModified 873 筆**（過去 heuristic 為 0）。未填時間戳的 151 筆恰為封裝（Store）App entry——其在 AppCompatCache 中本就無 FILETIME；recall 的 ~143 筆差距亦為這些 Store moniker 的呈現格式與 AppCompatCacheParser 不同（雙方皆見同樣 1,024 筆，非漏抓），列為已記錄的次要差異。
- **Amcache 支援現代 schema（重大；現代 Windows 上原本解不出，Phase 2.3）**：差異化驗證發現 `AmcacheParser` 只查舊版分支 `Root\Programs`／`Root\File`，但 Win10 1607+／Win11 改用 `Root\InventoryApplication`／`Root\InventoryApplicationFile`——導致在**現代主機上回 fallback、零筆 file/program**（真實 Win11 hive 經 EZ AmcacheParser 解出 3,525 筆 file entries，我方原本 0 筆）。`Export` 改為先查現代分支、再退回舊版；分支不存在不再硬性 fail（讓另一 schema 接手）；並支援自 `FileId`（`0000`+SHA1）推導 SHA1。值欄位解析本就相容現代名稱（`LowerCaseLongPath`／`SHA1`／`ProgramId`）。修復後對真實 Win11 hive 驗證：**SHA1 recall 對 AmcacheParser 3,073/3,103 = 99%**（修復前 0）。
- **SRUM 改用原生 ESE reader（重大；原本完全不能用，Phase 2.3）**：差異化驗證發現 `SrumExporter` 透過 OLE DB ACE/Jet provider 讀 `SRUDB.dat`，但 SRUDB 是 ESE（esent／JET Blue）資料庫、ACE/Jet 只能讀 Access（JET Red）——即使裝了 64-bit ACE 2016 仍回 `Could not find installable ISAM`／`Unrecognized database format`，等於**在所有機器上都靜默退回 header-only、SRUM 功能從未真正運作**。新增 `EseReader`（直接 P/Invoke 系統內建 `esent.dll`，無外部相依；read-only + recovery off，可讀取複製出的 dirty DB），重寫 `SrumExporter` 以 ESE 逐表讀取（IdMap→SID/app 解析、App/Network 資源表）。對真實 `SRUDB.dat` 驗證：app rows 73,812（SrumECmd 73,808）、**distinct app 對 SrumECmd recall 684/684 = 100%**、UserId 正確解析為 SID。
- **MFT NTFS USN/fixup（重大正確性，Phase 2.3）**：`MftParser` 現在於讀屬性前套用 NTFS Update Sequence fixup（header 0x04=usaOffset、0x06=usaCount；還原每個 512-byte sector 末 2 bytes）。先前未還原 → 任何跨越 record offset 510-511／1022-1023 的欄位都會被 USN 覆蓋而毀損（差異化驗證實證：`tokenbinding.dll` 被讀成 `tokenbindi?g.dll`）。
- **MFT 取 Win32 長檔名而非 DOS 8.3（Phase 2.3）**：`$FILE_NAME` 解析改讀 namespace byte（content+0x41），依 Win32&DOS(3) > Win32(1) > POSIX(0) > DOS(2) 取最高者，而非用最後一個屬性覆蓋（先前會輸出 `ENTRIE~1.JSO` 而非 `entries.json`）。
- **差異化 harness UTF-8 讀取**：`DiffValidate.ps1` 改以 UTF-8 明確讀取我方 JSON 與 MFTECmd/LECmd/JLECmd 的 CSV（PowerShell 5.1 預設 ANSI 會把 CJK 檔名 mojibake 成假 mismatch）。
- 對真實 2.8 GB `$MFT`（280 萬筆）重跑差異化驗證：時間戳 **100%** 一致；檔名 real mismatch（gate）**= 0**。`DiffValidate.ps1-Kind mft` 改為 hardlink-aware（一筆 record 可有多個合法 Win32 名 → 我方名只要命中其一即算一致），並新增 `-MftCsv` 重用既有 MFTECmd CSV（免每次重跑 ~11 分鐘）。殘餘 78 筆（0.13%）為已記錄的 `$ATTRIBUTE_LIST` 涵蓋缺口：長 Win32 名存在延伸記錄、我方僅讀 base record（WinSxS `.cat`/`.manifest`），歸為 informational 非 gate 失敗，於 `MftParser` 程式碼註明為待補項。

### Added
- **GUI 開啟資料夾（Phase 4.1，把分析層接進 GUI）**：GUI 原本只能開 ZIP 案卷(`LoadCase`)。新增 **File 選單「Open Folder (triage)...」**(快捷鍵 Ctrl+Shift+O),以 Phase 3.1 的 `CaseManager.LoadCaseFromFolder` 載入任意 artifact 資料夾(他牌 triage 輸出／解壓案卷),與 ZIP 載入共用同一套後置流程(主機樹節點、load warnings、背景建 FactStore——抽成共用 `RegisterLoadedCase`)。新增 `BtnImportFolder_Click`(FolderBrowserDialog)+ `LoadCaseFolder`。已開 GUI 實機驗證:選單項出現、可選資料夾、主機節點正常載入。
- **證據雜湊 manifest + SBOM（Phase 5.2，報告↔證據密碼學連結 + 相依治理）**：資料夾分析(`-analyze`/`-correlate`/`-graph`)現在於**載入時(衍生任何 CSV 之前)** 對輸入資料夾每個檔案算 SHA-256,把報告綁回它實際消耗的證據。新增 `EvidenceManifest`(`HashFolder` → 每檔 {relpath,size,sha256} + 一個 rollup `evidence_digest`=對排序後 (relpath,sha256) 行再雜湊),`CaseData` 帶 `EvidenceFiles`/`EvidenceDigest`。`summary_v3` 新增完整 `evidence[]` + `evidence_digest`;`correlation_v1`／`graph_v1` 每台 host 帶精簡 `evidence_digest`+`evidence_file_count`(多機輸出不爆量)。真實驗證:對真實 `SRUDB.dat` 我方 SHA-256 與 Windows `Get-FileHash` **完全一致**;自測 `EvidenceManifest_hashes_inputs_and_summary_carries_digest` 以 `"abc"` 的教科書 SHA-256 做 known-answer。新增 `docs/SBOM.md`(相依宣告:esent.dll／wintrust.dll 系統 DLL、System.Data.SQLite.dll 僅在 Authenticode 受信任時載入、framework refs、bundled EZ tools 不入庫不在 runtime;build 釘選 csc + `build_common.rsp` lockfile + determinism 限制揭露)。
- **工具身分標記 + `-version`（Phase 5.1，可呈堂可重現性）**：新增單一版本真實來源 `BuildInfo`(`ToolName="IR_Collect"`、`Version` 一次性讀自執行組件 `AssemblyInfo.cs`,不再有第二處需同步),並把 `tool_name`／`tool_version` 寫進**所有機讀輸出**(`summary_v3`／`correlation_v1`／`graph_v1`／`full_log_v3`)——可呈堂要求:每份報告須宣告產生它的工具與版本。新增 CLI `IR_Collect.exe -version`(印工具身分 + 各輸出 schema 版本)。新增自測 `BuildInfo_version_matches_assembly_and_is_stamped_in_outputs`(版本對齊組件 + 序列化輸出含 tool_version/tool_name)。**可重現性說明(誠實揭露)**:本專案釘選的編譯器為 .NET Framework `v4.0.30319` csc(C# 5、pre-Roslyn),**不支援 `/deterministic`**,每次建置會嵌入新的 MVID/時間戳 → 無法達成位元層級可重現建置;`build_common.rsp` 的明確檔案清單即為釘選的建置輸入清單(lockfile)。逐檔雜湊的證據 manifest(報告↔證據的密碼學連結)與 SBOM／相依宣告列為後續增量 5.2。
- **多跳調查圖 CLI `-graph`（Phase 3.2b，深化）**：`InvestigationGraphBuilder.Build` 原本只有單跳(seed → 共現實體)。新增生產 CLI `IR_Collect.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <folderA> [...]`:自 seed 實體 BFS 多跳展開(跨 ≥1 個資料夾)、節點/邊去重、每跳 fanout 預設 40 + 全圖 node/edge 上限,輸出新 `graph_v1` JSON(`nodes[]{type,value,depth,hosts}`／`edges[]{from,to,fact_count,host_count,hosts,sources,actions,first_seen,last_seen,depth}`,時間 ISO)。新增 `GraphCli`(可測 `BuildGraph(cases,seedType,seedValue,maxDepth,options)`)。新增自測 `GraphCli_multi_hop_reaches_sibling_via_shared_publisher`(兩個 Amcache file 共用 Publisher → 由 a.exe 經 Publisher 在 **depth 2** 才觸及 b.exe,證實真多跳而非單跳共現)。真實資料驗證:seed `User:S-1-5-18` depth 2 → 77 nodes / 147 edges,depth 分布 {0:1, 1:40, 2:36}(depth-2 節點僅經 depth-1 觸及),有界且正確序列化。
- **跨機關聯 CLI `-correlate`（Phase 3.2，深化多機關聯）**：關聯引擎(`SharedEntityPivotBuilder`／`InvestigationGraphBuilder`／`BuildTemporalCorrelations`)本就具備且可 headless 呼叫(自測已證),但**只有 GUI 入口、結果從不序列化**。新增生產 CLI `IR_Collect.exe -correlate <out.json> <folderA> <folderB> [...]`:以 Phase 3.1 的 `LoadCaseFromFolder` 載入 ≥2 個資料夾、各自建 FactStore,跑跨機 shared-entity pivot(預設 entity 型別 Path/Hash/User/IP/AppId)+ 時間桶關聯,輸出新 `correlation_v1` JSON(`shared_entities[]`／`temporal_correlations[]`,每筆含 host_count/hosts/sources/first_seen/last_seen,時間以 ISO-8601 字串而非 `/Date()/`)。新增 `CorrelationExport`(DTO + 序列化)、`CorrelationCli`(可測 `BuildReport(cases, types, options)`)。新增自測 `CorrelateCli_finds_shared_entity_across_two_folders`(兩台 host 共用同一路徑 → 該路徑為跨機 shared entity + correlation_v1 schema)。對真實資料端到端驗證:兩台各 90,051 facts → 435 shared entities(User 185 + AppId 250 上限)+ 500 temporal,共享 `User S-1-5-18`(85,248 facts)橫跨兩台,時間桶 ISO 正確。不需提權、不需 GUI。
- **分析層前門 `-analyze <folder>`（Phase 3.1，核心命題：不在採集上競爭、成為可信任的分析層）**：新增生產 CLI 模式 `IR_Collect.exe -analyze <folder|-> [out.json]`,可對「已採集好的 artifact 資料夾」(他牌 triage 輸出、或解壓後的 IR_Collect case)直接跑與載入 case 完全相同的 facts-only 關聯管線(`FactStore.BuildFromCase` + GuidedHunt),輸出 `summary_v3` JSON——不碰 live host、不開 GUI。`<folder>` 給 `-` 時從標準輸入讀資料夾路徑(吃標準輸入)。新增 `CaseManager.LoadCaseFromFolder`(不解 ZIP、不刪資料夾,read-only 重用 LoadCase 的掃描/MFT/EVTX 重建/ShellBags/fact_store.db 步驟;`mft_preview.csv` 載入抽成共用 `LoadMftFromPreviewCsv`)與 `AnalysisCli`(headless `BuildHeadlessSummary`,由 `store.Facts` 直接統計 source/entity/notes,不依賴 GUI helper)。本增量涵蓋 $MFT(raw 或 preview)、EVTX(離線重建)、以及採集器產生的 CSV。新增端到端自測 `AnalyzeFolder_ingests_artifacts_and_builds_summary`(合成資料夾 → 載入 → 建 facts → 序列化 summary)。
- **原始 hive/ESE 自動解析(Phase 3.1b)**:`-analyze` 遇到資料夾內有原始 `Amcache.hve`／`SYSTEM`／`SRUDB.dat` 但無對應 CSV 時,以 IR_Collect 自家(已驗證)解析器離線解析並寫出正規採集器 CSV,使**他牌 triage 包也能直接產出 Amcache/ShimCache/SRUM facts**。新增 `RawArtifactCsvDeriver`(於 `LoadCaseFromFolder` 掃描前執行;不覆寫既有 CSV;對需提權而 fallback 的 artifact 不寫檔、改記一條 load-warning 提示提權重跑)。為杜絕格式漂移,將 `ExecutionArtifactCollector` 三個 CSV 寫出體抽成共用 `ExecutionArtifactCsvWriter`(`WriteAmcacheCsvs`／`WriteShimCacheEntriesCsv`／`WriteSrumCsvs`),採集器與 deriver 共用同一格式。新增 round-trip 自測 `RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer`(合成 parse result → 共用 writer → `AmcacheNormalizer` 還原出 Path/Hash entity)。**驗證分工:SRUM 用原生 ESE reader、不需提權 → 對真實 `SRUDB.dat` 端到端自驗證通過(73,826 app + 16,225 network = 90,051 facts);Amcache/ShimCache 用 `reg load` 需提權,非提權時正確降級為 load-warning(待提權 `-analyze` 驗證)。**
- **解析器 fixture 語料庫（Phase 2.1）**：新增 `tests/fixtures/`，以位元組層級保存 IR_Collect 自有解析器的決定性測試樣本——LNK（Unicode/ANSI LocalBasePath + 截斷/無 LinkInfo）、MFT run-list（合法/over-claim 截斷/零長度 run）、SRUM 身分 blob（合法 SID / UTF-16 AppId / subAuth 溢位畸形），共 11 個樣本，含 `manifest.json` 與 `README.md`。每個已修復的解析器 bug 都有一個獨立於 inline 測試碼的常駐回歸守門。
- **語料庫產生器與漂移守門**：新增 `IR_Collect_review.exe -make-fixtures [dir]`（由 `FixtureCorpus.Build()` 決定性重建語料庫，預設 `tests\fixtures`）。`-test` 新增 `FixtureCorpus_*`：對每個已提交檔案以真實解析器驗證**並**在記憶體重建後做位元組相等比對，使已提交語料庫無法與產生器靜默漂移（已負向驗證：竄改一個 byte 即 FAIL）。Self-tests 共 115 項。
- **Phase 2.2 預備**：`manifest.json` 的 `requiresRealSample` 區段登錄無法忠實合成的容器格式（Amcache.hve、AppCompatCache、SRUDB.dat ESE、ShellBags、完整 $MFT）及各自對應的參考工具（AmcacheParser / AppCompatCacheParser / SrumECmd / SBECmd / MFTECmd），供差異化驗證 harness 使用。
- **解析器差異化驗證 harness（Phase 2.2）**：新增 `scripts/DiffValidate.ps1` 與 `run_diff_validate.bat`，把 IR_Collect 的**真實生產解析器**與 Eric Zimmerman 工具（LECmd / JLECmd）跑在同一批真實 artifact 上做差異比對。新增 review-build CLI `IR_Collect_review.exe -parse <lnk|jumplist> <file> [out]`（emit 穩定 JSON；因 winexe stdout 不可靠故支援寫出檔）。LNK 為硬性 gate：若 LECmd 取得 LinkInfo LocalBasePath 而我們未重現即 FAIL；僅靠 target IDList 解析者（我方目前不涵蓋）另計為 coverage note。實測本機 34 個真實 LNK：**22/22 一致、0 mismatch**、11 個 IDList-only。JumpList 為 informational：我方 byte-scan heuristic 對 JLECmd（完整 OLE-CFB 解析）的 path recall 約 53.7%，明確標示為 Phase 2.3 待補（非 gate 失敗）。Harness 在缺工具時 skip-with-reason（exit 3→wrapper 視為 pass），不靜默放行。
- **差異化 harness 擴及 SRUM / Amcache（Phase 2.3b/c）**：`-parse srum`（`SrumExporter.Export` → app rows ts/path/user）、`-parse amcache`（`AmcacheParser.ParseHive` → file rows path/name/sha1）；`DiffValidate.ps1` 新增 `-Kind srum`（對 SrumECmd `AppResourceUseInfo.ExeInfo` 做 app set-overlap recall）與 `-Kind amcache`（對 AmcacheParser FileEntries 做 SHA1 set-overlap recall），皆 informational。當我方解析器 fall back 時 skip-with-reason（**實測發現**：本機未裝 ACE OLEDB provider → 我方 SRUM 靜默退回 header-only，屬相依脆弱性；Amcache `ParseHive` 走 `reg load` 需提權）。`CollectLocalSamples.ps1` 改為連同 hive 交易紀錄（`.LOG1/.LOG2`）一起複製，讓參考工具能 replay dirty hive。
- **共用 jump-list 抽路徑**：自 `ParseJumpListFile` 抽出 `JumpListsCollector.ExtractJumpListPaths(byte[])`（生產與 `-parse` CLI 共用同一段邏輯，保證兩者不漂移）；行為與原 inline 合併邏輯等價，既有 jump-list 測試全綠。
- **MFT 差異化驗證（Phase 2.2 延伸）**：`-parse` 新增 `mft`（`MftParser.Parse` → 每筆 record 的 path 與 Std MACB 時間，上限 60000 筆，UTC 秒精度）；review-build 新增 `-dump-mft <drive> <outDir>`（以 `MftDumper` raw-extract `$MFT`，需提權）。新增 `scripts/CollectLocalSamples.ps1`（提權執行：raw dump `$MFT` + 以暫時 Volume Shadow Copy 複製鎖定的 Amcache.hve / SYSTEM / SRUDB.dat 到 `samples/`，事後刪除 shadow；`samples/` 已 gitignore，屬本機真實證物、永不入庫）。`DiffValidate.ps1` 新增 `-Kind mft`：以 EntryNumber join MFTECmd CSV，FILENAME 不一致為硬性 gate、時間戳為 informational。

## [0.22.2] — 2026-06-06

### Fixed
- **config.ini 機密 ACL 保護**：`ConfigManager.Save` 寫入後 best-effort 將 ACL 鎖到當前使用者（停用繼承、移除其他規則、僅授當前使用者 FullControl）；FAT/exFAT 等非 NTFS 優雅降級。降低明文 API key 在可預期位置被讀取的風險。
- **分析師匯出 CSV 公式注入中和**：新增 `CsvUtils.EscapeFieldForExport`（與收集端 `EscapeField` 分離、收集 CSV 維持位元穩定）；對開頭為 `= + - @ \t \r` 的值加 `'` 前綴。套用於 Timeline 匯出 CSV（其餘分析師匯出為 JSON，已安全）。
- **Registry SAM/SECURITY 失敗對稱**：`RegistryCollector` 不再因 SAM 在非 LocalSystem 下失敗而將整個 Registry 步驟標為失敗（與 SECURITY 一致處理）。
- **記憶體 handoff 引數治理註記**：`memory_acquisition.json` / `memory_analysis.json` 新增 `args_governance_note`，標明工具引數為操作者提供、未驗證，僅 `{OutputPath}`/`{OutputDir}` 受治理。
- **AI / Upload POST 連線洩漏修正**：失敗時釋放 `WebException.Response`，並帶出伺服器錯誤內文。
- **USN 串流寫檔（防 OOM）**：`CommandHelper.RunToFile` 改為串流 stdout 至檔案（不整段 buffer），含逾時、stderr 抽乾、exit code 檢查與失敗時清除半成品檔。
- **Jump List LNK Unicode 路徑**：`TryParseLnkLocalPath` 依 MS-SHLLINK 重寫，依 LinkFlags／LinkInfoHeaderSize 正確使用 `LocalBasePathOffsetUnicode`(0x1C) 或 ANSI(0x10)，修正現代 jump-list LNK 路徑讀錯。
- **MFT run-list 邊界**：`MftDumper.ParseRunList` clamp `end` 至 buffer 長度並逐 run 做邊界檢查，畸形/截斷的 record-0 不再丟例外（原本被吞掉→靜默截斷 $MFT）。
- **MFT fact action 正確性**：`MftNormalizer` 在 Created 無效退回 Modified 時，Action 改標 `Modified`（原本永遠標 `Created`，造成時間軸假建立事件）。
- **EventLog 5145 絕對路徑**：額外輸出 `ShareLocalPath + RelativeTargetName` 組成之絕對路徑，使 SMB 檔案存取可與 MFT/USN/Amcache 絕對路徑關聯（相對片段仍保留）。
- **SRUM SID 解碼**：`SrumExporter.DecodeIdBlob` 建 SID 前要求 revision byte=0x01 與正確長度，避免 UTF-16 AppId 文字被誤判成假 SID 字串。

### Changed
- **專案開源（MIT）**：原本僅釋出 binary 的公開鏡像改為發佈完整原始碼（`.gitignore` 改為追蹤 source、排除 build 產物/執行期狀態/證物）；新增 GitHub Actions CI（每次 push/PR build + 跑 self-tests）。

### Added
- **Regression 覆蓋**：`IRCollectSelfTests` 自 v0.22.1 起新增 10 項（config ACL、CSV 匯出中和、RunToFile 串流、記憶體引數註記 round-trip、LNK ANSI+Unicode、MFT run-list 邊界、MFT action、5145 絕對路徑、SRUM SID 辨識），共 114 項。

## [0.22.1] — 2026-06-06

### Fixed
- **Fact timebase 一致性（關聯引擎）**：MFT／ShellBags 之 fact 帶 `Kind=Utc`，EventLog／Process／Activity 為 naive-local，而 `DateTime` 比較忽略 `Kind`，導致跨來源關聯依主機 UTC offset 錯位。新增 `FactStore.ToComparableUtc`（naive=local→UTC、Local→UTC、Utc passthrough，MinValue/MaxValue sentinel 保留；與 `NormalizeFactTimeForJson` 匯出政策一致），並套用於 `FactStore.GetByTimeRange` 與 `SharedEntityPivot` 時間窗篩選／bucketing。**不**改寫各 collector 來源時間（MFT MACB 仍為 UTC，避免變更鑑識可見時間語意）。
- **External command 穩定性**：`CommandHelper.RunCore` 改為以背景執行緒抽乾 stderr、主執行緒讀 stdout，避免單一管線緩衝區塞滿造成的 deadlock；並加上逾時上限（5 分鐘）與逾時 kill，避免 `wmic`／`fsutil`／`systeminfo` 等卡住整個收集。
- **cmd 引數跳脫**：`EscapeArgForCmd` 修正——移除引號內錯誤的 `^&`／`\"`（前者注入多餘 `^`、後者會提早結束 cmd 引號狀態），改為去除非法的雙引號後，僅在含 metacharacter 時以雙引號包裹。
- **AI redaction ReDoS**：所有 redaction regex 加上 1 秒 `matchTimeout`，重寫有歧義的 `RxUnixProfilePath`；逾時時 **fail-closed**（整段以 `[redacted]` 取代，不外洩）。
- **`fact_store.db` 載入 fail-soft**：單一損毀／缺 `SchemaVersion` 的 fact 列改為略過並計數，不再丟棄整個案卷；僅在 schema 版本整體不支援或「有列但無一可讀」時硬性失敗。略過數以 Load warning 呈現，提示重建 Fact Store。
- **EventLog 缺時間事件保留**：`EventLogNormalizer` 對 `TimeCreated` 缺失／無法解析的列不再整列丟棄，改為以 `UnknownTime`／`Low` confidence 保留 fact 與其實體（含 `FallbackUsed` 與 ParserNote），避免遺失 4624／4769／5145 等高價值橫向移動事實。
- **Jump List 讀取強化**：`ParseJumpListFile` 修正忽略 `FileStream.Read` 回傳值（部分讀取殘留零尾被誤解析）並加上 16 MB 上限，避免使用者目錄下被竄改的超大檔造成 OOM。
- **Fact Store 併發安全**：以單一 lock 保護 `FactStore.Facts`／`EntityIndex` 的變更與讀取，避免背景重建（`AugmentFactStoreWithRebuiltEventLogs`）與 UI 端 pivot／graph／entity search 同時存取造成 `InvalidOperationException` 或讀到半建好的索引。
- **Entity search 結果上限**：Dashboard Entity search 對結果加上 5000 筆上限與截斷提示，避免廣泛實體在大型多主機 Fact Store 上把非 virtual ListView 灌爆造成 UI 卡死／OOM。
- **SQLite DLL 載入完整性驗證（防 DLL planting）**：`FactStorePersistence.GetSqliteAssembly` 在 `Assembly.LoadFrom` 前先以 `SignatureHelper` 驗證 `System.Data.SQLite.dll`，僅在 Authenticode 簽章 `Signed-Trusted` 時才載入；未簽章／不受信任／不存在一律拒絕並記錄原因（SQLite 功能優雅降級）。同時降低用過舊引擎解析不受信任瀏覽器 SQLite DB 的 CVE 曝險。

### Added
- **Regression 覆蓋**：`IRCollectSelfTests` 新增 10 項——cmd 引數跳脫、`fact_store.db` fail-soft（略過／不支援 schema／全毀）、fact 時間 UTC 對齊與混合 Kind 時間窗查詢、EventLog 缺時間保留、Fact Store 併發 append 交換語意與並行讀寫無例外、SQLite DLL 未簽章/缺檔拒載。

## [0.22.0] — 2026-04-09

### Added
- **WP-A 出站治理**：AI 與 ZIP 上傳各用 endpoint allowlist；空清單預設阻擋對應 POST。Summary → **AI Analyze** 可選 redaction profile（僅影響將 POST 之 JSON）；Summary JSON 檔與 ZIP 內文不改寫。
- **WP-E Collection mode profile**：Settings 可選 `Standard` / `TriageFast` / `ForensicStrict`；寫入 `collection_coverage.json` 與分析師匯出。`ForensicStrict` 阻擋 Local Collect 後 ZIP 上傳與 **AI Analyze**，並加強收集前風險提示（非零足跡承諾）。
- **WP-D Jump List 正規化**：`jump_lists.csv` 納入 Fact Store／Timeline／Correlation Source；BITS `RemoteName` 多段衍生實體；Unified Timeline 不再重複餵入 raw jump CSV。
- **WP-C ShellBags 第一階段**：產生 `Registry\shellbags.csv`、`ShellBagsNormalizer`、UI **ShellBags (parsed)**、Correlation/Timeline/Entity `Sid`。
- **Guided Hunt Pack v1 + 服務與身分跡證**：`ServiceNormalizer`；`logon_sessions` / `network_resources` / `server_connections` / `stored_credentials` / `kerberos_tickets` 納入 Fact Store overlay；ATT&CK 對映、可解釋規則（唯讀 facts）。
- **Memory handoff 一等公民**：sidecar `schema=*_v2`、preset／驗證／診斷欄位；Settings 擴充；Memory 可正規化回 Summary／export（仍不解析 dump 內文）。

### Fixed
- **Strict acceptance hardening**：`collection_coverage.json` 之 Event Logs 改為逐對 `.evtx` / `*_filtered.csv`；有 `missing` 時 overall 不誤標 `complete`。
- **Memory orchestration clarity**：analyst 面向輸出併列 `Coverage` 與 `Sidecar`；handoff 拒絕 case root／證物目錄為分析輸出路徑。
- **Summary / HTML / summary_v3 consistency**：跨來源 parser notes 一致；HTML 缺失計數不顯示 `-1`；`summary_v3` 缺失數以 `0` 表示。
- **Timeline graph handoff**：structured entity match 優先、分鐘級時間窗。

### Docs
- README、`docs/README`、SPEC、REGRESSION_RUN、SMOKE_RUN 與 acceptance 行為對齊。
- `USER_MANUAL` / `FIELD_SOP` 英繁雙語；SPEC 版本歷程詳載 v0.22.0 各工作包。

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
