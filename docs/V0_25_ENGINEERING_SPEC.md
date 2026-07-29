# 9SEC Evidence Workbench v0.25.0 工程規格與實作狀態

**狀態（2026-07-29）**：WP-A、WP-B 第一階段與 WP-C 第一階段均已完成並通過
review regression；本文保留需求、實作邊界、驗收與 defer 項，作為 `v0.25.0`
發版工程紀錄，正式版本號已與 `src/AssemblyInfo.cs` 對齊。

## 1. 目的

本文將最能直接改善實戰調查效率的三個方向，收斂成可驗收的 `v0.25.0` 工程規格，並記錄目前實作狀態：

1. `Case Diff / Baseline Diff`
2. `Large Case Performance / Incremental Rebuild`
3. `Low Impact / Forensic Strict` 完整化

本文不是對外版本公告，也不是產品宣傳文案；它的用途是回答以下問題：

1. 哪些缺點屬於可工程化改善，而不是產品類型的先天取捨。
2. 每個工作包應落在哪些既有模組與資料流。
3. 這些工作應如何分波次實作與驗收。

---

## 2. 輸入與範圍

本文依據：

1. [SPEC.md](SPEC.md) 現況與 roadmap
2. 既有工程原則：
   - `Collector -> Artifact -> Normalizer -> Fact Store -> Timeline / Correlation / Export`
3. 既有分析層與離線前門：
   - `AnalysisCli`
   - `FactStore`
   - `GuidedHuntPack`
   - `InvestigationGraph`

`v0.25.0` 的目標不是再擴大產品邊界，而是收斂下列 analyst friction：

1. 缺少快速差異視角
2. 大案量重建與重開成本高
3. Forensic Strict 原先偏警示，缺少可操作、可記錄的 profile restriction

---

## 3. 不變原則

以下原則在 `v0.25.0` 不得被破壞：

1. 維持 `facts-only`，不新增 heuristic / verdict engine。
2. 新功能若進入 Fact Store，必須沿用既有 provenance 欄位。
3. 不把 live response 包裝成 `zero-footprint`。
4. 不把外部記憶體工具 orchestration 擴張成內建 Volatility/Rekall 級分析平台。
5. 任何使用者可調整的行為，一律透過 **Advanced -> Settings** 暴露，並由 `ConfigManager` 管理。
6. 不漂移既有 `summary_v3` / `diff_v1` / `full_log_v3` / `correlation_v1` / `graph_v1` schema；若新增欄位，需向後相容。

---

## 4. v0.25.0 核心工作包

### WP-A: Case Diff / Baseline Diff

#### 實作狀態（2026-07-28）

已完成：`DiffBuilder`、`DiffCli`、`DiffExport`、GUI `Diff` 分頁、Facts / Timeline
下鑽、`diff_v1` draft-07 schema、fixture / GUI / CLI / source-read-only 自測。單次報告最多
50,000 changes，雙側最多各保留 20 個 fact references；截斷會由 `changes_truncated`
明示。Added/Removed 的 notes 會提醒「未觀察到不等於不存在」；case reference 保留
collection coverage / Fact Store freshness，fact reference 保留 collection / parse
provenance，供分析師判讀。

#### 目標

提供「和基線相比到底新增了什麼」的第一視角，讓分析師能更快聚焦在：

1. 新增程序
2. 新增持久化
3. 新增或消失的檔案與 hash
4. 新增關鍵實體關聯（帳號、遠端端點、分享、服務、排程等）

#### 為什麼優先

目前平台擅長：

1. 收集
2. 時間軸
3. 關聯
4. 圖譜

但缺少「變化量」視角。這不是資料不足，而是工作流缺口。

#### 範圍

`v0.25.0` 只做：

1. `host vs baseline`
2. `host vs host`
3. `same host old case vs new case`

`v0.25.0` 不做：

1. 自動 benign suppression 引擎
2. 複雜角色型 baseline 推論
3. 原始檔案 byte-level diff UI

#### 資料模型（已實作）

新增 `diff_v1` 輸出格式，至少包含：

1. `diff_schema`
2. `generated_at`
3. `tool_name`
4. `tool_version`
5. `baseline_ref`
6. `target_ref`
7. `changes[]`

每筆 `change` 包含：

1. `category` (`Process` / `Persistence` / `File` / `Identity` / `Network` / `Fact`)
2. `change_type` (`Added` / `Removed` / `Modified`)
3. `entity_key`
4. `display_value`
5. `source_names`
6. `confidence`
7. `baseline_fact_refs`
8. `target_fact_refs`
9. `notes`

#### UI / CLI

GUI：

1. 新增 `Diff` 分頁
2. 可依 `Category` / `ChangeType` / `Source` / `Host` 篩選
3. 雙擊結果可跳到 `Facts` 或 `Timeline`

CLI：

1. 新增 `9SEC_Evidence_Workbench.exe -diff <baseline> <target> [out.json]`

#### 實際檔案邊界

1. 新增 `src/Analysis/DiffCli.cs`
2. 新增 `src/Analysis/DiffExport.cs`
3. 新增 `src/Analysis/Correlation/DiffBuilder.cs`
4. `src/Analysis/CaseManager.cs`
5. `src/MainFormAnalysis.cs`
6. `src/MainForm.cs`

#### 驗收

1. 已知 fixture 可正確標出新增 autorun / service / task / executable / shared hash。
2. GUI diff 結果可跳回對應 facts。
3. `diff_v1` 可在不依賴 GUI 的情況下由 CLI 產生。

#### Defer

1. 不做全域 baseline repository
2. 不做自動風險分數
3. 不做基線學習

---

### WP-B: Large Case Performance / Incremental Rebuild

#### 實作狀態（2026-07-28）

第一階段已完成：`FactStoreBuildCoordinator` 會為實際 normalizer inputs 建立
`relative_path / size / mtime_utc / sha256 / normalizer_name` manifest。啟用
**Advanced → Settings → Persist Fact Store cache in Local AppData** 後，完全相同的輸入會
`Reused`；只有 filtered Event Log CSV 新增、刪除或變更時，只替換受影響的 EventLog
facts 並標示 `Incremental`；其他來源變更、tool/config/schema 不相容或 cache 損毀均以
明確原因回退 `Full`。

持久化 cache 使用目前使用者 Local Application Data 下的 gzip JSON，而不是把效能快取
寫回 evidence root。寫入採同目錄 temporary file 後原子發布，ACL 以 best effort 限制為
目前使用者，讀取另有 1 GiB compressed / 4 GiB decompressed 安全上限。Settings 可清除
cache；Summary、HTML、`summary_v3`、`full_log_v3` 與 CLI 會顯示 build mode、時間、原因
及 input manifest。Cache 預設關閉，可能包含敏感 normalized facts。

本階段未把所有 normalizer 都拆成可獨立 partial rebuild。filtered Event Log 以外的變更
刻意採 Full rebuild，以維持 provenance、entity index 與跨來源 facts 的一致性。既有
`fact_store.db` 仍維持可選的 case-level SQLite 輸出與 freshness 檢查，不被內部 cache
取代。

#### 目標

降低大案匯入、重開、重建的成本，特別是：

1. 舊案重新打開
2. 只更新少量 artifacts
3. 單一主機重建 Event Logs 或 Fact Store

#### 為什麼優先

目前 repo 已做過一輪收集性能優化，但分析端的大案量成本仍存在，特別是匯入與 rebuild。[SPEC.md](SPEC.md)

#### 範圍

`v0.25.0` 只做：

1. artifact fingerprint
2. incremental invalidation
3. partial rebuild
4. 更積極利用 `fact_store.db`

`v0.25.0` 不做：

1. 跨 schema 自動 migration 修復
2. 分散式 index
3. 長駐背景服務

#### 資料模型（已實作）

為每個 source artifact 記錄：

1. `relative_path`
2. `size`
3. `mtime_utc`
4. `sha256`（可選；先針對高價值小檔啟用）
5. `normalizer_name`

Fact Store metadata 已包含：

1. `build_mode` (`Full` / `Incremental` / `Reused`)
2. `build_inputs_manifest`
3. `build_generated_at`

#### 重建策略

1. 匯入時先比對 artifact fingerprint
2. 未變動 artifact 不重跑 normalizer
3. 單一 artifact 變動時，只重建受影響 facts / entity index
4. 若偵測 schema 不相容，回退到 full rebuild

#### UI / CLI

GUI：

1. Summary 顯示 `Fact Store build mode`
2. `Rebuild Selected Host Fact Store` 新增 `changed artifacts only`

CLI：

1. `-analyze` 若遇到可重用快取，輸出明確提示 `reused` / `incremental`

#### 實際檔案邊界

1. `src/Analysis/Correlation/FactStore.cs`
2. `src/Analysis/Correlation/FactStorePersistence.cs`
3. `src/Analysis/CaseManager.cs`
4. `src/MainFormCollection.cs`
5. `src/MainFormAnalysis.cs`

#### 驗收

1. 未變動案卷重匯入時，不再全量 rebuild。
2. 單一 `EventLogs/*_filtered.csv` 變更時，不重跑無關 normalizer。
3. Summary / warnings 對快取重用或回退 full rebuild 的原因有明確說明。

目前三項均已由 self-tests 覆蓋：cache exact reuse、EventLog-only incremental、non-Event
change full fallback、corrupt cache full fallback，以及 stale store auto rebuild。

#### Defer

1. 不做背景預編譯索引器
2. 不做全文搜尋引擎
3. 不重寫現有 facts schema

---

### WP-C: Low Impact / Forensic Strict 完整化

**實作狀態（2026-07-29）**：第一階段完成，程式、schema、雙語手冊、field SOP 與
自動化回歸測試已同步。

#### 目標

把原先偏警示型的 `ForensicStrict`，收斂成「可操作、可記錄、可驗收」的低擾動 profile。

#### 重要澄清

此工作包的目標是：

1. 降低不必要擾動
2. 提高操作者自覺
3. 把 tradeoff 明確寫進 coverage 與 summary

它不是要把工具變成 `zero-footprint`。

#### 範圍

`v0.25.0` 只做：

1. 輸出位置風險檢查
2. 高擾動步驟二次確認
3. profile-driven step restriction
4. coverage / summary / export 一致記錄

`v0.25.0` 不做：

1. offline imaging
2. core collector 重寫
3. 對所有 collector 做完全 read-only 保證聲明

#### 設定項（已實作）

在 **Advanced -> Settings** 新增或收斂：

1. `RequireRemovableMediaConfirmation`
2. `WarnOnSystemDiskOutput`
3. `ForensicStrictSkipMemoryHandoff`
4. `ForensicStrictSkipDeepScan`
5. `ForensicStrictRequireSecondConfirmation`

上述選項都必須由 `ConfigManager` 管理，不新增僅可手改 `config.ini` 的隱藏開關。

#### 資料模型（已實作）

在 `collection_coverage.json` 補充：

1. `operator_acknowledged_risks`
2. `restricted_steps`
3. `skipped_by_profile`
4. `output_target_class` (`system_disk` / `removable` / `network` / `unknown`)

Summary / `summary.json` / `full_log_v3` 需可見：

1. 當次 profile
2. 因 profile 被略過的步驟
3. 這些略過如何影響 coverage

#### 實際檔案邊界

1. `src/ConfigManager.cs`
2. `src/MainFormSettings.cs`
3. `src/MainFormCollection.cs`
4. `src/Collector.cs`
5. `src/CollectionCoverage.cs`
6. `src/CollectionImpactPolicy.cs`
7. `src/Program.cs`
8. `src/MainForm.cs`
9. `src/Collectors/MemoryAcquisitionCollector.cs`
10. `src/Collectors/MemoryAnalysisCollector.cs`
11. `src/Analysis/Correlation/FactStorePersistence.cs`
12. `src/Analysis/SummaryPayloadAiRedactor.cs`
13. `docs/schemas/summary_v3.schema.json`

#### 驗收

1. [x] `ForensicStrict` 下，輸出落在系統碟時有強警示；CLI / GUI 顯示 output class。
2. [x] 未完成風險確認時，Collector 在建立輸出目錄前拒絕 strict run；CLI 回傳 `3`。
3. [x] 預設二次確認，且五項 safeguard 皆可由 Settings 設定並由 `ConfigManager` 保存。
4. [x] Enabled memory acquisition / analysis handoff 因 profile 略過時，不啟動外部工具，寫出 `skipped` sidecar，coverage overall 降為 `partial`。
5. [x] Deep Scan 在預設 strict policy 下被阻擋。
6. [x] `operator_acknowledged_risks`、`restricted_steps`、`skipped_by_profile`、`output_target_class` 可在 coverage、Summary、HTML、`summary_v3` 與 `full_log_v3` host metadata 檢視。
7. [x] 文案不把該模式描述成完整鑑識映像或 zero-footprint。

自動化驗證涵蓋 system/network/unknown 分類、strict/standard restrictions、Collector fail
closed、memory sidecar 無外部 process 路徑、coverage round-trip/partial semantics、
Summary/HTML/export/schema drift；完整 live collection 仍依 [SMOKE_RUN.md](SMOKE_RUN.md)
在授權測試主機執行。

#### Defer

1. 不做 kernel driver
2. 不做 write-blocking
3. 不做全步驟可證明零寫入

---

## 5. 延後或不做的項目

### Deferred-1: 內建深度記憶體解析

理由：

1. 這會把工具從 DFIR collector/workspace 推向另一個產品類型。
2. 目前定位已明確是外部工具 orchestration + validation。

### Deferred-2: 自動惡意 verdict / risk score

理由：

1. 會破壞 `facts-only` 核心邊界。
2. 容易讓分析師把引導結果誤當結論。

### Deferred-3: zero-footprint 宣稱

理由：

1. 不符合 live-response 類型本質。
2. 文檔與 UX 應維持誠實，不做過度承諾。

---

## 6. 開發順序與完成狀態

### Wave 1: 直接改善分析效率

1. [x] WP-A `Case Diff / Baseline Diff`

### Wave 2: 降低重開與重建成本

1. [x] WP-B `Large Case Performance / Incremental Rebuild`（第一階段完成）

### Wave 3: 收斂現場操作風險表達

1. [x] WP-C `Low Impact / Forensic Strict` 完整化（第一階段完成）

### Stretch / Post-v0.25.0

1. 更完整 ShellBags semantic recovery
2. 更多非 Event Log pivot sources（第一階段已完成 UAC executable/running-process hash facts）
3. Guided Hunt 規則擴充

---

## 7. 共通驗收

所有 `v0.25.0` 工作包都必須滿足：

1. `build.bat` 成功
2. review build / self-tests 不退化
3. 不破壞既有 `summary_v3` / `diff_v1` / `full_log_v3` / `correlation_v1` / `graph_v1`
4. GUI 與 CLI 對同一功能的語意一致
5. 文檔與 schema 同步；未完成或 defer 功能不得寫成既成事實

已納入 regression：

1. `-diff` 正反向 fixture
2. incremental rebuild cache hit / miss / fallback
3. Forensic Strict restricted-step coverage rendering

---

## 8. 結論

`v0.25.0` 主線沒有再追更多 artifacts，而是補齊三件最影響實戰節奏的事：

1. 已提供分析師差異視角
2. 已降低未變動案卷與 EventLog-only 變更的重建成本
3. 已把 Forensic Strict 從提醒收斂成可驗收的操作模式

這三項都能在不改變產品定位的前提下，讓 9SEC Evidence Workbench 更接近一個成熟的 Windows DFIR 實戰工作台。
