# IR_Collect v0.22.0 規格優化工程文件

## 1. 目的

本文件將 [SPEC.md](SPEC.md) §5.1 的 `v0.22.0 draft` 候選更新項目，從「方向清單」收斂成可執行的工程規格。

重點不是再擴寫願景，而是回答以下問題：

1. 哪些項目適合在目前 repo 架構上增量實作。
2. 哪些項目屬於 v0.22.0 核心範圍，哪些應延後。
3. 每個工作包應落在哪些既有模組。
4. 驗收、測試、文件同步應如何定義。

本文件應作為 v0.22.0 的工程拆分基準，而不是對外版本公告。

---

## 2. 輸入與範圍

本文件依據：

1. [SPEC.md](SPEC.md) §5.1 `v0.22.0 draft`
2. 目前程式骨架：
   - `Collector -> Artifact -> Normalizer -> Fact Store -> Timeline / Correlation / Export`
3. 目前已存在的模組：
   - `ConfigManager`
   - `MainFormSettings`
   - `CollectionCoverage`
   - `MemoryAcquisitionCollector`
   - `MemoryAnalysisCollector`
   - `FactStore`
   - `SummaryExport`

v0.22.0 的工程目標應聚焦在：

1. 補足目前已明確可行的缺口。
2. 提升 analyst-facing 安全性、交接性與可解釋性。
3. 避免把專案推向新的產品定位。

---

## 3. 不變原則

以下原則在 v0.22.0 不得被破壞：

1. 維持 `facts-only`，不得把新功能做成 heuristic / verdict 引擎。
2. 原始證據、分析 sidecar、workflow sidecar 必須分層，不直接改寫原始 ZIP。
3. 不把外部記憶體工具輸出包裝成平台內建結論。
4. 不承諾 `zero-footprint` 或「完整法院級鑑識」。
5. 不引入重型新依賴或迫使架構跳脫目前 `WinForms + C# 5 / .NET Framework` 相容邊界。
6. 不任意漂移既有 schema / field semantics；若新增欄位，必須向後相容。
7. 所有新 facts 若進入 Fact Store，必須帶既有 provenance 欄位。

---

## 4. v0.22.0 核心工作包

下列工作包依「適合目前 repo 增量實作」與「對產品可信度有直接價值」排序。

### WP-A: Redaction / Endpoint Governance

#### 目標

補上 AI / Upload 出站治理，降低敏感資料外送風險。

#### 為什麼先做

目前 AI / Upload 出站點集中，工程切入面小，但風險高、收益直接。

#### 既有掛點

1. `src/ConfigManager.cs`
2. `src/MainFormSettings.cs`
3. `src/MainForm.cs`
4. `docs/SECURITY.md`

#### 建議交付

1. 新增 endpoint allowlist 設定。
2. 新增 AI 匯出 redaction profile，至少區分：
   - `None`
   - `Basic`
   - `Strict`
3. AI request 發送前顯示目前 profile / endpoint / payload 模式。
4. 若 endpoint 不在 allowlist，預設拒絕送出。
5. Upload path 與 AI path 分開治理，不共用模糊開關。

#### 明確限制

1. `summary.json` / AI request 可做 redaction。
2. 原始 ZIP upload 不應假裝「邊上傳邊 redaction」。
3. 對 raw case ZIP，v0.22.0 應做的是治理與阻擋，不是內容改寫。

#### 驗收

1. 未列入 allowlist 的 endpoint 無法送出。
2. AI request 可依 profile 輸出不同敏感度 payload。
3. Summary / UI 能清楚顯示目前 profile 與 endpoint policy。
4. `SECURITY.md`、`README.md`、`USER_MANUAL*` 同步更新。

---

### WP-B: Memory Handoff 一等公民化

#### 目標

把現有 memory acquisition / analysis handoff 從「可接」提升到「可穩定交接與可稽核」。

#### 既有掛點

1. `src/Collectors/MemoryAcquisitionCollector.cs`
2. `src/Collectors/MemoryAnalysisCollector.cs`
3. `src/MemoryAcquisitionRecord.cs`
4. `src/MemoryAnalysisRecord.cs`
5. `src/Collector.cs`
6. `src/Tests/IRCollectSelfTests.cs`

#### 建議交付

1. 常見外部工具 preset / args template。
2. sidecar 輸出驗證規則集中化，不要散落在 collector 內。
3. 常見失敗診斷訊息正規化，例如：
   - tool path missing
   - not elevated
   - timeout
   - dump missing
   - output dir invalid
4. Summary / HTML / `summary.json` / `full_log_v3` 對 memory coverage 與 sidecar 的說明再收斂一致。

#### 可選深化

若時間允許，可新增有限度的 sidecar-normalized memory facts，但必須符合：

1. 僅接受明確、低爭議、可 facts-only 化的輸出。
2. 僅限外部工具已產生的結構化 sidecar。
3. 不做完整 Volatility UI，也不做 verdict。

#### 驗收

1. 設定、執行、coverage、summary 的狀態語意一致。
2. sidecar 宣稱成功但輸出缺失時，coverage 必須降級。
3. 既有 memory self-tests 持續通過，並擴充 preset / 診斷測試。

---

### WP-C: ShellBags 內建解析

#### 目標

把目前 `raw/export-only` 的 ShellBags 收集，提升成平台內可直接檢視與 pivot 的結構化資料。

#### 既有掛點

1. `src/Collectors/RegistryCollector.cs`
2. `Registry\\ShellBags_<SID>.reg`
3. `Registry\\UsrClass_<SID>.dat`
4. `FactStore`
5. Host tabs / Timeline / Entity search

#### 建議交付

1. 新增 ShellBags parser，第一階段優先吃 `.reg` 匯出。
2. 產出 `shellbags.csv`。
3. 新增 `ShellBagsNormalizer` 接入 Fact Store。
4. Host UI 新增 ShellBags 檢視分頁。
5. Timeline / Entity search 能用 `Path`、`User` 等常見實體 pivot。

#### 工程取捨

v0.22.0 不要求一次處理所有 Shell Item 細節。應優先：

1. 路徑還原
2. 可用時間欄位
3. parser notes / partial decode

#### 驗收

1. 匯入含 `ShellBags_<SID>.reg` 的案卷後，平台可見 `shellbags.csv` 或等效結構化輸出。
2. 可在 UI 與 Fact Store 中檢視。
3. 無法完整還原時，要保留 parser notes，而非靜默失敗。

---

### WP-D: 非 Event Log 的 lateral movement / identity 補強

#### 目標

降低橫向移動與身分濫用調查對 Security / TerminalServices log 的單點依賴。

#### 既有掛點

1. `src/Collectors/ExecutionArtifactCollector.cs`
2. `src/Analysis/Correlation/Normalizers/*`
3. `src/Analysis/Correlation/FactStore.cs`
4. `Timeline Analysis`
5. `Investigation Graph`

#### 建議方向

v0.22.0 應優先強化「已存在 artifacts 的正規化與 entity 化」，不要一開始就再開太多新 collector。

優先來源：

1. `BITS`
2. `WMI Persistence`
3. `SRUM Network / App`
4. `Activity Timeline`
5. `Jump Lists`
6. `ShellBags`（若 WP-C 完成）

#### 建議補強實體

1. `RemoteName`
2. `RemoteIP`
3. `User`
4. `Path`
5. `Share-like path`
6. `WmiFilter`
7. `WmiConsumer`
8. `TaskName`
9. `BitsJob`

#### 驗收

1. 在缺乏關鍵 Event Log 時，仍可透過非 log artifacts 做基本 cross-source pivot。
2. 新增 facts 需進入 `Facts`、`Timeline`、`Entity search`、`full_log_v3`。
3. 不新增 verdict 型欄位，只新增可解釋的 fact/action/entity。

#### 交付快照（v0.22.0 實作進度）

- **已完成（本變更）**：`jump_lists.csv` → `JumpListNormalizer`；`BITS` `RemoteName` 以 `;` 分段後 UNC／URL 衍生實體（`Workstation`／`ShareName`／`RemoteIP`），保留完整 `RemoteName` 字串；Correlation **Source** 增 **JumpList**；Unified Timeline 僅經 `activity_timeline.csv` 呈現 Jump List 列、不重複 merge `jump_lists.csv`；`IRCollectSelfTests` 最小覆蓋。
- **仍可做（非本次範圍）**：WMI／SRUM／Activity Timeline 的 incremental entity 化；更大範圍文件化。

---

### WP-E: Low Impact / Forensic Strict Profile

#### 目標

把目前對 live-response 影響的說明，從文件建議提升為可被設定、可被記錄、可被 warning 的操作 profile。

#### 重要澄清

此工作包的目標是「降低擾動並提高操作者自覺」，不是把工具變成 `zero-footprint`。

#### 既有掛點

1. `src/ConfigManager.cs`
2. `src/MainFormSettings.cs`
3. `src/MainFormCollection.cs`
4. `src/Collector.cs`
5. `collection_coverage.json`
6. Summary / HTML / `summary.json`

#### 建議交付

1. 新增 collection mode profile，例如：
   - `Standard`
   - `TriageFast`
   - `ForensicStrict`
2. `ForensicStrict` 下強化：
   - 現場 warning
   - 輸出位置風險提示
   - 停用或預設拒絕 AI / Upload
   - 停用高爭議步驟的預設啟用
3. 將本次 mode profile 寫入 `collection_coverage` / summary 匯出。
4. 明確記錄「本次收集工具自產痕跡與限制」。

#### 工程風險

此工作包是 cross-cutting change，容易碰到收集流程、UI 提示、文件與 schema，一次不要做太大。

#### 驗收

1. 不同 profile 會在 UI / 匯出中被明確記錄。
2. `ForensicStrict` 會阻擋或明確警示不符合該模式的操作。
3. 文件不應誤導使用者把此模式理解為完整 forensic imaging。

#### 實作狀態（與 SPEC / 測試對齊）

- **Settings**：`CollectionModeProfile`（`Standard` / `TriageFast` / `ForensicStrict`）由 **Advanced → Settings** 保存至 `config.ini`。
- **稽核欄位**：`collection_coverage.json`、`summary.json`、`full_log_v3` 的 `hosts[]` 可含 `collection_mode_profile`；GUI Summary 的 `parser_notes` 亦會複述（若有）。
- **ForensicStrict**：收集前強化警示（含輸出目錄路徑）；**阻擋** Local Collect 後 ZIP 上傳與 **AI Analyze**（與 WP-A allowlist 分層；變更 profile 後才恢復 allowlist 流程）。

---

## 5. 延後或降級項目

### Deferred-1: Guided Hunt Pack

這個方向有價值，但應在 v0.22.0 核心工作包穩定後再做。原因：

1. 它屬分析提示層，不是資料可信度核心。
2. 若先做，容易模糊 `facts-only` 邊界。

若後續實作，必須與 Fact Store 分層，並在 UI / export 明確標示為 analyst guidance。

### Deferred-2: Case Diff / Baseline Diff

此功能技術上可做，但不建議列為 v0.22.0 核心交付。

原因：

1. 目前 spec 對此項仍處於候選狀態，尚未收斂成明確需求。
2. 工程上會碰到 baseline 定義、diff 粒度、UI 呈現、效能與輸出 schema。
3. 相比治理、memory handoff、ShellBags，此項對目前可信度提升不是第一優先。

建議做法：

1. 先完成 `fact_store.db` / `full_log_v3` 的穩定化。
2. 後續以 normalized entity / fact diff 原型切入，不以 raw file diff 切入。

---

## 6. 建議開發順序

### Wave 1: 低風險高收益

1. WP-A `Redaction / Endpoint Governance`
2. WP-B `Memory Handoff 一等公民化`

### Wave 2: 補 analyst 使用缺口

1. WP-C `ShellBags 內建解析`
2. WP-D `非 Event Log 補強`

### Wave 3: 跨模組行為收斂

1. WP-E `Low Impact / Forensic Strict Profile`

### Post-v0.22.0 / Stretch

1. `Guided Hunt Pack`
2. `Case Diff / Baseline Diff`

---

## 7. 檔案邊界建議

為避免一次 patch 過大，建議按工作包拆 ownership：

### Config / UI / Governance

1. `src/ConfigManager.cs`
2. `src/MainFormSettings.cs`
3. `src/MainForm.cs`
4. `src/MainFormCollection.cs`

### Collection / Memory

1. `src/Collector.cs`
2. `src/Collectors/MemoryAcquisitionCollector.cs`
3. `src/Collectors/MemoryAnalysisCollector.cs`
4. `src/MemoryAcquisitionRecord.cs`
5. `src/MemoryAnalysisRecord.cs`

### New Artifact / Parser / Normalizer

1. `src/Collectors/RegistryCollector.cs`
2. 新增 `src/Utils/ShellBagsParser.cs`
3. 新增 `src/Analysis/Correlation/Normalizers/ShellBagsNormalizer.cs`
4. `src/Analysis/Correlation/FactStore.cs`
5. `src/MainFormTimeline.cs`
6. `src/MainForm.cs`

### Regression / Documentation

1. `src/Tests/IRCollectSelfTests.cs`
2. `README.md`
3. `docs/README.md`
4. `docs/SPEC.md`
5. `docs/USER_MANUAL.md`
6. `docs/USER_MANUAL.zh-TW.md`
7. `docs/FIELD_SOP.md`
8. `docs/FIELD_SOP.zh-TW.md`
9. `docs/SECURITY.md`

---

## 8. v0.22.0 共通驗收

所有 v0.22.0 工作包都必須滿足：

1. `build.bat` 成功。
2. review build / self-tests 不退化。
3. 新欄位或新 artifact 不破壞既有匯入與舊案卷讀取。
4. `Summary`、HTML、`summary.json`、`full_log_v3` 的語意一致。
5. docs 同步，不把新功能只留在 code。

### 建議新增 regression 類型

1. endpoint allowlist block / allow
2. AI redaction profile 行為
3. memory preset / diagnostics / output validation
4. ShellBags parse success / partial decode
5. 非 Event Log cross-source pivot
6. collection mode profile 輸出與 warning

---

## 9. 明確不做的事

為避免規格失控，v0.22.0 不應被實作成以下方向：

1. 完整記憶體鑑識平台
2. 自動惡意判定或 AI verdict engine
3. raw evidence 自動 redaction
4. graph canvas 大改版
5. 將 live response 包裝成零擾動鑑識

---

## 10. 結論

`v0.22.0` 應該被做成「可信度與交接能力的收斂版本」，而不是再一次大範圍擴張。

最合理的主線是：

1. 先補治理與 memory handoff 的可信度。
2. 再補 ShellBags 與非 Event Log 的調查深度。
3. 最後再把 low-impact profile 做成可設定、可記錄、可驗收的操作模式。

這樣能在不破壞目前產品定位的前提下，讓 draft roadmap 變成真正可執行的工程工作包。
