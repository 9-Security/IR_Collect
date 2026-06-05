# IR_Collect Cursor 工程計畫書

## 1. 目標

本計畫的目的，是在不破壞目前 `facts-only`、`portable`、`Windows host DFIR` 定位的前提下，補強下列能力：

1. 補 execution / persistence artifacts 的結構化分析能力。
2. 把跨主機關聯從 pivot table 提升到 investigation workspace。
3. 補 analyst workflow，讓工具更貼近真實辦案流程。
4. 補 lateral movement 分析能力。
5. 補 evidence provenance，讓每筆 fact 更可採信、可複查。

本計畫預設由 Cursor / Codex 逐階段實作，不要求一次做完。

## 2. 不變原則

以下原則不得被破壞：

1. 工具維持 `facts-only`，不得恢復 heuristic / rule 結論輸出。
2. 原始證據與分析 sidecar 分離，不直接修改原始 ZIP。
3. 保留 `Collector -> Artifact -> Normalizer -> Fact Store -> Timeline / Correlation / Export` 主架構。
4. 優先維持現有 `WinForms + .NET Framework + C# 5` 相容性，不引入重型新依賴。
5. 所有新增 facts 都必須帶入既有 provenance 欄位。

## 3. 專案邊界

### 本專案適合做

1. Windows host artifacts 收集與結構化解析。
2. 多主機 entity pivot / timeline correlation / graph-style investigation。
3. 分析師工作流、註記、交接、匯出。
4. 記憶體採集整合入口。

### 本專案不應硬做成

1. 完整 EDR。
2. 法院級完整鑑識平台。
3. 自動下結論的 AI 判案工具。
4. 大量依賴雲端 API 的 SaaS 調查平台。

## 4. 分期規劃

---

## Phase 1: Execution / Persistence 結構化解析

### 目標

把目前已收進案卷但仍偏 raw 的 execution / persistence evidence，轉成可進 Fact Store / Timeline / Entity search 的 facts。

### 範圍

1. `Amcache.hve` 解析。
2. `ShimCache` entry-level 解析。
3. `SRUDB.dat` 結構化匯出。

### 主要工作

1. 新增 parser / exporter：
   - `src/Collectors/ExecutionArtifactCollector.cs`
   - 新增 `src/Utils/AmcacheParser.cs`
   - 新增 `src/Utils/ShimCacheParser.cs`
   - 新增 `src/Utils/SrumExporter.cs`
2. 新增中間輸出：
   - `amcache_programs.csv`
   - `amcache_files.csv`
   - `shimcache_entries.csv`
   - `srum_network_usage.csv`
   - `srum_app_usage.csv`
3. 新增 normalizer：
   - `src/Analysis/Correlation/Normalizers/AmcacheNormalizer.cs`
   - `src/Analysis/Correlation/Normalizers/ShimCacheEntryNormalizer.cs`
   - `src/Analysis/Correlation/Normalizers/SrumNetworkNormalizer.cs`
   - `src/Analysis/Correlation/Normalizers/SrumAppNormalizer.cs`
4. 接進：
   - [FactStore.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/FactStore.cs)
   - [MainFormTimeline.cs](/D:/cursor/IR_script/IR_Collect/src/MainFormTimeline.cs)
   - [MainForm.cs](/D:/cursor/IR_script/IR_Collect/src/MainForm.cs)

### 建議 facts

1. `Amcache`
   - Action: `Executed`, `Installed`, `FirstObserved`
   - Entities: `Path`, `FileName`, `Hash`, `Publisher`, `ProductName`, `User`
2. `ShimCache`
   - Action: `ExecutedCandidate`
   - Entities: `Path`, `FileName`
3. `SRUM Network`
   - Action: `NetworkUsageObserved`
   - Entities: `AppId`, `Path`, `User`, `RemoteIP`, `Interface`
4. `SRUM App`
   - Action: `AppResourceUsageObserved`
   - Entities: `AppId`, `Path`, `User`

### 驗收標準

1. 匯入含 `ExecutionArtifacts` 的案卷後，自動產生上述 CSV。
2. 相關 facts 會出現在 `Facts`、`Entity search`、`Timeline`。
3. 每筆 fact 具有 `SourceFile / CollectionStep / CollectionStatus / CollectionPrivilege / ParseLevel / FallbackUsed`。
4. `summary.json`、`full_log_v3`、HTML report 能看見新 source counts。

### 風險

1. `SRUM` 結構複雜，建議先做可穩定輸出的核心表，不追求一次全覆蓋。
2. `Amcache / ShimCache` 跨版本差異大，先做 parser notes 與 fallback。

---

## Phase 2: Investigation Graph Workspace

### 目標

把目前的 shared / related / time-window / graph-style table，提升成分析師可持續操作的 investigation workspace。

### 範圍

1. Seed entity graph 展開。
2. Edge drilldown。
3. Host-scoped pivot。
4. Graph session state。

### 主要工作

1. 擴充分析層：
   - [InvestigationGraph.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/InvestigationGraph.cs)
   - [SharedEntityPivot.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/SharedEntityPivot.cs)
   - 新增 `src/Analysis/Correlation/InvestigationWorkspaceState.cs`
2. 擴充 UI：
   - [MainFormAnalysis.cs](/D:/cursor/IR_script/IR_Collect/src/MainFormAnalysis.cs)
   - [MainForm.cs](/D:/cursor/IR_script/IR_Collect/src/MainForm.cs)
3. 新功能：
   - `Expand From Selected Edge`
   - `Pin Seed`
   - `Filter To Host`
   - `Open In Focused Facts`
   - `Open In Timeline`
   - `Back / Forward Graph Navigation`

### UI 形式建議

因現有為 WinForms，不建議一開始硬做高互動 graph canvas。先做：

1. graph-style table
2. edge detail panel
3. seed trail / breadcrumb
4. pinned entities panel

### 驗收標準

1. 分析師可以從任一 `Path / User / RemoteIP / ServiceName / TaskName / Hash` 當 seed。
2. 可展開一層以上關聯，不只停在單次查詢。
3. 任一 edge 可下鑽到 host-level facts，並跳進該 host 的 focused Facts / Timeline。
4. graph filters 可與現有 `Source / Confidence / Host / From / To / Window` 共用。

---

## Phase 3: Analyst Workflow 強化

### 目標

把目前 workflow sidecar 從單機標記，提升到真正可辦案的 case workflow。

### 範圍

1. Fact-level bookmark / tag。
2. Host-level notes。
3. Hypothesis tracking。
4. Priority / status。
5. Review export。

### 主要工作

1. 擴充：
   - [AnalystWorkflow.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/AnalystWorkflow.cs)
   - [MainForm.cs](/D:/cursor/IR_script/IR_Collect/src/MainForm.cs)
   - [SummaryExport.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/SummaryExport.cs)
   - [FactStorePersistence.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/FactStorePersistence.cs)
2. 新欄位：
   - Fact bookmarks
   - Fact tags
   - Host notes
   - Hypothesis list
   - Review status: `Open / Reviewing / Confirmed / Rejected`
3. 匯出：
   - `review_pack.json`
   - HTML review appendix

### 驗收標準

1. 分析師可對單一 fact 加 bookmark / tag。
2. Hypothesis 可關聯多個 facts / hosts。
3. 匯出能帶走 analyst workflow，不破壞原證據。

---

## Phase 4: Lateral Movement 套件深化

### 目標

把現有 Event Log 結構化 facts，再補強成更完整的 RDP / SMB / 認證濫用調查能力。

### 範圍

1. 擴充 logon / share / session / credential 事件。
2. 補 host artifacts 關聯。
3. 補時間窗與跨主機敘事能力。

### 主要工作

1. 擴充 [EventLogNormalizer.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/Normalizers/EventLogNormalizer.cs)
2. 優先事件：
   - `4624 / 4625 / 4634 / 4647 / 4648 / 4672 / 4768 / 4769 / 4776 / 4778 / 4779`
   - `5140 / 5142 / 5143 / 5144 / 5145`
   - `1149`
   - 既有 `7045 / 4698 / 4702 / 4104` 維持
3. 補強實體：
   - `TargetUser`
   - `SubjectUser`
   - `TargetHost`
   - `SourceHost`
   - `RemoteIP`
   - `RemotePort`
   - `ShareName`
   - `ShareLocalPath`
   - `LogonType`
   - `AuthenticationPackage`
   - `LogonProcess`
4. 補 correlation helpers：
   - `possible_rdp_sequence`
   - `possible_smb_lateral_sequence`
   - `privileged_logon_chain`
   - 以上只作 facts aggregation，不輸出工具結論

### 驗收標準

1. 多主機 graph / pivot 可用 `RemoteIP / ShareName / TargetUser / SourceHost` 當 seed。
2. Timeline 可更容易看出登入、session、share access、服務建立、排程建立前後序。
3. 仍維持 facts-only，不新增 heuristic verdict。

---

## Phase 5: Evidence Provenance 深化

### 目標

把 provenance 從「有欄位」提升到「分析師可直接使用」。

### 範圍

1. UI 顯示強化。
2. Export schema 強化。
3. Provenance summary。

### 主要工作

1. 在 [MainForm.cs](/D:/cursor/IR_script/IR_Collect/src/MainForm.cs) 的 Facts / Summary / HTML 報表中，清楚顯示：
   - 來源 artifact
   - parse level
   - fallback
   - collection privilege
   - collection status
2. 擴充 [FactProvenanceHelper.cs](/D:/cursor/IR_script/IR_Collect/src/Analysis/Correlation/FactProvenanceHelper.cs)
3. 在 `summary.json` 與 `full_log_v3` 增加：
   - provenance distribution
   - fallback counts
   - parse level counts
   - collection privilege summary

### 驗收標準

1. 分析師不需打開原始 CSV，也能知道 fact 的可信背景。
2. HTML / JSON 可供外部 AI 或報告流程直接引用 provenance。

---

## Phase 6: Memory Acquisition Integration

### 目標

補足目前最大缺口，但只做「採集整合與納入案卷」，不在第一版內建完整記憶體分析。

### 範圍

1. 外部 memory tool 整合入口。
2. 採集結果納入案卷。
3. Coverage / provenance / workflow 顯示。

### 主要工作

1. 新增 Settings：
   - memory tool path
   - output mode
   - enable / disable
2. Collector 整合：
   - [Collector.cs](/D:/cursor/IR_script/IR_Collect/src/Collector.cs)
   - 新增 `src/Collectors/MemoryCollector.cs`
3. coverage 與報表同步。

### 驗收標準

1. 分析師可選擇是否收記憶體。
2. 採集結果有明確 hash、大小、時間、工具版本、錯誤訊息。
3. 不因 memory 失敗而讓整體案卷失敗。

### 限制

1. 無法保證每台主機都適合做 memory acquisition。
2. 不保證低干擾。
3. 完整 memory analysis 不在本階段。

## 5. 開工順序

### 建議順序

1. Phase 1
2. Phase 5
3. Phase 2
4. Phase 4
5. Phase 3
6. Phase 6

### 原因

1. 先把 facts 來源補強，後面的 graph 與 workflow 才有料可看。
2. provenance 先強化，才能避免 parser 擴充後反而讓可信度下降。
3. graph 和 lateral movement 依賴前面資料品質。
4. memory integration 最有價值，但風險最高，應最後獨立推進。

## 6. 每階段共通驗收

每一階段都必須完成：

1. `build.bat` 成功。
2. 新 artifact 可被匯入。
3. Facts / Timeline / Entity search / Summary / HTML / JSON 行為一致。
4. docs 同步：
   - [README.md](/D:/cursor/IR_script/IR_Collect/README.md)
   - [docs/README.md](/D:/cursor/IR_script/IR_Collect/docs/README.md)
   - [docs/ARTIFACTS.md](/D:/cursor/IR_script/IR_Collect/docs/ARTIFACTS.md)
   - [docs/SPEC.md](/D:/cursor/IR_script/IR_Collect/docs/SPEC.md)

## 7. Cursor 執行方式

### 建議一次只做一個 Phase

不要讓 Cursor 一次跨太多範圍。每次只下達：

1. 單一 phase
2. 明確檔案邊界
3. 明確驗收標準

### 建議指令模板

```md
請在 IR_Collect 專案中實作 Phase 1: Execution / Persistence 結構化解析。

限制：
1. 維持 facts-only，不可加入 heuristic/rule verdict。
2. 維持 .NET Framework / C# 5 相容。
3. 不要破壞現有 Fact Store / Timeline / Export schema。

請完成：
1. Amcache 結構化解析
2. ShimCache entry-level 解析
3. SRUM 結構化匯出
4. 接入 Fact Store / Timeline / Entity search / Export
5. 更新 README / docs/README / docs/ARTIFACTS / docs/SPEC

完成後請回報：
1. 改了哪些檔案
2. build 是否成功
3. 驗證怎麼做
4. 仍存在的限制
```

## 8. 最後結論

這份計畫可在本專案上落地，而且大部分都能實作。

但要注意：

1. 可以補強很多能力，不代表能消除 live response 的先天限制。
2. 可以補更多 evidence，不代表能保證所有現場都收得到。
3. 記憶體、雲端、外部 telemetry 整合屬高風險範圍，必須獨立控管。

正確方向不是把工具做成萬能，而是把它做成一個更強、更可採信、更適合分析師辦案的 DFIR 事實工作台。
