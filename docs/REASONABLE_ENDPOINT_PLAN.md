# 9SEC Evidence Workbench 合理終點與維運邊界

**狀態（2026-07-29）**：核心合理終點第一階段已達成。Windows live collection、
UAC Linux/macOS evidence intake、facts-only analysis、memory handoff、Case Diff、
增量 Fact Store cache、ForensicStrict 與 release regression 均已落地。本文後半保留
原工作包，並標記完成／defer 狀態，避免把歷史規劃誤讀成目前待辦。

## 1. 目的

這份文件的目的，不是再替專案無限發明新 phase，而是定義：

1. 這個專案做到什麼程度，算是合理完成。
2. 哪些能力屬於「必做收尾」。
3. 哪些能力屬於「可選深化」。
4. 哪些方向不建議在本專案內繼續擴張。

本文件應作為後續 Cursor / Codex 開發的收斂基準。

---

## 2. 合理終點定義

`9SEC Evidence Workbench` 的合理終點，不是成為 EDR、SIEM、雲端調查平台、或完整法院級鑑識套件。

它的合理終點應該是：

**一個以 Windows live collection 為核心、可分析 Windows 與 UAC Linux/macOS 證據的成熟 facts-first DFIR investigation workbench。**

也就是說，專案在合理終點時，應具備：

1. 穩定的主機 artifact 收集能力。
2. 穩定的 facts-only 正規化與匯出能力。
3. 足夠實用的多主機 pivot / graph / timeline 調查能力。
4. 明確的 evidence provenance 與 collection coverage。
5. 可選擇的 memory acquisition 與後續 handoff 能力。
6. 足夠的 regression / fixture / release hardening，讓功能可維護、可回歸驗證。

---

## 3. 專案邊界

### 本專案應持續維持的定位

1. Windows live collection 為主；Linux/macOS 僅分析已由 UAC 收集的證據，不在遠端 Unix-like 主機執行本工具收集。
2. facts-only。
3. portable。
4. 分析師優先，而不是自動判案優先。
5. 以案卷、artifact、timeline、graph、handoff 為核心。

### 本專案不應擴張成

1. EDR。
2. SIEM。
3. 自動下結論的 AI 判案平台。
4. 雲端身分 / 郵件 / proxy / DNS 的大型整合平台。
5. 內建完整記憶體鑑識平台。

### 一旦開始接近以下方向，就應視為超出合理終點

1. 持續增加 verdict / suspicious / malicious 標籤。
2. 把大量開發資源轉到 SaaS API 整合。
3. 把 UI 重心放到複雜 graph canvas，而不是調查效率。
4. 在沒有穩定 regression 基礎下，持續堆疊 parser 與 feature。

---

## 4. 目前已完成能力概況

截至 2026-07-29，專案已完成：

1. Execution / persistence artifacts 結構化解析。
2. Investigation Graph Workspace。
3. Lateral movement / identity abuse 事實層強化。
4. Analyst workflow 與 evidence provenance 的主要骨架。
5. Memory acquisition 與 external analysis handoff（orchestration、sidecar、coverage、facts-only metadata）。
6. UAC folder / ZIP / TAR / TAR.GZ/TGZ intake，以及 Linux/macOS 高價值來源的 bounded normalization。
7. Case Diff / Baseline Diff、Fact Store exact reuse 與 EventLog-only incremental rebuild。
8. ForensicStrict 輸出風險確認、restricted steps、coverage/export metadata。
9. Schema drift tests、fixture/differential validation 與 build/release/signing gate。

這代表專案已跨過「功能完全不足」階段，開始進入「收斂、強化可信度、控制邊界」階段。

---

## 5. 合理終點工作包狀態

以下保留原工作包定義，並以目前狀態標記。

---

## Work Package A: Regression / Release Hardening

**狀態：已完成第一階段。** Review build、內建 self-tests、schema drift、synthetic
sample case、parser differential validation、endpoint gate 與簽章驗證皆已有可重跑入口。

### 目標

建立足夠的 regression 基礎，讓現有能力可維護、可驗證、可發版。

### 為什麼先做

現在功能已經很多。如果沒有 fixture 與回歸驗證，後面每補一個 parser 或 memory handoff，都會提高退化風險。

### 範圍

1. Event Log normalizer fixture pack。
2. Graph / shared / related / time-window regression pack。
3. Memory acquisition sidecar / coverage regression pack。
4. summary / HTML / full_log_v3 schema 穩定性檢查。
5. build / release / signing / docs version consistency。

### 驗收標準

1. 至少有一組可重複執行的 synthetic case fixtures。
2. 關鍵匯出格式的 schema 不再任意漂移。
3. build / release 路徑可穩定重跑。
4. 修改 parser 時可快速驗證是否破壞既有行為。

### 這包做完後的價值

專案會從「能做很多事」變成「能穩定做很多事」。

---

## Work Package B: Memory Analysis Handoff

**狀態：已完成。** `memory_acquisition_v2` / `memory_analysis_v2`、preset、validation、
diagnostics、coverage reconcile、Summary/HTML/JSON/Fact Store metadata 均已實作；平台仍不解析 dump。

### 目標

把目前已收進案卷的 memory dump，變成更可交接給外部分析器的流程。

### 注意

這不是內建完整記憶體鑑識。

### 範圍

1. 記憶體分析器外部工具整合入口。
2. 可配置的 command / plugin / output path orchestration。
3. 分析 sidecar 納入案卷。
4. coverage / summary / export 區分：
   - memory acquired
   - memory analysis started
   - memory analysis complete / failed / skipped

### 驗收標準

1. dump 可交給外部工具分析。
2. 產出的 sidecar 能收進案卷。
3. 不引入 heuristic verdict。
4. 不把 memory handoff 假裝成 memory analysis 結論。

### 這包做完後的價值

補上目前最實務的能力缺口，但仍維持本專案邊界。

---

## Work Package C: Selective Memory Facts Pack

**狀態：defer／選配，未納入目前核心終點。** 現行只正規化 acquisition / handoff
metadata，不解析外部工具的 process/network/module/handle 結果。

### 目標

只把少數高價值、低爭議、可 facts-only 化的記憶體分析結果納入平台。

### 範圍

僅限外部分析結果 sidecar 的 facts 化，例如：

1. process list
2. network connections
3. loaded modules
4. handles 或少數高價值 plugin 摘要

### 不應做的事

1. 不做完整 Volatility UI。
2. 不做大量 plugin 全量內建。
3. 不做記憶體惡意判定引擎。

### 驗收標準

1. 僅有少數明確、可驗證的 memory-derived facts。
2. provenance 清楚標示來自哪個外部分析器 / plugin。
3. Facts / Timeline / Graph 仍維持 facts-only。

### 這包的定位

這是合理終點前的「選配深化」，不是必做核心收尾。

---

## Work Package D: Performance / Large-Case Scaling

**狀態：第一階段完成。** Fact Store cache 支援 exact `Reused`、filtered EventLog-only
`Incremental` 與其他變更 fail-safe `Full`；大型 view 延遲載入與多項上限已存在。
更廣泛的 source-level incremental rebuild 與額外 UI profiling 仍屬後續深化。

### 目標

讓工具在多主機、大 EVTX、大 MFT、大 dump metadata 案卷下仍可用。

### 範圍

1. 大案卷載入優化。
2. Graph / pivot 結果分頁與延遲載入。
3. Timeline / Facts 大資料集的 UI 響應優化。
4. 匯出效能與記憶體占用控制。

### 驗收標準

1. 多主機案卷下 UI 不會明顯卡死。
2. 大型匯出不會輕易 OOM。
3. 主要分析操作有可接受延遲。

### 這包的定位

若工具已進入實戰使用，這包屬於高優先；若目前主要仍在功能補齊，則可晚於 Work Package B。

---

## 6. 合理終點後的可選深化

以下項目不是合理終點所必需，只能在前述工作包完成後再評估。

### 可選深化 1：Campaign / Multi-case Analysis

1. case-to-case cluster
2. shared remote IP clusters
3. shared account / shared service / shared task campaign 視圖

### 可選深化 2：Graph Workspace 2.0

1. 更好的 seed comparison
2. cluster summaries
3. graph session persistence

### 可選深化 3：Pattern Coverage 持續補強

1. 更多 RDP / SMB / WinRM / service / task patterns
2. 更多 Windows version 差異兼容

這些都應被視為「版本深化」，不是合理終點前的必做項。

---

## 7. 不建議在本專案內硬做的方向

以下方向應明確列為 `Not Recommended In This Repo`：

1. 完整雲端調查平台。
2. 大量 SaaS API 依賴的外部證據整合。
3. 全面性自動惡意判定或 AI verdict。
4. 完整 memory forensics suite。
5. 取代 EDR 的長期 telemetry 與即時查詢。

如果真的要做，應視為新產品線，而不是這個 repo 的自然延伸。

---

## 8. 工作包完成順序

### 建議順序（收斂導向）

1. [x] Work Package A: Regression / Release Hardening
2. [x] Work Package B: Memory Analysis Handoff
3. [x] Work Package D: Performance / Large-Case Scaling（第一階段）
4. [ ] Work Package C: Selective Memory Facts Pack（defer；需有明確案件需求才評估）

### 為什麼不是先做更多功能

因為目前最需要的，不是再堆 parser，而是：

1. 確保現在已有能力可維護。
2. 把最大缺口 memory 往前補一層。
3. 避免功能越多，可信度反而下降。

---

## 9. 合理終點驗收狀態

目前第一階段已符合：

1. [x] 主要 Windows host artifacts 具備 collection coverage 與失敗可見性。
2. [x] Windows 與支援的 UAC Linux/macOS artifacts 共用 facts-only 分析管線。
3. [x] Event / persistence / execution / lateral movement / memory orchestration 具可用事實層。
4. [x] 多主機 investigation workspace、Diff、Timeline、Correlation、Graph 可用。
5. [x] exports / sidecars / provenance / coverage 有 schema 與 drift tests。
6. [x] 有 fixture-based regression pack 與 synthetic sample case。
7. [x] build / release / signing / docs 可由 gate 重跑。
8. [x] 產品邊界仍排除 EDR / SIEM / automatic verdict / full memory forensics。

---

## 10. 終點後的策略

達成第一階段合理終點後，策略不是持續新增大 phase，而是：

1. bug fix
2. parser compatibility updates
3. fixture expansion
4. small tactical improvements
5. limited performance tuning

也就是說，之後應進入：

**維運 + 小幅深化**

而不是：

**無限新功能擴張**

---

## 11. 建議結論

這個專案的最佳終點，不是「什麼都做」，而是：

**在明確邊界內，把 Windows live collection 與 Windows/UAC 跨平台證據分析的 facts-first investigation workbench 做到成熟、穩定、可信。**

如果後續需求開始要求：

1. 雲端身分調查
2. 郵件調查
3. proxy / DNS / NetFlow 大量整合
4. 即時端點監控
5. 自動化惡意判定

那應該考慮新 repo / 新產品，而不是持續拉長本專案的 phase 鏈。
