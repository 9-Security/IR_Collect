# 跨來源事實關聯 — 架構設計

**目標**：讓已正規化的 LOG／跡證以一致的實體、時間與 provenance 串接，並保留未解析來源的 raw/indexed 可見性。

**狀態註記**：Fact Store、Entity index、Timeline、Diff、shared/related entity、
time-window correlation 與 multi-hop Investigation Graph 均已實作。第 6 節的通用 JSON
規則格式只保留為歷史設計，不是現行執行路徑；目前可關閉的 Guided Hunt 是獨立 overlay，
不改寫 Fact Store，也不輸出自動 verdict。

**最後更新**: 2026-07-29

---

## 1. 現行架構簡述

- **統一事實層**：Windows artifacts 與支援的 UAC Linux/macOS canonical sources 由 normalizer 轉成 `Fact`，保留時間信心、collection/parse provenance、來源檔與 raw reference。
- **Entity index**：Path、Hash、User、RemoteIP、Service、Task、Share、AppId 等實體可跨來源與跨主機查詢。
- **調查操作**：Facts、Timeline、Case Diff、Shared/Related Entities、Time-Window Correlation 與 Investigation Graph 共用 Fact Store，而不是各自解析一份資料。
- **輸出**：`summary_v3`、`diff_v1`、`correlation_v1`、`graph_v1`、`full_log_v3` 保留工具版本與證據／provenance 脈絡。
- **Guided Hunt**：以 ATT&CK-mapped explainable overlay 消費 facts；可關閉，不回寫 facts，也不取代分析師結論。

現行核心資料流為：
`Evidence -> Normalizer -> Fact Store / Entity Index -> Timeline / Diff / Correlation / Graph / Export`。

---

## 2. 現行架構：統一事實層 + 實體索引

### 2.1 核心概念

```
┌─────────────────────────────────────────────────────────────────────────┐
│  原始資料 (Raw Artifacts)                                                │
│  process_list.csv, autoruns, MFT, EventLogs, activity_timeline, ...     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                 │ 正規化 (Normalizers)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  統一事實層 (Unified Fact Store)                                         │
│  每筆「事件」= Fact: Time, TimeKind, TimeConfidence, Source, Action,      │
│                        EntityRefs[], Details                               │
│  同一實體（路徑/Hash/User/PID）在不同來源可被串在一起                     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                 │ 實體萃取 + 索引
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  實體索引 (Entity Index)                                                 │
│  EntityKey (path/hash/user/pid) → List<FactId, Time, Source, Action>     │
│  查詢：「這個路徑在哪些 LOG 出現過？」「這 5 分鐘內所有來源發生了什麼？」   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                 │ 查詢與分析 API
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  分析工作流                                                              │
│  - Facts / Timeline / Entity search                                      │
│  - Diff / Shared / Related / Time-window correlation                     │
│  - Investigation Graph / Guided Hunt overlay / Export                    │
└─────────────────────────────────────────────────────────────────────────┘
```

已支援且可正規化來源的「可關聯資訊」會轉成**統一事實 (Fact)**，再透過**實體 (Entity)** 做串接與查詢；工具本身只保留觀察事實，後續判讀交由分析師或外部模型處理。

---

## 3. 統一事實模型 (Unified Fact)

### 3.1 Fact 結構

每一筆從任意來源產生的「可分析事件」都正規化成一條 **Fact**：

| 欄位 | 型別 | 說明 |
|------|------|------|
| **Id** | string | 唯一識別（如 `{Source}_{RowId}`） |
| **Time** | DateTime | 事件時間（盡量從原始欄位解析） |
| **TimeKind** | string | `EventTime` / `MetadataTime` / `ObservedTime` / `UnknownTime` |
| **TimeConfidence** | string | `High` / `Medium` / `Low` / `Unknown` |
| **Source** | string | 來源識別：Process, MFT, EventLog, USN, Autorun, ScheduledTask, Prefetch, RecentFiles, JumpList, RegistryActivity, … |
| **Action** | string | 動作類型：Created, Modified, Executed, Accessed, Logon, Deleted, … |
| **EntityRefs** | List\<EntityRef\> | 本筆事實涉及的實體（路徑、Hash、User、PID 等），用於跨來源串接 |
| **Details** | string / JSON | 原始摘要或關鍵欄位，供顯示與 analyst/AI 消費 |
| **RawRef** | string | 原始檔案 + 列/事件 ID，方便回溯 |

### 3.2 EntityRef（實體參考）

用於「同一實體在不同 LOG 出現」的串接：

| 型別 | 範例 | 用途 |
|------|------|------|
| **Path** | `C:\Windows\System32\cmd.exe` | 檔案路徑（可正規化：小寫、環境變數展開） |
| **Hash** | SHA256 | 同一執行檔在 process_list / MFT / Prefetch 串接 |
| **User** | `DOMAIN\user` | 登入、程序、排程的關聯 |
| **Pid** | 1234 | 程序與網路/Handle 關聯（若未來有） |
| **RegistryKey** | `HKLM\...\Run\BadEntry` | Autorun 與其他登錄來源 |
| **RemoteIP** | 192.168.1.1 | EventLog 登入 / RDP / SMB / Defender 等遠端來源關聯 |
| **ServiceName** | `BadSvc` | 服務安裝與啟動行為 |
| **TaskName** | `\BadTask` | 排程任務建立 / 更新 |
| **CommandLine** | `powershell -enc ...` | 程序建立與腳本行為 |

同一條 Fact 可帶多個 EntityRef（例如：Process 啟動 → Path + Hash + User）。

---

## 4. 各來源正規化對應 (Normalizers)

每個「LOG」由一個 **Normalizer** 負責：讀取原始產物，輸出 `List<Fact>`。

| 來源 | 原始產物 | 建議 Fact 產出 |
|------|----------|----------------|
| **Process** | process_list.csv | 每列 1 Fact：Source=Process, Action=Executed, Time=StartTime, EntityRefs=[Path, Hash(若有), User(若有)] |
| **MFT** | mft_preview.csv | 每列可 1～4 Fact（Created/Modified/Accessed/MFTModified），EntityRefs=[Path, Size 可選] |
| **EventLog** | `*.evtx` + `*_filtered.csv` | 每事件 1 Fact：Source=EventLog, Action=依 EventId / Provider 對應（如 ProcessCreated, LogonSucceeded, ServiceInstalled, ScheduledTaskCreated, DefenderEvent），EntityRefs 可含 `[User, Path, CommandLine, RemoteIP, ServiceName, TaskName, ThreatName, Computer]` |
| **Autorun** | autoruns_registry.csv | 每列 1 Fact：Source=Autorun, Action=Persist, EntityRefs=[Path from Value, RegistryKey] |
| **ScheduledTask** | scheduled_tasks.xml | 每 Task 1 Fact：Action=Scheduled, EntityRefs=[Command Path, User] |
| **Prefetch** | Prefetch/*.pf 或清單 | 每檔 1 Fact：Source=Prefetch, Action=Executed, EntityRefs=[Path 從檔名推導] |
| **RecentFiles** | recent_files.csv / filesystem_7days | 每列 1 Fact：Action=Accessed/Created/Modified, EntityRefs=[Path] |
| **JumpList** | jump_lists.csv | 每列 1 Fact：Source=JumpList, Action=Open, EntityRefs=[Path] |
| **USN** | usn_journal.csv | 每列 1 Fact：Source=USN, Action=依 Reason 正規化（Created/Deleted/Renamed/Modified…），EntityRefs=[Path 或 FileName, Reason] |
| **Activity Timeline** | activity_timeline.csv | 已是扁平化；可當成「已合併的 Fact 流」或改由上面各來源直接產 Fact，不再重複 |

**重點**：同一「實體」（例如某個執行檔路徑）在 Process、MFT、Prefetch、EventLog 都會產出 Fact，並帶上 Path/Hash 等 EntityRef，之後就能用**實體索引**把這些 Fact 串在一起。

---

## 5. 實體索引 (Entity Index)

- **目的**：快速回答「這個路徑 / Hash / User 在哪些來源、什麼時間出現過？」
- **結構**（概念上）：
  - Key：實體類型 + 正規化值（如 `Path:C:\windows\system32\cmd.exe` 或 `Hash:abc123...`）
  - Value：`List<(FactId, Time, Source, Action)>`
- **建檔時機**：在 Case 載入或「載入案件後建立關聯庫」時，對所有已正規化的 Fact 掃一遍，依 EntityRefs 寫入索引。
- **查詢**：
  - 依**實體**：給 Path/Hash/User → 回傳所有相關 Fact。
  - 依**時間窗**：給 t1～t2 → 回傳該區間所有 Fact（可再依實體過濾）。
  - **複合**：同一時間窗 + 同一 Path 的 Process Fact 與 MFT Fact → 即可做「程序啟動 + 檔案建立」關聯。

這樣讓已正規化來源能互相串接：串接鍵是**實體**（路徑、Hash、User 等），不是只有時間。

---

## 6. 通用關聯規則設計（歷史／未啟用）

本節保留早期通用 JSON rule engine 的設計脈絡。現行程式不載入此格式；若未來重新引入，
必須維持與 Fact Store 分層、標示為輔助判讀，並補齊 schema、timeout、provenance 與回歸測試。

### 6.1 規則結構建議（JSON）

```json
{
  "correlation_rules": [
    {
      "id": "mft_create_and_process_4688",
      "group": "execution",
      "severity": "high",
      "score": 60,
      "time_window_minutes": 5,
      "link_by": ["Path"],
      "conditions": [
        { "source": "MFT", "action": "Created", "field_path": "Path", "regex": "\\.exe$" },
        { "source": "EventLog", "event_id": 4688, "field": "CommandLine", "contains": "same_path_or_hash" }
      ],
      "note": "New executable created and process started in same time window (same path)"
    },
    {
      "id": "autorun_and_scheduled_task_same_path",
      "group": "persistence",
      "severity": "medium",
      "score": 40,
      "link_by": ["Path"],
      "conditions": [
        { "source": "Autorun", "field": "Value", "regex": "temp|appdata" },
        { "source": "ScheduledTask", "field": "Command", "regex": "temp|appdata" }
      ],
      "note": "Same path in autorun and scheduled task (no time window; same host)"
    }
  ]
}
```

- **time_window_minutes**：可選；有則表示「同一時間窗內」才成立。
- **link_by**：用哪類實體把多個條件串起來（如 Path、Hash、User）。若為同一實體，則從實體索引找齊各來源的 Fact，再檢查時間窗與欄位條件。
- **conditions**：多個 `{ source, action?, event_id?, field, regex/contains }`，對應到 Fact 的 Source、Action 與 Details 的欄位。

### 6.2 評估流程（概念）

1. 若規則有 **link_by**（例如 Path）：
   - 對每個在實體索引中出現過的 Path（或 Hash/User），取得所有相關 Fact。
   - 若有 **time_window_minutes**：以每個 Fact 的時間為中心，取時間窗內同實體的其他 Fact，檢查是否滿足各 condition（來源 + 動作 + 欄位匹配）。
   - 若無時間窗：同一實體下，只要各 condition 在該主機內有對應 Fact 即可（例如 autorun + scheduled task 同路徑）。
2. 若規則**沒有** link_by，僅有時間窗：
   - 以時間滑動視窗掃描所有 Fact，在窗內檢查是否同時存在滿足各 condition 的 Fact（可放寬為「同主機」或「同實體」依產品需求）。
3. 命中時產出 **CorrelationFinding**：RuleId, Severity, Score, 涉及的 FactIds / 摘要，方便在 UI 上點開看原始 LOG。

若未來啟用此設計，可在「已正規化來源進入同一事實層 + 實體索引」的基礎上，用**關聯規則**把多個來源的資訊一起做分析。

---

## 7. 實作狀態

1. [x] **Fact / EntityRef 模型與記憶體 Fact Store**
2. [x] **Entity index 與 ByEntity / ByTimeRange 查詢**
3. [x] **Windows EventLog、execution、persistence、file、identity、network normalizers**
4. [x] **UAC evidence index 與支援的 Linux/macOS canonical normalizers**
5. [x] **Facts、Timeline、Diff、Correlation、Graph 與 JSON export**
6. [x] **選用 SQLite schema v3 與預設關閉的持久化 build cache**
7. [x] **獨立 Guided Hunt overlay**
8. [ ] **通用外部 JSON rule engine**：未啟用，非目前產品邊界

---

## 8. 小結

- **統一事實層**：已支援來源經 Normalizer 轉成同一種 Fact 結構（Time, Source, Action, EntityRefs, Details），是「互相串接」的基礎。
- **實體索引**：用 Path/Hash/User 等當鍵，查「同一實體在哪些來源、什麼時間出現」，實現跨 LOG 串接與查詢。
- **外部關聯層**：若有需要，可在事實層 + 實體索引之上，由外部規則或模型做多條件、多來源、可選時間窗、可選 link_by 實體的輔助分析。

此架構讓已支援的 artifacts 能依實體、時間與 provenance 串接；未正規化來源仍保留為
raw/indexed evidence，不能宣稱已參與語意關聯。工具本身維持以觀察事實為核心。

---

## 9. 若採用 C# class + JSON 序列化存 SQLite：需考慮要點

當 Fact 以 C# class 定義、序列化成 JSON 後寫入 SQLite 時，除了「怎麼存」還要考慮**查詢效能、索引、Schema 演進與可攜性**。

### 9.1 儲存方式：整條 JSON 一欄 vs 拆欄

| 做法 | 優點 | 缺點 |
|------|------|------|
| **單一 TEXT 欄存整條 Fact JSON** | 簡單、Schema 變更時不用改表 | 依 Time / Source / Entity 查詢都要掃全表、再反序列化，資料量大時慢 |
| **常用查詢欄位拆成獨立欄位 + Details 用 JSON** | 可對 Time、Source、EntityKey 建索引，查詢快 | 寫入時要填兩邊（欄位 + JSON）；Fact 結構變更時要考慮欄位遷移 |

**建議**：至少拆出 **Id、Time、Source、EntityKey**（一個代表「主要實體」的字串，如 `Path:xxx` 或 `Hash:xxx`）做索引欄位，其餘可放 JSON 欄（Details、EntityRefs 完整結構）。這樣「依時間範圍」「依實體」查詢不用每次都解析整坨 JSON。

### 9.2 實體索引要怎麼存

- **選項 A**：不另建表，查詢時用 SQL 的 `WHERE json_extract(Details, '$.Path') = ?`（需 SQLite JSON1）或對 EntityKey 欄位查詢。若已拆出 EntityKey 欄並建索引，單表即可。
- **選項 B**：另建 **EntityIndex 表**（EntityKey, FactId, Time, Source），寫入 Fact 時同時寫入此表；依實體查詢時只查這張小表，再依 FactId 回查 Fact。適合「依實體找 Fact」很頻繁的場景。

依目前 9SEC Evidence Workbench 的規模，**單表 + 拆出 EntityKey/Time/Source 並建索引**通常就夠；真的變大再考慮 B。

### 9.3 查詢效能

- 若整條 Fact 都是 JSON：每次條件查詢都要 `SELECT *` 再反序列化過濾 → 資料量一大就慢。
- **建議**：Time、Source、EntityKey（或多個 EntityKey）用一般欄位 + 索引，只對「篩選後的少數列」再從 JSON 欄還原完整 Fact 或 Details。

### 9.4 Schema 與序列化版本

- Fact 的 C# class 日後可能加欄位、改型別（例如 EntityRefs 從 string 改為物件）。
- **考慮**：在 Fact 或表加一個 **SchemaVersion** / **Version** 欄；讀取時若版本不符可做遷移或相容讀取（例如舊 JSON 缺欄位就填預設）。
- SQLite 本身不加欄位就不會壞，但「JSON 內容的結構」要自己用版本控管。

### 9.5 依賴與可攜性

- **SQLite**：.NET 可用 `Microsoft.Data.Sqlite` 或 `System.Data.SQLite`；若要做成單一 exe 可攜，需一併帶 DLL 或考慮 NativeAOT 等打包方式。
- **JSON 序列化**：.NET Framework 內建 `DataContractJsonSerializer` 或 `JavaScriptSerializer`；.NET Core/5+ 可用 `System.Text.Json`。注意 DateTime、列舉、null 的序列化方式要一致（例如 ISO8601、Enum 用字串）。

### 9.6 並行與檔案鎖

- SQLite 同一連線不建議多執行緒同時寫；GUI 若在背景建 Fact / 寫入，建議單一「寫入佇列」或專用背景執行緒寫入，避免與 UI 讀取交錯造成鎖或忙碌。
- 讀多寫少時，SQLite 可應付；寫入頻繁時再考慮 WAL 模式或批次 INSERT。

### 9.7 小結（C# class + JSON + SQLite）

- **Schema**：建議 Time / Source / EntityKey 拆欄並建索引，其餘可放 JSON（或 Details 一欄 JSON）。
- **實體索引**：先以單表 + EntityKey 索引為主；必要時再另建 EntityIndex 表。
- **版本**：Fact 結構加 SchemaVersion，方便日後遷移與相容。
- **依賴**：選定 SQLite 套件與 JSON 序列化方式，並注意可攜部署（DLL、.NET 版本）。
- **並行**：寫入集中、避免多緒同時寫；讀多寫少時負擔較小。
