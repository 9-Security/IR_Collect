# End-to-end Smoke Run 檢查清單

用於驗證收集與分析流程是否正常，建議在發版前或重大變更後執行。

## 1. 手動 Smoke Run（收集 + 匯入 + 檢視）

### 1.1 執行收集

任選一種方式：

- **GUI**：執行 `9SEC_EvidW.exe` → 選「Local Collect」→ 輸入 Evidence ID → 等待收集完成。
- **CLI**：執行 `9SEC_EvidW.exe -c`（自動產生 Evidence ID）或 `9SEC_EvidW.exe -c <ID>`（例如 `-c SmokeRunTest`），等待完成。

### 1.1.1 ForensicStrict 保護流程

在隔離測試主機以 **Advanced → Settings** 選 `ForensicStrict`，保留五項 safeguard 預設值：

- 輸出位於系統碟時，GUI/CLI 必須顯示強警示與 `system_disk`。
- 第一次確認取消時，不應建立 `IR_Output_<ID>`；CLI exit code 應為 `3`。
- 第一次確認後，預設仍需第二次明確確認；第二次取消同樣不應開始收集。
- 啟用 Memory acquisition / analysis handoff 後完成 Strict 收集，外部工具不應啟動；兩份 sidecar 應為 `skipped`，`skipped_by_profile` 應列出 enabled memory 步驟，`overall_status` 應為 `partial`。
- File Check 的 **Deep Scan** 應被阻擋，不啟動 System32 掃描。
- `collection_coverage.json` 應包含 `operator_acknowledged_risks=true`、`restricted_steps`、`skipped_by_profile`、`output_target_class`；完整輸出路徑不應寫入 `output_target_class`。
- Summary、HTML、`summary_v3` 與 `full_log_v3` host 摘要應顯示相同 policy metadata。

此項會啟動實際 live collection；僅可在授權、可接受現場變更的測試環境執行。自動回歸測試另覆蓋未確認拒絕與不啟動外部 memory tool 的合成路徑。

### 1.2 驗證產出

- 輸出目錄內應產生 ZIP 檔。
- （可選）確認 ZIP 內有預期檔案（如 `system_info_full.txt`、`process_list.csv`、`*.evtx` 等），並可檢查 SHA256。

### 1.3 匯入案卷並檢視關鍵分頁

- **GUI**：File → Import（或將 ZIP 拖入），選擇剛產生的 ZIP。
- 確認主機出現在左側清單，點選該主機後檢查下列分頁是否可正常開啟、無當機或明顯錯誤：
  - **Summary**
    - `collection_coverage` 有顯示 `Overall` 與各步驟狀態。
    - 有 profile metadata 的案卷會顯示 Output target、Operator acknowledged risks、Restricted steps 與 Skipped by profile。
    - 若啟用 memory 功能，`Memory acquisition` / `Memory analysis handoff` 會同時顯示 `Coverage` 與 `Sidecar`，且文字不把外部 handoff 說成內建記憶體分析。
    - `Parser Notes` 區塊可見；若案卷內有 parser/fallback note，不只 HTML / JSON，可在 Summary 直接看到。
  - **Processes**（或對應 CSV 分頁）
  - **Event Logs**（任選一則 log 點開）
    - 若案卷含 `.evtx` 與 `*_filtered.csv`，確認 Summary 的 Event Logs coverage 沒有誤顯示 `complete`。
  - **Recent Files**（或 **Browser Artifacts**）
  - **Timeline Analysis**
    - `From / To` 可正常套用到分鐘，不會被悄悄擴大成整天。
    - 若從 Investigation Graph 使用 `Open Timeline`，確認 graph 提示列存在，且可用 `Show full timeline` 還原。

### 1.3.1 匯出驗證

- 在 **Summary** 分頁執行：
  - **Export Summary JSON**
  - **Export HTML Report**
- 檢查輸出內容：
  - `summary.json` 有 `collection_coverage`、`parser_notes`、`memory_acquisition` / `memory_analysis`（若案卷有）；coverage policy metadata 與畫面一致，且缺失 artifact count 不會出現負數。
  - HTML report 的 artifact counts 對缺失項應顯示 `(not found)`，不應出現 `-1`。
  - Summary / HTML / `summary.json` 的 parser notes 與 memory `Coverage / Sidecar` 語意一致。

### 1.4 記錄結果

- 若上述步驟皆正常，記錄測試日期、Windows build、權限、profile、輸出媒體與工具版本。
- 若有失敗，請記錄步驟與錯誤訊息以便除錯。

## 2. UAC 離線證據 Smoke Run

使用不含敏感資料的 UAC 測試 folder 或 archive；至少覆蓋 folder 與一種 TAR.GZ/TGZ，
發版矩陣再補 ZIP/TAR：

1. 先計算來源 folder tree 或 archive SHA-256，記錄來源檔案數與大小。
2. GUI 使用 **Import Case**；CLI 使用 `-analyze <folder-or-archive> <out.json>`。
3. 確認 Summary / JSON 的 `source_format`、`source_evidence_sha256`（archive）、
   `evidence_digest`、UAC metadata 與 Fact Store build 狀態合理。
4. 確認 Evidence Index 可見全部原始檔；支援來源標示 parsed/canonical，
   未支援來源維持 `indexed-raw`，不得消失或被描述為已解析。
5. 確認 analysis workspace 存在 `analysis_workspace_v1.json`，其 derived file SHA-256
   與磁碟一致；canonical CSV、cache、CLI report 不得寫入 evidence root。
6. 依 fixture 內容抽查 process、auth/audit、network、account、package、web/system log、
   executable/running-process file hash、shell history、persistence、journal/boot/login facts；
   hash facts 應維持 untimed，並可在 Entity search / Diff / Correlation / Graph 以 `Hash`、`Path`
   pivot，不得被描述成執行或惡意 verdict。
7. 對來源再次計算 hash／檔案清單，必須與匯入前一致。
8. 對同一案執行 `-diff`、兩案執行 `-correlate`，確認 case reference、provenance 與
   source digest 沒有遺失。
9. 測一個損壞、截斷或超限 archive，確認 intake 拒絕且不留下可載入的 `.partial-*` 案件。

UAC intake 是離線分析能力，不代表本 EXE 能在 Linux/macOS 主機上執行 live collection。

## 關聯說明

- 收集階段會使用 **CommandHelper** 執行 systeminfo、netstat、reg、schtasks 等指令；Smoke run 可間接驗證 CommandHelper 在實際環境中的表現（路徑含空格／特殊字元時已透過 `EscapeArgForCmd` 跳脫）。
