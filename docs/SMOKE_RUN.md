# End-to-end Smoke Run 檢查清單

用於驗證收集與分析流程是否正常，建議在發版前或重大變更後執行。

## 1. 手動 Smoke Run（收集 + 匯入 + 檢視）

### 1.1 執行收集

任選一種方式：

- **GUI**：執行 `IR_Collect.exe` → 選「Local Collect」→ 輸入 Evidence ID → 等待收集完成。
- **CLI**：執行 `IR_Collect.exe -c`（自動產生 Evidence ID）或 `IR_Collect.exe -c <ID>`（例如 `-c SmokeRunTest`），等待完成。

### 1.2 驗證產出

- 輸出目錄內應產生 ZIP 檔。
- （可選）確認 ZIP 內有預期檔案（如 `system_info_full.txt`、`process_list.csv`、`*.evtx` 等），並可檢查 SHA256。

### 1.3 匯入案卷並檢視關鍵分頁

- **GUI**：File → Import（或將 ZIP 拖入），選擇剛產生的 ZIP。
- 確認主機出現在左側清單，點選該主機後檢查下列分頁是否可正常開啟、無當機或明顯錯誤：
  - **Summary**
    - `collection_coverage` 有顯示 `Overall` 與各步驟狀態。
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
  - `summary.json` 有 `collection_coverage`、`parser_notes`、`memory_acquisition` / `memory_analysis`（若案卷有），且缺失 artifact count 不會出現負數。
  - HTML report 的 artifact counts 對缺失項應顯示 `(not found)`，不應出現 `-1`。
  - Summary / HTML / `summary.json` 的 parser notes 與 memory `Coverage / Sidecar` 語意一致。

### 1.4 記錄結果

- 若上述步驟皆正常，可於 TODO 將「End-to-end smoke run」勾選或註記完成日期。
- 若有失敗，請記錄步驟與錯誤訊息以便除錯。

## 關聯說明

- 收集階段會使用 **CommandHelper** 執行 systeminfo、netstat、reg、schtasks 等指令；Smoke run 可間接驗證 CommandHelper 在實際環境中的表現（路徑含空格／特殊字元時已透過 `EscapeArgForCmd` 跳脫）。
