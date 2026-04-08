# IR_Collect 現場 SOP

本文件是給現場應變人員的短版操作流程。若需要完整功能說明，請看 `docs/USER_MANUAL.md`。

## 1. 現場前檢查

- 優先以系統管理員執行 `IR_Collect.exe`
- 優先從外接儲存裝置執行，並讓輸出寫到外接儲存裝置
- 確認磁碟空間足夠，尤其若有啟用 Memory acquisition
- 若案件敏感，先確認 `config.ini` 內 AI / Upload endpoint 是否符合政策

## 2. 快速收集

### GUI

1. 執行 `IR_Collect.exe`
2. 按 `Local Collect`
3. 輸入 `Evidence ID`
4. 等待收集完成
5. 確認工具自動載入剛產生的 ZIP

### CLI

```cmd
IR_Collect.exe -c
IR_Collect.exe -c Case001
```

收集完成後應看到：

- `<EvidenceId>.zip`
- `<EvidenceId>.zip.sha256`

## 3. 第一時間必看

收集或匯入完成後，先看 `Summary`，順序如下：

1. `collection_coverage`
2. `load warnings`
3. `parser notes`
4. `memory acquisition / memory analysis`
5. `fact store freshness`

原則：

- 先確認收集是否完整，再開始推論
- 不要把 `missing` 解讀成「沒有這個活動」
- 看到 parser fallback 或 sidecar 異常時，要把不確定性寫進判讀

## 4. 單機調查最短路徑

1. `Summary`
2. `Timeline Analysis`
3. `Facts`
4. `Event Logs`
5. `Processes`
6. `Persistence`

## 5. 多機關聯最短路徑

1. 匯入所有主機
2. Dashboard 執行 `Find Shared Entities`
3. 聚焦可疑 `User`、`RemoteIP`、`Share`、`ServiceName`、`TaskName`
4. 執行 `Build Investigation Graph`
5. 用 `Open Timeline` 驗證時間關係
6. 必要時回到 `Facts` 看 provenance

## 6. 匯出交接

最常用的交接輸出：

- `Summary JSON`
- `HTML Report`
- `Export full LOG JSON`

建議：

- 給人工交接優先用 HTML + Summary JSON
- 給後續分析流程或外部工具優先用完整 LOG JSON

## 7. 何時重建分析資料

遇到下列情況時，使用 `Rebuild Selected Host Event Logs / Fact Store`：

- 匯入的是舊案卷
- `fact_store.db` 顯示 stale
- Event Log filtered CSV 不完整
- 調整了 `EventLogDays` 或 `EventLogMaxEvents`

## 8. Memory 功能判讀

- `memory_acquisition.json` / `memory_analysis.json` 是 sidecar，不是最終結論
- sidecar 顯示 `complete`，不代表 dump 或分析輸出一定存在
- 一律以 `Summary` 與 `collection_coverage` 的 `Coverage` 為準

## 9. 現場不要做的事

- 不要先跳進 Event Logs 細看，而忽略 `collection_coverage`
- 不要把工具輸出的 facts 直接當成惡意判決
- 不要把外部 memory 工具的 sidecar 狀態當成最終證據
- 不要把輸出寫回受調查主機的系統碟，除非沒有其他選擇

## 10. 快速排錯

### MFT 沒資料

- 重新以系統管理員執行
- 檢查 `logs/ir_collect.log`
- 檢查 Summary 的 MFT coverage

### Event Logs 不完整

- 看 Summary 的 Event Logs coverage
- 重建 Selected Host Event Logs
- 檢查 `logs/ir_collect.log`

### Facts / Entity search 不能用

- 確認 Fact Store 已建立
- 檢查是否 stale
- 重建 Selected Host Fact Store

### Memory 顯示 complete 但沒 dump

- 以 `collection_coverage` 為準
- 查 `memory_acquisition.json` 或 `memory_analysis.json`

## 11. 一句話原則

先看收集完整性，再看時間軸，再做關聯，最後才下結論。
