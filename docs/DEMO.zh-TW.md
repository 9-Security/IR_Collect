# 導覽示範 —— 用一個合成案卷做分析、關聯與獵捕

*(English: [DEMO.md](DEMO.md))*

這是一段約 5 分鐘的導覽，用一個小型、**完全合成**的雙主機案卷帶你走過 IR_Collect 的
**離線分析層**。案卷放在 [`docs/sample-case/`](sample-case/)，**不含任何真實證據**、
不接觸實機、不需系統管理員權限、也不需先做採集 —— 直接把分析器指向一個「已採集好
的成品資料夾」，讀輸出即可。

以下所有數字都**對當前建置版本實測過**，是工具實際印出的結果，不是示意。

## 0. 先取得執行檔

自行建置或下載 `IR_Collect.exe`（見主 [README](../README.md)）。下列指令皆為唯讀、
免提權。在 PowerShell 中請把 `IR_Collect.exe` 換成 `.\IR_Collect.exe`。

## 1. 一段話說完這個案子

一封釣魚信寄給 **WKSTN-07** 上的 **jdoe**，把 `invoice_update.exe` 丟到
`AppData\Local\Temp` 並執行（父行程為 `OUTLOOK.EXE`）。攻擊者加了一個 Run 機碼做
持久化、掛載 `\\FILE-SRV01\C$` 管理共享，在 **FILE-SRV01** 上從 `C:\ProgramData\`
再次執行同一支檔案，最後在兩台機器上都清掉了 Security 日誌。兩台主機之間唯一的硬性
關聯，就是那支檔案的 SHA-1：`a94a8fe5…`。

## 2. 分析單一主機

```
IR_Collect.exe -analyze docs\sample-case\WKSTN-07 wkstn07.json
```

它會唯讀地讀入資料夾、建立 fact store、跑 Guided Hunt 規則，並寫出一份 `summary_v3`
JSON（schema 見 [`schemas/summary_v3.schema.json`](schemas/summary_v3.schema.json)）。
報告同時帶上工具版本，以及對所消費輸入檔的 SHA-256 證據 manifest。

`guided_hunt.rule_matches` 陣列含 **4** 條對應 ATT&CK 的線索：

| 規則 | 嚴重度 | ATT&CK | 觸發原因 |
|------|--------|--------|----------|
| `GH-EXEC-SUSPATH-001` | High | T1204 / T1036 | `invoice_update.exe` 從 `AppData\Local\Temp` 執行（BAM + Amcache） |
| `GH-AUTORUN-001` | Medium | T1547.001 | HKCU Run 機碼指向 `AppData\Roaming` |
| `GH-SMB-001` | High | T1021.002 | 連上 FILE-SRV01 的 `C$` 管理共享 |
| `GH-LOGCLEAR-001` | High | T1070.001 | Security **1102** —— 稽核日誌被清除 |

同一批 CSV 裡刻意放的正常列（`Program Files` 的 OneDrive、已簽章的 7-Zip、`System32`
的 autorun、映射的團隊磁碟）都**不會**誤觸：規則看的是使用者可寫／非標準位置與已知
反鑑識事件，而不是「只要有執行或連線就報」。

也分析一下伺服器：

```
IR_Collect.exe -analyze docs\sample-case\FILE-SRV01 filesrv01.json
```

→ **2** 條：`GH-EXEC-SUSPATH-001`（同一支檔案從 `C:\ProgramData\` 執行，Amcache 與
ShimCache 都看得到）與 `GH-LOGCLEAR-001`。

## 3. 關聯兩台主機

```
IR_Collect.exe -correlate corr.json docs\sample-case\WKSTN-07 docs\sample-case\FILE-SRV01
```

它會跨兩台主機比對共享實體（預設 Path／Hash／User／IP／AppId），寫出 `correlation_v1`
JSON。`shared_entities` 有 **2** 個命中：

- **Hash** `a94a8fe5…` 出現在**兩台**主機（4 筆 facts）—— 即使落地路徑不同，落地的是
  同一支檔案。
- **User** `jdoe` 出現在**兩台**主機（3 筆 facts）。

這個共享 hash，就是兩個原本各自獨立的 triage 資料夾合併成「同一起事件」的關鍵瞬間。

## 4. 展開調查圖

以那個共享 hash 為種子，展開多跳圖：

```
IR_Collect.exe -graph Hash a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 2 graph.json docs\sample-case\WKSTN-07 docs\sample-case\FILE-SRV01
```

→ 一份 `graph_v1` JSON，橫跨 **2 台主機**共 **18 個節點／34 條邊**。從種子往外讀：

- **depth 0** —— 種子 `Hash a94a8fe5…`
- **depth 1** —— `FileName invoice_update.exe`（兩台主機）、兩條落地路徑
  （WKSTN-07 的 `…\Temp\…`、FILE-SRV01 的 `…\ProgramData\…`），以及各主機的 Amcache
  `ProgramId`
- **depth 2** —— WKSTN-07 上完整的執行脈絡，包含
  `ParentPath C:\…\Office16\OUTLOOK.EXE` —— 這張圖從一個 hash 一路走回釣魚源頭。

## 5. 接下來看哪裡

- 規則清單與各自的觸發條件：[`../src/Analysis/GuidedHunt.cs`](../src/Analysis/GuidedHunt.cs)
- 輸出契約（可呈堂／互通）：[`schemas/`](schemas/)
- 範例本身與完整故事：[`sample-case/README.md`](sample-case/README.md)

Guided Hunt 的命中是**由 facts 推導、可解釋的線索 —— 不是判決**。它只是把值得細讀的
記錄指給你看；結論仍由分析師下。
