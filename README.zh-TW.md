# IR Collector (IR_Collect)

[English](README.md) | **中文（繁體）**

**Windows 現場快蒐 + 事實關聯分析底座。** 單一可攜執行檔，GUI／CLI 雙用；**不是**零足跡鑑識映像平台，也**不是**內建完整的記憶體鑑識套件。

## 下載

**[最新發行版（ZIP）](https://github.com/9-Security/IR_Collect/releases/latest)** — 僅含 **`IR_Collect.exe`**，解壓後執行。

- **執行環境：** .NET Framework 4.5+（一般 Win7 以上已具備）。
- **圖形介面：** 連點 `IR_Collect.exe`。
- **CLI 收集：** `IR_Collect.exe -c`（需完整日誌、原始磁區時建議**提高權限**執行）。
- 建議將**輸出寫在外接媒體**，降低對受查主機的變動。

## 定位（事件前—中期）

最適合快速釐清：

- **哪些主機**可能受影響、應納入範圍。
- **哪個帳號、程序、檔案、遠端端點**值得往下追。
- **橫向移動**大致怎麼走、哪些關聯要優先確認。
- 哪些是**真的沒在資料裡看到**，哪些其實是**根本沒收齊**（覆蓋率與「活動不存在」分開判斷）。

*以下判斷依本 repo 文件與程式模組整理，不代替你在實案中的驗證。*

## 實戰上能帶來的幫助

- **單機現場很快帶回資料：** 單一 EXE、GUI／CLI，適合 Windows 上第一時間 **live response**。
- **蒐證面廣：** 程序、持久化、Event Logs，以及 MFT、USN、Registry、Prefetch、Jump List、Amcache、ShimCache、SRUM 等，對**可疑執行**、**持久化**、**使用者活動**特別有用。
- **不只有 raw：** 會做 **facts 正規化**（Fact Store），可用 **時間軸**、**實體搜尋**、**調查圖**先縮小範圍，再回頭對原始跡證做驗證。
- **橫向移動與帳號濫用：** 規格與文件涵蓋 RDP、SMB、Kerberos、登入、服務／排程等，並支援**跨主機 Investigation Graph**。
- **日誌不全仍可 pivot：** Jump List、BITS、SRUM、stored credentials、Kerberos tickets 等**非日誌**跡證可與 Event Logs 並用，實務上常關鍵。
- **交接友善：** Summary JSON、HTML、完整 LOG JSON，適合交給下一線、外部平台或報告流程。

## 優點

- **Facts-only：** 不替你亂下惡意結論，降低誤判風險。
- **Raw 與 normalized 並存：** 利於快篩與事後複驗。
- **`collection_coverage`、parser notes、時間信度**實用，提醒「看不到」≠「沒發生」。
- **多主機 graph、shared entities、timeline handoff** 對 **scoping** 很有幫助。
- **Memory acquisition／analysis handoff** 放在同一案件脈絡（編排、sidecar、coverage）；**不**在工具內解析 dump 內文。

## 限制

- **本質仍是 live response：** 會寫輸出目錄、留下自身執行痕跡；**不能**取代 dead-box／完整離線鑑識流程。
- **仍相當依賴 Event Logs：** 對手清 log、未開啟、保留太短，可見度會明顯下降。
- **記憶體：** 以外部工具編排與驗證為主，**不是**內建 Volatility 級分析；fileless、in-memory implant、LSASS 深挖仍要靠你的專用流程／商業工具。
- **部分 artifact 為第一階段解析**（例如 ShellBags）：有幫助但非完整語意還原，時間語意亦有已知限制（見手冊與 SPEC）。
- **Facts-only 的代價：** 很會整理證據，但**不**代你做歸因、優先級或修復決策；分析師能力要求較高。
- **大型案件：** 匯入慢、記憶體占用、Fact Store stale 等操作成本仍在，需要流程紀律。

## 治理（v0.22+）

**AI** 與 **ZIP 上傳** 各有 endpoint **allowlist**；**AI Analyze** 可選 **redaction profile**，**僅**作用於即將送出的 JSON，**不**改寫已匯出之 Summary 檔或 ZIP 內文。**Collection mode profile**（`Standard`／`TriageFast`／`ForensicStrict`）在 **Advanced → Settings**，會寫入 `collection_coverage.json`；`ForensicStrict` 會阻擋收集後的 ZIP 上傳與程式內 **AI Analyze**，但**仍非**零足跡承諾。詳見 `docs/SECURITY.md`、`docs/USER_MANUAL.md`。

## 一句話結論

若目標是 **快速收證、建時間軸、跨來源與跨主機關聯、並把案件交接清楚**，這支工具有實戰價值。  
若目標是 **零擾動鑑識、深度記憶體分析、或自動化惡意判定**，它不是那一類工具。

**最強場景：** Windows 端點事件的**初判**、**範圍界定**、**橫向移動追查**，以及**交接前的證據整理**。

---

## 文件

GitHub 本 repo 之 **`docs/`**。**現場 SOP** 與**使用手冊**為雙語（英文 `*.md`、繁體 `*.zh-TW.md`，檔首可切換）。

| 檔案 | 說明 |
|------|------|
| [FIELD_SOP.md](docs/FIELD_SOP.md) / [FIELD_SOP.zh-TW.md](docs/FIELD_SOP.zh-TW.md) | 現場短版 SOP |
| [USER_MANUAL.md](docs/USER_MANUAL.md) / [USER_MANUAL.zh-TW.md](docs/USER_MANUAL.zh-TW.md) | 完整使用手冊 |
| [docs/README.md](docs/README.md) | 文件索引（繁體為主） |
| [docs/SPEC.md](docs/SPEC.md) | 規格、版本歷程、Roadmap |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | 變更紀錄 |

完整程式碼與建置腳本若未鏡像至此 repo，以維護者工作區為準；**執行檔**請自 **[Releases](https://github.com/9-Security/IR_Collect/releases/latest)** 下載。

歡迎 **Issues／討論** 回饋。
