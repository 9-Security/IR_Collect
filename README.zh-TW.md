# 9SEC Evidence Workbench

[English](README.md) | **中文（繁體）**

**Windows 現場快蒐 + Windows/Linux/macOS 證據分析。** 單一 Windows 可攜執行檔，GUI／CLI 雙用，可直接吃 UAC 證據並共用 facts-based 關聯管線；**不是**零足跡鑑識映像平台，也**不是**內建完整的記憶體鑑識套件。

## 下載

**[最新發行版（ZIP）](https://github.com/9-Security/IR_Collect/releases/latest)** — Release 提供 ZIP 與對應的 `.zip.sha256` sidecar；請先驗證 ZIP，再解壓執行。目前 source 與 v0.25.1 候選版使用 **`9SEC_EvidW.exe`**，已發布的 v0.25.0 archive 仍保留先前的執行檔名。

**目前 GitHub 正式版：v0.25.0（2026-07-29）；目前 source 目標：v0.25.1。** 候選版強化記錄於 [`docs/CHANGELOG.md`](docs/CHANGELOG.md) 的 **Unreleased**。
請以 `-version`／`--version` 與 release notes 確認任一執行檔的實際能力。

- **執行環境：** .NET Framework 4.5+（一般 Win7 以上已具備）。
- **圖形介面：** 連點 `9SEC_EvidW.exe`。
- **CLI 收集：** `9SEC_EvidW.exe -c`（需完整日誌、原始磁區時建議**提高權限**執行）。
- 建議將**輸出寫在外接媒體**，降低對受查主機的變動。

### 離線分析與關聯（不碰 live 主機、不開 GUI）

9SEC Evidence Workbench 也能分析**任何人**已採集好的 artifact —— 指向資料夾或證據封裝，即可跑與載入 case 完全相同的 facts-only 關聯管線：

- `9SEC_EvidW.exe -analyze <資料夾或封裝> [out.json]` —— 支援 folder、ZIP、TAR、TAR.GZ/TGZ；UAC 證據會自動辨識、索引並正規化可支援來源 → `summary_v3` JSON。
- `9SEC_EvidW.exe -diff <基線> <目標> [out.json]` —— 透過正規化 facts 比較兩個資料夾或證據封裝 → `diff_v1` Added/Modified/Removed JSON。
- `9SEC_EvidW.exe -correlate <out.json> <路徑A> <路徑B> [...]` —— 跨機 shared-entity + 時間關聯 → `correlation_v1` JSON。
- `9SEC_EvidW.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <路徑...>` —— 從 seed 實體多跳展開的調查圖 → `graph_v1` JSON。
- `9SEC_EvidW.exe -version` —— 工具名稱 + 版本。

GUI 的 **Diff** 分頁會把目前選取的 target，與另一個已載入且 Fact Store ready 的 case 比較。
結果可依類別、變更型態與來源篩選，並跳回對應 Facts 或 Timeline 驗證。Added/Removed 只表示
某一側有觀察到，若兩案收集覆蓋率不同，不能據此證明存在或不存在。

Folder 與 archive intake 會將證據根目錄維持唯讀。Canonical CSV、重建 Event Log CSV、
ShellBags、Fact Store cache 與 CLI 預設報告都寫入獨立分析工作區；`analysis_workspace_v1.json`
保存每個衍生檔的 SHA-256、工具版本與來源 evidence digest。UAC 證據中預先存在的 9SEC
canonical 同名檔仍會列入 raw evidence index，但不會取代本次 parser 重新產生的結果。
分析師 workflow notes 則保存於目前使用者的 Local Application Data，不寫回證據根目錄。

正規化 Fact Store 的持久化快取為選用功能，且**預設關閉**。可在
**Advanced → Settings** 啟用，快取會寫入目前使用者的 Local Application Data。所有輸入
SHA-256 完全相符時標示 `Reused`；只有 filtered Event Log CSV 變更時標示 `Incremental`
並只重跑受影響 normalizer；其他輸入變更、metadata 不相容或快取損毀時會回退 `Full`，
原因會顯示於 Summary 與 CLI。快取不取代來源證據，且可能包含敏感的 normalized facts；
Settings 亦提供 **Clear persistent Fact Store cache**。

每份分析輸出都記錄**工具版本**與**逐檔 SHA-256 證據 manifest**（`evidence_digest`）；archive intake 另記錄 `source_evidence_sha256`。UAC 的帳號、套件清單、Apache/nginx Web 日誌、shell history、持久化設定、journal metadata／boot range、登入歷程（`last`／`lastb`／`lastlog`／`utmpdump`）、Linux auditd、Linux/macOS 系統文字日誌、process、bodyfile、auth 與 network 來源會進入 Fact Store，尚未支援解析的原始檔仍以 `indexed-raw` 顯示。Web-log intake 支援有界限的 plain/gzip Common/Combined access log 與 Apache/nginx 預設 error envelope；缺 offset 的 error time 保留 raw，client/proxy 欄位不視為可信身分。套件 intake 支援有界限的 dpkg、RPM、DNF/YUM、pacman、apk、Flatpak、Snap 與 macOS Homebrew command output；套件存在是狀態觀察，不代表惡意或近期安裝。一般系統日誌可有界限地解析 plain/gzip RFC 3164、RFC 5424 與 ISO timestamp；缺少年份或 offset 時只保留原始時間，不虛構 UTC。Audit records 依相同 `audit(epoch:serial)` 合併，不在缺少可靠 architecture mapping 時猜測 syscall 名稱；登入時間只有在來源提供可靠 numeric offset 時才會產生 UTC。

UAC `hash_executables.{md5,sha1,sha256}` 與 `hash_running_processes.{md5,sha1,sha256}` 會正規化為 `uac_file_hashes.csv` 及 untimed `UacFileHash` facts，供 IOC、Diff、跨主機 Correlation 與 Graph pivot；路徑／digest observation 本身不證明執行或惡意性。

**5 分鐘試玩** —— [`docs/sample-case/`](docs/sample-case/) 附了一個合成的雙主機案卷；導覽 [`docs/DEMO.zh-TW.md`](docs/DEMO.zh-TW.md)（[English](docs/DEMO.md)）帶你把 `-analyze`／`-diff`／`-correlate`／`-graph` 完整跑過一遍（不含真實證據、免提權）。

## 定位（事件前—中期）

最適合快速釐清：

- **哪些主機**可能受影響、應納入範圍。
- **哪個帳號、程序、檔案、遠端端點**值得往下追。
- **橫向移動**大致怎麼走、哪些關聯要優先確認。
- 哪些是**真的沒在資料裡看到**，哪些其實是**根本沒收齊**（覆蓋率與「活動不存在」分開判斷）。

*以下判斷依本 repo 文件與程式模組整理，不代替你在實案中的驗證。*

## 實戰上能帶來的幫助

- **單機現場很快帶回資料：** 單一 EXE、GUI／CLI，適合 Windows 上第一時間 **live response**。
- **跨平台證據分析：** 可匯入 Linux/macOS 的 UAC 資料夾或封裝；支援來源會進入同一套 Fact Store、Timeline、Diff、Correlation 與 Graph 流程。
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

**AI** 與 **ZIP 上傳** 各有 endpoint **allowlist**；**AI Analyze** 可選 **redaction profile**，**僅**作用於即將送出的 JSON，**不**改寫已匯出之 Summary 檔或 ZIP 內文。**Collection mode profile**（`Standard`／`TriageFast`／`ForensicStrict`）在 **Advanced → Settings**，會寫入 `collection_coverage.json`。`ForensicStrict` 會分類預定輸出位置、要求明確風險確認（預設再做第二次確認）、強烈警示系統碟輸出，並預設略過已啟用的外部記憶體採集／分析 handoff、阻擋手動 **Deep Scan**、收集後 ZIP 上傳與程式內 **AI Analyze**；限制與 profile 略過項目都會寫入 coverage 與分析匯出。此模式**仍非**零足跡承諾。詳見 `docs/SECURITY.md`、`docs/USER_MANUAL.md`。

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

原始碼與文件均維護於此 repository。調查時請使用與執行檔相同 tag 的文件；正式執行檔請自 **[Releases](https://github.com/9-Security/IR_Collect/releases/latest)** 下載。

歡迎 **Issues／討論** 回饋。
