# IR Collector (IR_Collect)

[English](README.md) | **中文（繁體）**

Windows 事件回應 (IR) 證據收集與分析工具 — 單一執行檔、GUI/CLI 雙模式。

## 分析師觀點

**先講結論：** 這支 IR_Collect 比較像「**Windows live response 蒐證器 + facts-based investigation workspace**」。站在事件調查分析師角度，它對**前期到中期**調查很有價值，特別適合快速回答「**哪個帳號、哪個程序、哪個檔案、哪個遠端 IP/Share，在什麼時間窗出現過**」。但它**不是**完整的低擾動鑑識平台，也**不是**完整的記憶體分析平台。以下判斷是依 **repo 文件與實作設計**，不是拿真實案件實測。

### 對事件調查能帶來的幫助

- 很適合 **first-response triage**。單一執行檔、GUI/CLI 雙模式，現場部署成本低。
- **蒐證面夠廣。** Process、Persistence、Event Logs、MFT、USN、Registry、Browser、Prefetch、Jump Lists、Amcache、ShimCache、SRUM 都有涵蓋。
- **對時間軸重建有幫助。** 它把多來源資料正規化成 Fact Store、Timeline、Entity search，不用人工在一堆 CSV/EVTX 之間來回翻。
- **對橫向移動調查有幫助。** 它有把登入、RDP、SMB、Kerberos、Service/Task 這類事件做結構化，可跨主機 pivot。
- **對交接有幫助。** 除了 raw artifact，也能輸出 HTML、summary JSON、full LOG JSON、analyst workflow sidecar。
- **對證據可解釋性有幫助。** `collection_coverage`、`TimeConfidence`、`CollectionStatus`、`ParserNote` 這些欄位能提醒你哪些是看不到、哪些是沒收成功。

### 優點

- **facts-only 設計是優點。** 工具不直接替你下惡意結論，能減少 heuristic 誤判污染。
- **raw 與 normalized 結果並存。** 保留原始 EVTX/原始 artifact，同時提供可查詢 facts，兼顧保全與效率。
- **對事件日誌處理不錯，** 走「完整 EVTX + filtered CSV」雙輸出，對複驗與快查都友善。
- **有 coverage/freshness/parity 檢查，** 能降低分析師誤把「沒收全」當成「真的不存在」。
- **Investigation Graph、Entity search、minute-level timeline handoff** 很實用，特別適合追 lateral movement。
- **有 regression/self-test 與 endpoint gate，** 代表作者有把穩定性與輸出一致性當成正式能力。

### 缺點

- **它本質還是 live response。** 會寫輸出目錄、留下自身執行痕跡，對高鑑識嚴謹場景不是最佳解。
- **記憶體能力仍偏弱。** 現在是外部採集/外部分析編排，不是內建 dump parsing，所以對 fileless、credential theft、in-memory implant 支援不完整。
- **部分高價值線索仍重度依賴 Event Log。** 若日誌被清除、覆寫或根本沒開，RDP/SMB/身分濫用的可視性會掉很多。
- **有些 artifact 只做到原始匯出，** 還沒做到內建解析，例如 ShellBags，分析師還要再接別的工具。
- **沒有內建 guided analytics。** 對資深分析師是好事，對 junior 或大量案件則代表人工判讀負擔高。
- **Privacy redaction 沒做，** 加上有 AI/Upload endpoint，若部署治理不好，敏感資料外送風險不小。
- **它更像端點調查工具，不是完整集中式 IR 平台；** 這點是依目前設計所做的推論。

### 可以怎麼改進

- 增加 **Forensic Strict 或 Low Impact 模式**：強制輸出到外接媒體、記錄工具自產痕跡、預設關閉高擾動步驟。
- **把記憶體 handoff 做成一等公民**：提供標準化外部工具 preset、輸出驗證、常見 Volatility 結果回填 Fact Store。
- **補強非 Event Log 的 lateral movement/identity artifact，** 降低單一依賴。
- **內建 ShellBags 解析**與更多 execution/persistence normalizer，減少分析師切工具。
- 在 facts-only 之上加一層**可關閉的 hunt pack**：ATT&CK 對映、可解釋規則、假設模板，但要和原始 facts 分層。
- **補上 redaction profile、endpoint allowlist、config 簽章/唯讀保護，** 避免 AI/Upload 成為資料外流點。
- **增加 case diff / baseline diff，** 讓分析師更快看到「這台跟正常狀態相比多了什麼」。

**一句話總結：** 這支工具很適合做 Windows 事件調查的「**快速蒐證與關聯分析底座**」，強在整理事實與跨來源 pivot，不強在低擾動鑑識、記憶體深度分析與自動判決。

## 快速參考

- **GitHub Release（僅執行檔 ZIP）**：執行 `publish_release.bat` 會呼叫 `build_release.bat`，再產出 `dist\IR_Collect_vX.Y.Z.zip`（版本取自 `docs\SPEC.md` 標頭）。若已有建置好的 `IR_Collect.exe`，可用 `publish_release.bat -SkipBuild` 只打包。若已安裝並登入 [GitHub CLI](https://cli.github.com/)（`gh auth login`），加上 `-Publish` 可建立或更新 [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) 並上傳該 zip。例：`publish_release.bat -Publish`，或 `powershell -File .\scripts\PackageRelease.ps1 -Publish -Notes "…"`。
- **編譯**：`build.bat`（本機建置）/ `build_release.bat`（一鍵正式發佈：編譯、簽章、輸出 `IR_Collect.exe`；本機自簽根未受信任時會明確顯示 `LocalSelfSignedUntrusted`，若本機無法建立自簽 code-signing 憑證則顯示 `SkippedLocalCertUnavailable`）
- **執行**：`IR_Collect.exe`（GUI）或 `IR_Collect.exe -c`（CLI 收集）
- **Regression**：`run_review_regression.bat` 會先建置 `IR_Collect_review.exe`，再執行內建 self-tests（結果檔：`%TEMP%\IR_Collect_TestResult.txt`）；`run_endpoint_gate.bat` 會串起 review regression 與正式 `build.bat`
- **Phase 1 已接線**：Execution/Persistence 結構化輸出（`amcache_programs.csv`、`amcache_files.csv`、`shimcache_entries.csv`、`srum_network_usage.csv`、`srum_app_usage.csv`）可直接進 Fact Store / Timeline / Entity search / JSON 匯出；Amcache fallback/partial parse 會以去重後的 `ParserNote` 保留於 UI 與匯出，且不依賴 fact sample 排序。
- **Phase 3（Lateral Movement & Identity Abuse，facts-only）**：Security / RDP / SMB 等高訊號事件之 Event Log 正規化加深（4624–4625、4648、4672、4768–4769、4776、5140/5145、1149、4688、4697、4698/4702、7045 等），產出可跨主機 Pivot／Investigation Graph／Timeline 的實體（如 `SubjectUser`、`TargetUser`、`RemoteIP`、`ShareName`、`ServiceName` 等）；無內建惡意判決。手動 smoke 可用 `scripts/phase3_lateral_movement_fixture.csv` 匯入測試。
- **Phase 2（Investigation Workspace）**：`Build Investigation Graph` 不再只是一次性表格，新增 workspace 導覽（`Expand From Selected Edge`、`Back`、`Forward`、`Reset To Original Seed`）、host scope（all/edge hosts/host filter）與 pinned/trail 摘要，並可從 edge 連續跳轉到對應 host 的 Facts 或 Timeline。重跑 graph 或 trail 導覽時會同步篩選／scope 快照並避免舊的 selected edge 汙染「Current edge hosts」；從 graph 開啟 Timeline 會顯示調查脈絡列並可一鍵恢復完整時間軸。
- **Memory acquisition + analysis handoff（v0.21.0）**：可於 **Advanced → Settings** 啟用並設定**外部**採集工具與**外部**分析器；採集會產出 `memory_acquisition.json` 與可選 `Memory\*.raw|*.dmp`，handoff 會再產出 `memory_analysis.json` 與 `MemoryAnalysis\*` 工具輸出。兩者都會納入 `collection_coverage.json`、Summary / HTML / `summary.json` / `full_log_v3`；**不**內建採集驅動、**不**在程式內解析記憶體映像或下 verdict。
- **Latest acceptance hardening**：`collection_coverage.json` 的 Event Logs 只有在每個 `.evtx` 都有對應 `*_filtered.csv` 時才會是 `complete`；Summary / HTML / `summary.json` 會一致顯示跨來源 parser notes 與 Memory `Coverage` / `Sidecar` 分離狀態；從 Investigation Graph 開 Timeline 會優先做 structured entity match，且沿用分鐘級時間窗。

**完整說明與文件** 請見 **[docs/](docs/)** 目錄：

| 文件 | 說明 |
|------|------|
| [docs/README.md](docs/README.md) | 使用說明、DFIR 注意、版本摘要 |
| [docs/SPEC.md](docs/SPEC.md) | 開發規格、版本歷程、產出格式、Roadmap |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | 版本變更紀錄 |
| [docs/REGRESSION_RUN.md](docs/REGRESSION_RUN.md) | 自動化 regression review build/self-test 執行方式 |

其他：ARTIFACTS.md、SMOKE_RUN.md、SECURITY.md、CORRELATION_ARCHITECTURE.md 亦在 `docs/` 下。**Cursor/Agent 規則**：`.cursor/rules/ir-collect-agents.mdc`。
