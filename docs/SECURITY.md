# IR_Collect 潛在安全性風險檢測報告

**文件版本**: 1.2  
**檢測日期**: 2026-03-06（v1.2：補充 v0.22.0 AI/Upload allowlist 與 AI redaction profile 說明）  
**範圍**: 專案所有功能（收集、匯入、CLI、設定、檔案/登錄處理、Fact Store、匯出、Entity Search、規則引擎等）

---

## 1. 摘要

本報告針對 IR_Collect 進行潛在安全性風險檢測，涵蓋輸入驗證、路徑遍歷、權限與特權、敏感資料處理、設定檔與 CLI、命令/URL 注入、UI 與匯出、以及鑑識完整性等面向。**多數高風險項目已有緩解（如 Zip Slip、路徑驗證、參數化 SQL、HTML 跳脫）。**  

**v1.1 已實作修正**：VirusTotal hash 僅允許 32/64 字元十六進位；MFT 磁碟代號強制單一 A–Z；設定匯出禁止寫入系統目錄；規則引擎 Regex 逾時（2 秒）防 ReDoS；README 補充 config.ini 放置建議。

---

## 2. 輸入與路徑安全

### 2.1 已緩解

| 項目 | 說明 |
|------|------|
| **Zip Slip** | `CaseManager.ExtractZipSafely` 會驗證每個解壓路徑落在 `destDir` 下，跳過 `..` 等路徑遍歷項目並記錄 Warning。 |
| **案卷路徑** | `LoadCase(zipPath)` 檢查 `File.Exists(zipPath)`；解壓目錄為 `%TEMP%\Case_*`，Artifacts 掃描時以 `Path.GetFullPath` + `StartsWith(cacheDirFull)` 確保不離開解壓根目錄。 |
| **Evidence ID (CLI)** | `Program.Main` 的 `-c [EvidenceID]` 經 `Collector.NormalizeEvidenceId` → `SanitizeFileName`，會將 `Path.GetInvalidFileNameChars()` 替換為 `_`，避免目錄/檔名注入。 |
| **CommandHelper** | `RegistryCollector` / `SystemCollector` / `UsnCollector` / `PersistenceCollector` 呼叫 `reg`、`netstat`、`fsutil`、`wmic`、`schtasks` 時，路徑與參數皆經 `EscapeArgForCmd` 處理，且參數來源為程式建構（outputDir、driveLetter、SID 等），非直接使用者輸入。 |

### 2.2 已實作與殘留建議

| 項目 | 狀態 | 說明 |
|------|------|------|
| **MFT 磁碟代號** | 已實作 | `MftDumper.NormalizeDriveLetter` 與 `RawDiskReader` 建構子強制驗證單一 A–Z，避免路徑遍歷。 |
| **設定匯入路徑** | 風險低 | `path` 來自 GUI `OpenFileDialog`，讀取後僅寫回 defaultConfigPath，路徑本身未再寫入磁碟。 |
| **設定匯出路徑** | 已實作 | `ConfigManager.Export` 經 `IsPathSafeForExport` 拒絕寫入 SystemDirectory、Windows、ProgramFiles；回傳 `false` 並由 UI 提示。 |

---

## 3. 敏感資料與設定

### 3.1 已緩解

- **config.ini**：內含 `VirusTotalApiKey`、`AiApiKey`、`UploadApiKey` 等。存放於 `AppDomain.CurrentDomain.BaseDirectory`，依部署方式決定是否僅限當前使用者寫入。
- **日誌**：`Logger` 僅寫入 `message` 與 `ex.Message`，未發現直接記錄 API Key 或密碼的程式碼。
- **SQLite**：`FactStorePersistence` 使用參數化查詢（`@id`、`@t`、`@src`、`@ek`、`@json`、`@ver`），**無 SQL 注入**。`ExecuteQuery` 中 `LIMIT` 使用 `Math.Max(1, Math.Min(maxRows, 50000))` 數值運算，未拼接字串。

### 3.2 建議

- 若未來在日誌中記錄「設定鍵名」或錯誤內容，**應避免記錄含 Key 的 value**（或對 value 做遮罩）。
- 部署說明中可提醒：**勿將 config.ini 放在共用的可寫目錄**，以降低被竄改或竊取的風險。

---

## 4. 命令與 Process 執行

### 4.1 已緩解

- **CommandHelper.Run**：透過 `cmd.exe /c chcp 65001 > nul && <fileName> <args>` 執行；`args` 由各 Collector 組裝並經 `EscapeArgForCmd` 處理。
- **LogCollector**：`wevtutil epl` 的 log 名稱與輸出路徑來自內建清單與 `Path.Combine`，非使用者字串。
- **以管理員重新啟動**：`MainFormCollection.TryRunElevated` 使用 `Application.ExecutablePath`，未使用使用者輸入。

### 4.2 已實作

| 項目 | 說明 |
|------|------|
| **VirusTotal URL** | `MainForm.IsValidVirusTotalHash` 僅接受 32（MD5）或 64（SHA256）字元十六進位，不符時顯示提示且不呼叫 `Process.Start`。 |

---

## 5. UI、匯出與 XSS

### 5.1 已緩解

- **HTML 報告**：`BuildHtmlReport` 對 Hostname、CaseID、RuleFinding、CorrelationFinding、highlights、heur、groupScores 的 **Key** 等皆使用 `EscapeHtml`（`&`、`<`、`>`、`"` 跳脫）。Rule group scores 的 **Value** 為 `int`，無 XSS 風險。
- **Entity Search**：`FactStore.GetByEntity(type, value)` 僅做 `value.Trim().ToLowerInvariant()` 後當作字典鍵查詢，**未將使用者輸入當作正則或指令**，無 ReDoS 或命令注入。

### 5.2 建議

- 若未來在 HTML 報告或其它匯出中**新增來自案卷/規則的任意字串欄位**，應一律經 `EscapeHtml`（或等效）再輸出，避免 XSS。

---

## 6. 事實層查詢與輸出

### 6.1 現狀與已實作

- **目前狀態**：執行階段已不再載入內建規則檔，也不在工具內直接對觀察資料做 heuristic / rule-based 結論。
- **查詢模式**：目前以 Fact Store、Entity search、Timeline 與 JSON/HTML 匯出為主，輸入主要來自本工具自產 CSV/XML/FactStore 資料。

### 6.2 建議

- 若未來重新引入外部規則或 AI 提示層，建議與事實層分離，並將任何規則/模型輸出明確標示為「輔助判讀」而非工具內建結論。

---

## 7. 鑑識完整性與檔案安全

### 7.1 已緩解

- **僅讀設計**：收集階段以讀取/匯出為主（登錄、事件日誌、MFT、檔案複製），不刪改原始證據。
- **輸出目錄**：收集輸出目錄與 ZIP 路徑由程式與 `evidenceId`（經 SanitizeFileName）決定；完成後可依設定刪除暫存目錄，不影響原始磁碟。
- **Temp 清理**：`CaseManager.RemoveCase` / `CleanupAll` 僅刪除位於 `Path.GetTempPath()` 下且路徑長度足夠的解壓目錄，避免誤刪系統目錄。

### 7.2 建議

- 若在**高鑑識需求**環境，可考慮：  
  - 將 config.ini 的載入路徑固定為唯讀或簽章驗證；  
  - 記錄「本次收集使用的 config」雜湊，便於事後稽核。

---

## 8. 其它注意事項

| 項目 | 說明 |
|------|------|
| **AI / 上傳 API** | **v0.22.0**：`AiEndpointAllowlist` 與 `UploadEndpointAllowlist`（**Advanced → Settings**）以 **http(s) 前綴**比對（scheme/host/port + path prefix）；**空清單預設阻擋**對應之出站 POST。ZIP **上傳**不對封包內容做 redaction，僅能允許或拒絕目的地。**AI Analyze** 對將送出之 Summary JSON 套用 `AiExportRedactionProfile`（`None`：不變；`Basic`：遮罩頂層 `host` / `case_id` 與 `collection_coverage` 內識別欄位；對 highlights / warnings / parser notes / fact 敘事與實體值 / analyst workflow 文字與 memory 側錄等多數自由文字套用 IP、Email、路徑類（含 UNC、磁碟路徑、常見 profile env token）遮罩；memory `CollectorUser` 含 `DOMAIN\user` 形式者改為 `[user_redacted]`；**Export Summary JSON** 檔案匯出不套用。`Strict`：移除敘事性樣本與多數欄位，保留彙總計數）。仍應保護 `config.ini` 與網路環境，allowlist 無法取代對受信任 endpoint 的實務控管。**Collection mode profile**：當 **Advanced → Settings** 選擇 `ForensicStrict` 時，**Local Collect** 完成後之 **ZIP 出站上傳**與 **AI Analyze** 會被工具**直接拒絕**（與 allowlist 是否已設定為獨立考量）；此模式**不**代表 zero-footprint 或完整低擾動鑑識方案。 |
| **大檔與資源** | `CaseManager` 已對 Artifacts 掃描數設上限（如 200000）、MFT 筆數由 `MftMaxEntries` 限制；USN/Activity Timeline 等已有大檔不載入邏輯。有助於降低 DoS 與記憶體耗盡風險。 |
| **依賴** | 專案盡量使用原生 API 與少數依賴；SQLite 以反射動態載入，未提供 DLL 時僅略過寫入/讀取，不影響主流程。 |

---

## 9. 結論與後續

- **高影響項目**（Zip Slip、路徑遍歷、SQL 注入、命令參數跳脫、HTML 跳脫）已在目前程式碼中處理或受限。
- **v1.1 已實作**：VirusTotal hash 驗證、MFT 磁碟代號驗證、設定匯出系統目錄拒絕、規則引擎 Regex 逾時防 ReDoS；README 補充 config.ini 放置建議。

本報告為靜態程式碼檢視結果；若部署環境或使用情境有特殊需求（如高機密環境、合規要求），建議再進行滲透測試或專案型安全審計。
