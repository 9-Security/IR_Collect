# 9SEC Evidence Workbench — User manual

**English** | [繁體中文](USER_MANUAL.zh-TW.md)

This manual is for operators and incident analysts. It explains **how** to collect, import, review, and export with the tool—not build or release engineering. For a short field playbook see **[FIELD_SOP.md](FIELD_SOP.md)** (English) or **[FIELD_SOP.zh-TW.md](FIELD_SOP.zh-TW.md)** (Traditional Chinese). Specification and version history: `SPEC.md`. Changes: `CHANGELOG.md`. Doc index: `README.md`. This manual is aligned with `v0.25.2`. When reading another tag or binary, use its `-version`, release notes, and same-tag documents.

## 1. What the tool is

`9SEC Evidence Workbench` is a portable Windows incident-response and evidence-analysis tool that supports:

- Windows on-host evidence collection
- Import of Windows case bundles and UAC Linux/macOS folders or archives
- GUI and CLI operation
- Multi-host case management
- Fact Store, entity search, timeline, and Investigation Graph analysis
- Summary JSON, full LOG JSON, and HTML report export
- Optional external memory acquisition and external memory analysis handoff

Its Local Collect path is **live response**. Folder/archive analysis is offline and keeps the evidence
root read-only, but the tool is not a full disk-imaging forensics platform.

## 2. Before you start

### 2.1 Recommended environment

- Windows 7 through Windows 11
- Run **elevated (Administrator)** for richer Event Log, Registry, Prefetch, MFT, and related data.
- Prefer running from **removable media** and writing output to removable media.

### 2.2 On-scene considerations

- The tool reads system state but **writes new files** under the output directory.
- Running the executable may leave traces (e.g. Prefetch, paging).
- Writing output to the examined system disk increases on-scene change.
- In high-rigor forensic settings, consider memory capture **before** follow-on collection/analysis.

### 2.3 Sensitive configuration

`config.ini` may contain:

- `VirusTotalApiKey`
- `AiApiKey`
- `UploadApiKey`
- Upload / AI endpoints
- `AiEndpointAllowlist` / `UploadEndpointAllowlist` (pipe-separated URL prefixes; empty list blocks outbound for that path)
- `CollectionModeProfile` (`Standard` / `TriageFast` / `ForensicStrict`; controlled in **Advanced → Settings** alongside other options—do not rely on undocumented `config.ini`-only toggles)
- `AiExportRedactionProfile` (`None` / `Basic` / `Strict`; affects **AI Analyze** POST body only)
- Event Log window and limits
- Whether temp output is deleted after ZIP

Recommendations:

- Keep `config.ini` in a location readable/writable only by the current operator.
- Do not place `config.ini` in a world-writable shared folder.
- Do not point AI / Upload endpoints at untrusted services.
- Configure **Advanced → Settings** allowlists: each outbound channel (AI vs Upload) must list allowed `http(s)://host:port/path-prefix` entries. An **empty** allowlist **blocks** POSTs for that channel until you add at least one prefix that matches your configured endpoint.
- **AI Analyze** applies the selected **redaction profile** to the JSON being posted. **Export Summary JSON** and **ZIP upload** are not rewritten by the profile (upload is allow/deny only).
- **Collection mode profile** is recorded in `collection_coverage.json` and analyst exports (`summary.json`, `full_log_v3` host summaries, Summary/HTML/parser notes when present). **TriageFast** is mainly labeling plus an informational pre-collect reminder. **ForensicStrict** classifies the planned output target, strongly warns for system-disk output, requires explicit risk acknowledgement and, by default, a second confirmation. It skips enabled external memory acquisition/analysis handoff by default and blocks manual **Deep Scan**, **AI Analyze**, and automatic **ZIP upload**. Restrictions and profile skips remain visible in coverage and exports. It does **not** claim zero-footprint, forensic disk imaging, or a complete low-touch forensic program by itself.

## 3. Five-minute quick start

### 3.1 GUI

1. Run `9SEC_EvidW.exe`
2. Accept UAC; prefer **Run as administrator**
3. On the Dashboard click `Local Collect`
4. Enter an `Evidence ID`
5. Wait for collection to finish
6. The tool auto-loads the new ZIP
7. Open `Summary` first
8. Then `Timeline Analysis`, `Facts`, `Event Logs`
9. For handoff export `Summary JSON`, `HTML`, or `Export full LOG JSON`

### 3.2 CLI

```cmd
9SEC_EvidW.exe -c
9SEC_EvidW.exe -c Case001
9SEC_EvidW.exe --help
```

Notes:

- `-c` with no argument auto-generates an Evidence ID
- `-c <ID>` uses your ID
- Under `ForensicStrict`, enter `YES` at the risk prompt and, by default, `FORENSIC-STRICT` at the second prompt. Any rejection exits with code `3` before the collector creates its output directory.
- After collection you get a ZIP and matching `.sha256`

## 4. GUI tour

### 4.1 Main window

- Left **Hosts List**: loaded hosts / cases
- Right: host-specific tabs

With no case loaded, the right side is mostly Dashboard and entry points.

### 4.2 Local Collect

Use for:

- Collection on the current machine
- On-scene first response

Steps:

1. Click `Local Collect`
2. Enter `Evidence ID`
3. Wait for collection and packaging
4. The tool imports the new ZIP automatically

Typical outputs:

- `<EvidenceId>.zip`
- `<EvidenceId>.zip.sha256`
- If `DeleteOutputDirAfterZip=1`, intermediate output may be deleted

### 4.3 Import Case

Use to:

- Import a previously collected ZIP
- Import an extracted case folder
- Import multiple hosts for cross-host review

After import (defaults):

- Case extracted to a temp area
- Fact Store built automatically
- Host appears in Hosts List

If `Auto Build Fact Store when case is loaded` is off, Fact Store is not built automatically.

For UAC evidence, supported executable and running-process checksum lists are shown as
`uac_file_hashes.csv` and `UacFileHash` facts. Treat these as untimed path/digest observations:
they support IOC and cross-host pivots but do not prove execution or maliciousness.

### 4.4 Dashboard highlights

Common actions:

- `Find Shared Entities`
- `Find Related Entities`
- `Build Investigation Graph`
- `Find Time-Window Entity Correlation`
- `Back To Last Shared Pivot`
- `Export full LOG JSON`

Import every host you need **before** running cross-host workflows from the Dashboard.

### 4.5 Summary

Review **Summary** first for each host, in order:

1. `collection_coverage`
2. `load warnings`
3. `parser notes`
4. `event highlights`
5. `memory acquisition` / `memory analysis`
6. `fact store freshness`
7. `analyst workflow`

You can:

- See whether collection is complete
- Find `partial`, `failed`, or `missing` steps
- See parser fallback impact
- Edit analyst workflow sidecar
- Export `Summary JSON`
- Export `HTML Report`
- Open AI analysis entry points (if configured). Before posting, the tool shows the target endpoint and redaction profile; posting is refused if the endpoint is not on the **AI allowlist**.

### 4.6 Timeline Analysis

Use to:

- Merge multiple sources into one timeline
- Filter by source, time window, time type / confidence
- Export CSV / JSON

Key integrated sources include:

- Process, MFT, Event Log, USN, BAM / DAM, BITS, Amcache, ShimCache entries, SRUM network/app, Activity Timeline, **ShellBags** (when `Registry\shellbags.csv` exists)

ShellBags timeline rows use **ObservedTime** at **low** confidence when a CSV time is present: that timestamp is the **UTC last-write time of the source `ShellBags_*.reg` export file**, not the original registry key last modified time (registry exports do not embed per-key timestamps).

If opened via Investigation Graph `Open Timeline`:

- Entity and trail from the graph edge are applied
- Default focus uses **minute-level** windowing
- `Show full timeline` restores the full view

### 4.7 Facts

**Facts** are normalized observations—not tool verdicts. Use them to:

- Scan structured events on one host
- Check whether an entity appears across sources
- Inspect provenance and parser notes

Each fact may include:

- Time, Time Type / Confidence, Source, Action, Entities, Details
- CollectionStep / CollectionStatus / CollectionPrivilege
- ParseLevel / FallbackUsed / ParserNote
- SourceFile / RawRef

### 4.8 Diff

Load at least two cases and wait until both Fact Stores are ready. On the target host's **Diff** tab:

1. Select the other case as **Baseline**
2. Select `All`, `Process`, `Persistence`, `File`, `Identity`, `Network`, or `Fact`
3. Filter by `Added`, `Modified`, `Removed`, and optional source text
4. Double-click a row or use `Open Facts`; use `Open Timeline` to check timing
5. Use `Export JSON` to write a `diff_v1` report

`Added` and `Modified` navigate to the target case. `Removed` navigates to the baseline case. Each
change retains fact references and provenance from both sides where available.

Treat these as observed-state differences. A missing fact may reflect different collection coverage,
parser support, collection time, or retention—not proof that an artifact was absent.

### 4.9 Event Logs

View:

- Raw `.evtx`
- `*_filtered.csv` from collection or offline rebuild

Detail panes:

- `Description`, `Parsed fields`, `Raw XML`

If only `.evtx` exists, the tool tries to rebuild analysis CSVs on import.

### 4.10 Investigation Graph

Good for:

- Lateral movement, account abuse, shared paths/hashes/users/remote IPs, co-temporal anomalies

Common controls:

- `Expand From Selected Edge`, `Back`, `Forward`, `Reset To Original Seed`, `Pin Edge`, `Open Facts`, `Open Timeline`

Suggested flow:

1. `Find Shared Entities` for shared anchors
2. Build from suspicious entities
3. Expand stepwise with `Expand From Selected Edge`
4. Use `Open Timeline` to validate timing

### 4.11 Rebuild Selected Host Event Logs / Fact Store

Commands:

- `Rebuild Selected Host Event Logs`: rebuilds that host's `*_filtered.csv`
- `Rebuild Selected Host Fact Store (full)`: reruns every normalizer
- `Rebuild Selected Host Fact Store (changed artifacts only)`: uses the persistent cache; exact matches are reused and filtered Event Log-only changes are rebuilt incrementally

When:

- Old bundle import
- Changed `EventLogDays` / `EventLogMaxEvents`
- Summary shows stale `fact_store.db`
- You want one host refreshed without clearing all cases

Changed-artifacts-only requires **Persist Fact Store cache in Local AppData** in Settings. A changed
non-EventLog input, incompatible cache, or unreadable cache automatically falls back to a full
rebuild and shows the reason. This fallback preserves correctness; it is not a partial-success state.

### 4.12 Clear all hosts

`File -> Clear all hosts`:

- Removes all loaded hosts
- Deletes temp extraction
- Clears associated Fact Stores

This removes **all** loaded data, not just “analysis cache.”

## 5. CLI

### 5.1 Commands

```cmd
9SEC_EvidW.exe -c
9SEC_EvidW.exe -c Case001
9SEC_EvidW.exe -analyze <folder-or-archive> [out.json]
9SEC_EvidW.exe -diff <baseline> <target> [out.json]
9SEC_EvidW.exe -correlate <out.json> <pathA> <pathB> [...]
9SEC_EvidW.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <path...>
9SEC_EvidW.exe -version
9SEC_EvidW.exe --help
```

`--collect` is an alias for `-c`; `--version` is an alias for `-version`; `-h` is an alias for
`--help`.

### 5.2 Typical uses

- Quick collection after RDP to a host
- Batch invocation from another toolchain
- Collect-only on scene without immediate GUI review
- Read-only folder/archive analysis and baseline comparison without opening the GUI

For `-diff`, baseline and target may each be a folder, ZIP, TAR, TAR.GZ, or TGZ. If the output path is
omitted, the report is atomically published as `ir_diff.json` in the current directory.

Analysis commands print the Fact Store build mode (`Full`, `Incremental`, or `Reused`) and the
fallback/reuse detail. Persistent reuse occurs only when the cache option is enabled for the current
user; the default remains a full in-memory build.

For `-c` under `ForensicStrict`, the CLI prints the output target class and restricted steps before
collection. Type `YES`, then `FORENSIC-STRICT` when the second confirmation setting is enabled.
Cancellation returns exit code `3` before collection output is created.

### 5.3 Outputs

Expect at least:

- `Case001.zip`
- `Case001.zip.sha256`

Partial failures:

- Collection does not abort entirely on one submodule failure
- Read the console summary and `logs/ir_collect.log`
- Later inspect `collection_coverage` in GUI Summary

## 6. Outputs and files

### 6.1 Core collection artifacts

- `*.zip` case bundle
- `*.zip.sha256`
- `collection_coverage.json` (step coverage plus profile, risk acknowledgement, restrictions, profile skips, and output target class)
- `logs/ir_collect.log`

### 6.2 Common artifact filenames

- `system_info_full.txt`, `process_list.csv`, `services.csv`
- `autoruns_registry.csv`, `scheduled_tasks.xml`
- `EventLogs\*.evtx`, `EventLogs\*_filtered.csv`
- `MFT_Dump.bin`, `mft_preview.csv`, `usn_journal.csv`
- `recent_files.csv`, `filesystem_7days.csv`, `jump_lists.csv`, `file_integrity.csv`
- `Registry\ShellBags_*.reg`, `Registry\shellbags.csv` (parsed rows for UI / Fact Store; regenerated on import when `.reg` is newer)
- `bam_dam.csv`, `bits_jobs.csv`, `wmi_persistence.csv`
- `amcache_programs.csv`, `amcache_files.csv`, `shimcache.csv`, `shimcache_entries.csv`
- `srum_network_usage.csv`, `srum_app_usage.csv`

For imported UAC evidence, the analysis workspace may additionally contain:

- `uac_evidence_index.csv`; archive input also produces `uac_archive_entries.csv`
- `analysis_workspace_v1.json` (source digest, tool identity, and derived-output SHA-256 manifest)
- `uac_auth_events.csv`, `uac_audit_events.csv`, `uac_system_log_events.csv`, `uac_web_server_events.csv`
- `uac_network_connections.csv`, `uac_accounts.csv`, `uac_packages.csv`, `uac_shell_history.csv`
- `uac_persistence.csv`, `uac_journal_files.csv`, `uac_boot_sessions.csv`, `uac_login_events.csv`
- `uac_file_hashes.csv` for supported executable/running-process MD5, SHA-1, and SHA-256 lists

These are parser-derived files outside the read-only evidence root. Unsupported inputs remain visible
through `uac_evidence_index.csv` as `indexed-raw`.

### 6.3 Analysis / export artifacts

Often created **after** import or from GUI export—may not exist in the original ZIP:

- `summary.json`, full `full_log_v3` JSON export, HTML report
- `fact_store.db`, `analyst_workflow.json`, `<case>.zip.analyst.json`

### 6.4 Memory-related artifacts

If external acquisition is enabled:

- `Memory\*.raw`, `Memory\*.dmp`, `memory_acquisition.json`

If analysis handoff is enabled:

- `MemoryAnalysis\*`, `memory_analysis.json`

Remember:

- Sidecars describe orchestration/metadata
- External tool `complete` ≠ guaranteed dump/output on disk
- Trust `collection_coverage` **Coverage** for what actually landed

## 7. Reading `collection_coverage`

Per major step:

- `complete`: expected artifacts present
- `partial`: something collected but incomplete
- `failed`: step failed
- `skipped`: skipped or disabled
- `missing`: expected artifact not found

Workflow:

1. `overall_status`
2. `collection_mode_profile`, `output_target_class`, and `operator_acknowledged_risks`
3. `restricted_steps` and `skipped_by_profile`
4. Any step not `complete`
5. `artifacts_missing`, `detail`, and `logs/ir_collect.log`

**Do not** equate `missing` with “activity never occurred.”
An enabled step in `skipped_by_profile` deliberately makes overall coverage `partial`; it is not a
collector failure, but it is still an evidence-coverage limitation.

## 8. Suggested investigation flows

### 8.1 Single-host triage

1. `Local Collect` → `Summary` → `Timeline Analysis` → `Facts` → `Event Logs`
2. Export Summary JSON / HTML as needed

### 8.2 Lateral movement

1. Import all hosts
2. `Find Shared Entities`
3. Focus users, RemoteIP, share, service, task
4. `Build Investigation Graph` → `Open Timeline`
5. Export full LOG JSON for handoff

**Without key Event Logs** (for example, no Security or TerminalServices exports), pivot on non-log facts: **Entity search** / `Source` filter on **JumpList** (`jump_lists.csv` facts: Path, User, AppId, derived UNC fields), **BITS** (ShareName / Workstation / RemoteIP from job `RemoteName`), and **SRUM** (RemoteIP, AppId, Path). These are observations from artifacts only—no built-in malicious verdict.

### 8.3 Suspicious execution

1. `Processes`, `Timeline Analysis` (path/hash/user)
2. `Prefetch`, Jump Lists, Recent Files
3. Amcache, ShimCache entries
4. `MFT`, `USN` if needed

### 8.4 Persistence

1. Autoruns, Scheduled Tasks, Services
2. BAM / DAM, WMI Persistence
3. Return to `Facts` for correlation

## 9. Advanced features

### 9.1 Auto Build Fact Store

Default **on**: faster path to Facts, entity search, and full LOG JSON export.

**Off**: faster import, less correlation until you rebuild.

### 9.2 Write Fact Store to SQLite when building

Writes `fact_store.db` under each host's separate analysis workspace without modifying the evidence root. A database already present in imported evidence is retained as raw evidence and rebuilt from source artifacts before use.

Requires `System.Data.SQLite.dll` beside the EXE for SQLite writes; GUI still works without it (in-memory path only).

### 9.3 Persist Fact Store cache in Local AppData

Default **off**. When enabled, normalized facts and their input fingerprint manifest are stored under:

```text
%LOCALAPPDATA%\9SEC Evidence Workbench\FactStoreCache\
```

Build behavior:

- `Reused`: all input SHA-256 fingerprints match
- `Incremental`: only filtered Event Log CSV inputs changed
- `Full`: no cache, forced rebuild, other input changes, incompatible metadata, or unreadable cache

The cache is atomically published and its ACL is restricted to the current user on a best-effort
basis. It can contain account names, paths, command lines, network endpoints, and other normalized
evidence. Use **Clear persistent Fact Store cache** when the cache is no longer needed or before
handoff. Clearing it does not delete source evidence, analysis workspaces, or `fact_store.db`.

Current limitation: source-level partial rebuild is implemented only for filtered Event Log CSVs.
Any other changed source deliberately triggers a full rebuild.

### 9.4 ForensicStrict safeguards

All five options are visible in **Advanced → Settings** and persist through `ConfigManager`:

- Require confirmation when output is not classified as removable media
- Warn when output is on the Windows system disk
- Skip external memory acquisition and analysis handoff
- Block manual Deep Scan
- Require a second `ForensicStrict` confirmation

Output target classes are `system_disk`, `removable`, `network`, and `unknown`. A normal local
non-system fixed drive remains `unknown`; the tool does not assume it is trusted removable media.
The collector recomputes policy from the actual output path and refuses an unacknowledged strict run
before creating the output directory. These controls reduce avoidable activity but do not make live
response zero-footprint.

### 9.5 Memory acquisition

Calls **your** external acquisition tool; records timing, paths, exit codes, hashes, privilege context. **No** built-in dumper or dump parser; may need large disk.

**Settings**: use **Arguments preset** for common layouts (quoted output path only, WinPMEM-style `-o`, or fully **Custom** template). For **non-Custom** presets, `MemoryAcquireToolArgs` is **appended after** the preset core (extra switches only, or placeholders if needed). **Coverage** rows in `collection_coverage.json` reconcile disk artifacts against `memory_acquisition.json`; if they disagree, the detail includes `[Coverage]`. Before saving the sidecar, the collector may append `[Reconciled]` if the dump path had no file at finalize. Summary / HTML / `summary.json` / `full_log_v3` share one note explaining `[Coverage]` vs `[Reconciled]`. Under the default `ForensicStrict` policy, an enabled acquisition writes a `skipped` sidecar without launching the external tool and is reported in `skipped_by_profile`.

### 9.6 Memory analysis handoff

Feeds dumps to **your** external analyzer and ingests outputs. Tool **orchestrates only**—do not treat sidecar status alone as a forensic conclusion.

**Settings**: **Arguments preset** chooses the default dual-quoted `{InputPath}` + `{OutputDir}` layout or a **Custom** template. **Coverage** reconciles listed outputs against disk; sidecar may be downgraded with `[Reconciled]` if listed files are missing at finalize even though accounting claimed success. The default `ForensicStrict` policy likewise writes a `skipped` sidecar without launching the analyzer.

## 10. Troubleshooting

### 10.1 Empty MFT tab

Causes: no `MFT_Dump.bin` / `mft_preview.csv`, MFT step failed, not elevated, AV/locks blocking `$MFT`.

Try: rerun elevated, check `logs/ir_collect.log` and Summary coverage.

### 10.2 Incomplete Event Logs

Causes: `.evtx` without `*_filtered.csv`, export failure, tight `EventLogDays` / `EventLogMaxEvents`.

Try: Summary coverage/detail, `Rebuild Selected Host Event Logs`, log file.

### 10.3 Facts / entity search unavailable

Usually: Fact Store not built, stale, or incomplete host data.

Try: confirm Auto Build setting, `Rebuild Selected Host Fact Store`, Summary freshness warnings.

### 10.4 Memory sidecar “complete” but no dump

External tool reported success without real output.

Use Summary / `collection_coverage` **Coverage** (authoritative for disk); check **Sidecar** for tool-reported fields. Details may include `[Coverage]` (coverage builder) or `[Reconciled]` (pre-save disk check). Verify tool paths, elevation (`MemoryAcquireSkipIfNotElevated`), timeouts, and output-folder permissions; read `memory_acquisition.json` / `memory_analysis.json`.

### 10.5 Slow import or high memory

Large cases, first open of heavy tabs, auto Fact Store build.

Stagger tab opens; consider SQLite persistence for huge hosts.

### 10.6 ShellBags hard to read

Expected. The tool may collect `Registry\ShellBags_<SID>.reg`; use an external viewer (e.g. Eric Zimmerman ShellBags Explorer) for path/time interpretation.

## 11. Operating habits

- Prefer Administrator + removable output media.
- **Summary before** deep Event Log dives.
- Ground conclusions in `collection_coverage`.
- Document parser fallback uncertainty.
- Before multi-host work, ensure each host’s Fact Store is built and not stale.
- Handoff: Summary JSON, HTML, and full LOG JSON as appropriate.

## 12. Related documentation

- `README.md` — doc index and version summary
- `ARTIFACTS.md` — artifact inventory (full tree, if available)
- `SMOKE_RUN.md`, `REGRESSION_RUN.md`, `SECURITY.md` — full tree
- `SPEC.md` — output formats and development specification
