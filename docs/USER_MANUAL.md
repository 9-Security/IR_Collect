# IR_Collect — User manual

**English** | [繁體中文](USER_MANUAL.zh-TW.md)

This manual is for operators and incident analysts. It explains **how** to collect, import, review, and export with the tool—not build or release engineering. For a short field playbook see **[FIELD_SOP.md](FIELD_SOP.md)** (English) or **[FIELD_SOP.zh-TW.md](FIELD_SOP.zh-TW.md)** (Traditional Chinese). Specification and version history: `SPEC.md`. Changes: `CHANGELOG.md`. Doc index: `README.md`. If you use a **partial public mirror** (e.g. GitHub), treat the full `docs/` tree in the development workspace as authoritative; files not mirrored there (such as `ARTIFACTS.md`) live only in the full source tree.

## 1. What the tool is

`IR_Collect` is a Windows incident-response tool that supports:

- On-host evidence collection
- Import of existing case bundles
- GUI and CLI operation
- Multi-host case management
- Fact Store, entity search, timeline, and Investigation Graph analysis
- Summary JSON, full LOG JSON, and HTML report export
- Optional external memory acquisition and external memory analysis handoff

It is a **live-response** tool, not a full offline disk-imaging forensics platform.

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
- Event Log window and limits
- Whether temp output is deleted after ZIP

Recommendations:

- Keep `config.ini` in a location readable/writable only by the current operator.
- Do not place `config.ini` in a world-writable shared folder.
- Do not point AI / Upload endpoints at untrusted services.

## 3. Five-minute quick start

### 3.1 GUI

1. Run `IR_Collect.exe`
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
IR_Collect.exe -c
IR_Collect.exe -c Case001
IR_Collect.exe --help
```

Notes:

- `-c` with no argument auto-generates an Evidence ID
- `-c <ID>` uses your ID
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
- Open AI analysis entry points (if configured)

### 4.6 Timeline Analysis

Use to:

- Merge multiple sources into one timeline
- Filter by source, time window, time type / confidence
- Export CSV / JSON

Key integrated sources include:

- Process, MFT, Event Log, USN, BAM / DAM, BITS, Amcache, ShimCache entries, SRUM network/app, Activity Timeline

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

### 4.8 Event Logs

View:

- Raw `.evtx`
- `*_filtered.csv` from collection or offline rebuild

Detail panes:

- `Description`, `Parsed fields`, `Raw XML`

If only `.evtx` exists, the tool tries to rebuild analysis CSVs on import.

### 4.9 Investigation Graph

Good for:

- Lateral movement, account abuse, shared paths/hashes/users/remote IPs, co-temporal anomalies

Common controls:

- `Expand From Selected Edge`, `Back`, `Forward`, `Reset To Original Seed`, `Pin Edge`, `Open Facts`, `Open Timeline`

Suggested flow:

1. `Find Shared Entities` for shared anchors
2. Build from suspicious entities
3. Expand stepwise with `Expand From Selected Edge`
4. Use `Open Timeline` to validate timing

### 4.10 Rebuild Selected Host Event Logs / Fact Store

Rebuilds:

- That host’s `*_filtered.csv`
- That host’s Fact Store

When:

- Old bundle import
- Changed `EventLogDays` / `EventLogMaxEvents`
- Summary shows stale `fact_store.db`
- You want one host refreshed without clearing all cases

### 4.11 Clear all hosts

`File -> Clear all hosts`:

- Removes all loaded hosts
- Deletes temp extraction
- Clears associated Fact Stores

This removes **all** loaded data, not just “analysis cache.”

## 5. CLI

### 5.1 Commands

```cmd
IR_Collect.exe -c
IR_Collect.exe -c Case001
IR_Collect.exe --help
```

### 5.2 Typical uses

- Quick collection after RDP to a host
- Batch invocation from another toolchain
- Collect-only on scene without immediate GUI review

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
- `collection_coverage.json`
- `logs/ir_collect.log`

### 6.2 Common artifact filenames

- `system_info_full.txt`, `process_list.csv`, `services.csv`
- `autoruns_registry.csv`, `scheduled_tasks.xml`
- `EventLogs\*.evtx`, `EventLogs\*_filtered.csv`
- `MFT_Dump.bin`, `mft_preview.csv`, `usn_journal.csv`
- `recent_files.csv`, `filesystem_7days.csv`, `jump_lists.csv`, `file_integrity.csv`
- `bam_dam.csv`, `bits_jobs.csv`, `wmi_persistence.csv`
- `amcache_programs.csv`, `amcache_files.csv`, `shimcache.csv`, `shimcache_entries.csv`
- `srum_network_usage.csv`, `srum_app_usage.csv`

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
2. Any step not `complete`
3. `artifacts_missing`, `detail`, and `logs/ir_collect.log`

**Do not** equate `missing` with “activity never occurred.”

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

Writes `fact_store.db` under each host ExtractPath—useful for large cases or repeat analysis.

Requires `System.Data.SQLite.dll` beside the EXE for SQLite writes; GUI still works without it (in-memory path only).

### 9.3 Memory acquisition

Calls **your** external acquisition tool; records timing, paths, exit codes, hashes, privilege context. **No** built-in dumper or dump parser; may need large disk.

### 9.4 Memory analysis handoff

Feeds dumps to **your** external analyzer and ingests outputs. Tool **orchestrates only**—do not treat sidecar status alone as a forensic conclusion.

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

Use Summary / `collection_coverage` Coverage; verify analyzer paths; read `memory_acquisition.json` / `memory_analysis.json`.

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
