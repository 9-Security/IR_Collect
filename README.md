# IR Collector (IR_Collect)

**English** | [中文（繁體）](README.zh-TW.md)

Windows incident-response (IR) evidence collection and analysis — single portable executable, GUI and CLI.

## Analyst perspective

**Bottom line:** IR_Collect is best described as a **Windows live-response collector plus a facts-based investigation workspace**. From an incident analyst’s point of view it adds strong value in the **early-to-mid** stages of an investigation, especially when you need quick answers to **which account, which process, which file, and which remote IP or share appeared in what time window**. It is **not** a full low-footprint forensics platform and **not** a full memory-analysis platform. The following assessment is based on **repository documentation and implementation design**, not on validation against real cases.

### What it helps with in investigations

- **First-response triage:** single EXE, GUI and CLI, low cost to deploy on scene.
- **Broad collection surface:** process, persistence, Event Logs, MFT, USN, Registry, browsers, Prefetch, Jump Lists, Amcache, ShimCache, SRUM, and more.
- **Timeline reconstruction:** multiple sources are normalized into a Fact Store, Timeline, and entity search so analysts spend less time jumping between raw CSVs and EVTX.
- **Lateral-movement work:** logins, RDP, SMB, Kerberos, services/tasks, and related events are structured for cross-host pivoting.
- **Handoff:** beyond raw artifacts, outputs include HTML, summary JSON, full LOG JSON, and analyst workflow sidecars.
- **Explainability of evidence:** fields such as `collection_coverage`, `TimeConfidence`, `CollectionStatus`, and `ParserNote` surface what was not visible versus what failed to collect.

### Strengths

- **Facts-only design:** the tool does not render malware verdicts for you, which reduces contamination from heuristic false positives.
- **Raw and normalized together:** original EVTX and artifacts are retained while queryable facts improve review efficiency.
- **Solid Event Log handling:** “full EVTX + filtered CSV” dual output supports both deep re-checks and quick scans.
- **Coverage, freshness, and parity checks:** harder to mistake “we didn’t collect it” for “it doesn’t exist.”
- **Investigation Graph, entity search, and minute-level timeline handoff** are practical, especially for lateral movement.
- **Regression / self-test and endpoint gate** show stability and output consistency are treated as first-class capabilities.

### Limitations

- **Still live response:** it writes to an output directory and leaves its own execution traces; not the best fit for the strictest forensic-triage scenarios.
- **Memory capability is limited:** acquisition and analysis are **externally** orchestrated; there is no built-in dump parsing, so support for fileless activity, credential theft, and in-memory implants is incomplete.
- **Some high-value leads lean heavily on Event Logs:** if logs are cleared, rotated, or never enabled, visibility into RDP/SMB/identity abuse drops sharply.
- **Some artifacts are export-only** with no built-in parsing yet (e.g. ShellBags), so analysts still chain other tools.
- **No built-in guided analytics:** good for senior analysts; for juniors or high case volume, interpretation load stays high.
- **No privacy redaction**, plus optional AI/upload endpoints — **poor deployment governance creates meaningful sensitive-data exfiltration risk.**
- **Endpoint investigation tool, not a full centralized IR platform** — an inference from the current design.

### Possible improvements

- **Forensic Strict or Low Impact mode:** force output to removable media, log tool-generated artifacts, default-off for higher-disturbance steps.
- **First-class memory handoff:** standardized external-tool presets, output validation, and common Volatility-style results fed back into the Fact Store.
- **Strengthen lateral-movement and identity artifacts beyond Event Logs** to reduce single-source dependence.
- **Built-in ShellBags parsing** and more execution/persistence normalizers to cut tool-switching.
- **Optional, disable-able hunt layer** on top of facts-only: ATT&CK mapping, explainable rules, hypothesis templates — kept separate from raw facts.
- **Redaction profiles, endpoint allowlists, and signed/read-only config** so AI/upload paths cannot become data leaks by misconfiguration.
- **Case diff / baseline diff** so analysts quickly see what changed versus a known-good baseline.

**In one sentence:** IR_Collect is a strong **fast Windows collection and correlation base** for event investigations — strong at organizing facts and pivoting across sources; weaker at low-disturbance forensics, deep memory analysis, and automated verdicts.

## Quick reference

- **GitHub Release (EXE-only ZIP):** `publish_release.bat` runs `build_release.bat`, then writes `dist\IR_Collect_vX.Y.Z.zip` (version from `docs\SPEC.md` header). `publish_release.bat -SkipBuild` zips the current `IR_Collect.exe` only. Add `-Publish` to create or update a [GitHub Release](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) via [GitHub CLI](https://cli.github.com/) (`gh auth login` first). Example: `publish_release.bat -Publish` or `powershell -File .\scripts\PackageRelease.ps1 -Publish -Notes "…"`.
- **Build:** `build.bat` (local) / `build_release.bat` (release pipeline: compile, sign, produce `IR_Collect.exe`; shows `LocalSelfSignedUntrusted` when the local self-signed root is untrusted, `SkippedLocalCertUnavailable` when a local code-signing cert cannot be created)
- **Run:** `IR_Collect.exe` (GUI) or `IR_Collect.exe -c` (CLI collection)
- **Regression:** `run_review_regression.bat` builds `IR_Collect_review.exe` then runs built-in self-tests (output: `%TEMP%\IR_Collect_TestResult.txt`); `run_endpoint_gate.bat` chains review regression and release `build.bat`
- **Phase 1:** Execution/persistence structured outputs (`amcache_programs.csv`, `amcache_files.csv`, `shimcache_entries.csv`, `srum_network_usage.csv`, `srum_app_usage.csv`) feed Fact Store / Timeline / entity search / JSON export; Amcache fallback/partial parse surfaces deduplicated `ParserNote` in UI and exports without relying on fact sample ordering.
- **Phase 3 (Lateral movement & identity abuse, facts-only):** deeper Security / RDP / SMB Event Log normalization (4624–4625, 4648, 4672, 4768–4769, 4776, 5140/5145, 1149, 4688, 4697, 4698/4702, 7045, etc.), producing entities for cross-host pivot / Investigation Graph / Timeline (`SubjectUser`, `TargetUser`, `RemoteIP`, `ShareName`, `ServiceName`, …); no built-in malware verdicts. Manual smoke: import `scripts/phase3_lateral_movement_fixture.csv`.
- **Phase 2 (Investigation workspace):** `Build Investigation Graph` adds workspace navigation (`Expand From Selected Edge`, `Back`, `Forward`, `Reset To Original Seed`), host scope (all / edge hosts / host filter), pinned/trail summary, and edge-to-Facts/Timeline hops; reruns sync filter/scope snapshots and avoid stale selected-edge pollution of “Current edge hosts”; opening Timeline from the graph shows investigation context and one-click full timeline restore.
- **Memory acquisition + analysis handoff (v0.21.0):** enable in **Advanced → Settings** and configure **external** acquisition and **external** analyzers; acquisition yields `memory_acquisition.json` and optional `Memory\*.raw|*.dmp`, handoff yields `memory_analysis.json` and `MemoryAnalysis\*`; both roll into `collection_coverage.json`, Summary / HTML / `summary.json` / `full_log_v3`; **no** built-in acquisition drivers, **no** in-process image parsing or verdicts.
- **Latest acceptance hardening:** Event Logs in `collection_coverage.json` are `complete` only when each `.evtx` has a matching `*_filtered.csv`; Summary / HTML / `summary.json` consistently show cross-source parser notes and Memory `Coverage` / `Sidecar`; Timeline from Investigation Graph prefers structured entity match and minute-level windows.

Detailed guides in **[docs/](docs/)** are **mostly Chinese**; file names and paths are unchanged:

| Doc | Notes |
|-----|--------|
| [docs/README.md](docs/README.md) | Usage, DFIR notes, version summary |
| [docs/SPEC.md](docs/SPEC.md) | Spec, version history, output formats, roadmap |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Changelog |
| [docs/REGRESSION_RUN.md](docs/REGRESSION_RUN.md) | Regression / self-test runner |

Also under `docs/`: ARTIFACTS.md, SMOKE_RUN.md, SECURITY.md, CORRELATION_ARCHITECTURE.md. Cursor/agent rules: `.cursor/rules/ir-collect-agents.mdc`.
