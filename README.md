# IR Collector (IR_Collect)

**English** | [中文（繁體）](README.zh-TW.md)

Portable Windows **live-response** evidence collection and review: one executable, GUI or CLI, facts-oriented workspace (timeline, entity search, investigation graph). **Not** a silent imaging platform or a full in-memory forensics suite.

## Download

**[Latest release (ZIP)](https://github.com/9-Security/IR_Collect/releases/latest)** — contains `IR_Collect.exe` only. Extract and run.

- **Runtime:** .NET Framework 4.5 or later (typical on Windows 7+).
- **GUI:** double-click `IR_Collect.exe`.
- **CLI collection:** `IR_Collect.exe -c` (run from an elevated prompt when you need full logs, raw volumes, etc.).

Prefer writing collection **output to removable media** to reduce footprint on the system under examination.

## What you get

- Broad **collection**: processes, persistence, Event Logs (full EVTX + filtered CSV), MFT, USN, Registry exports, browsers, Prefetch, Jump Lists, Amcache, ShimCache, SRUM, and more.
- **Normalized “facts”** alongside raw artifacts: Fact Store, timeline, entity search; exports such as HTML summary, summary JSON, full LOG JSON, and workflow sidecars.
- **Lateral movement / identity–centric log structure** (RDP, SMB, Kerberos, logons, services/tasks, etc.) for pivoting and graphing—**without** the tool labeling something “malicious” for you (facts-only design).
- **Coverage / parser transparency** fields (e.g. collection coverage, timestamps confidence, parser notes) so “we didn’t collect it” is less often confused with “it never happened.”
- **Optional memory path:** external acquisition and external analysis tools can be wired in via **Advanced → Settings**; the app does not embed a memory dumper or a full dump parser.

## What you should not expect

- **Live response tradeoffs:** it creates an output directory and its own run artifacts; not a replacement for full dead-disk workflows or strict lowest-touch lab procedure by itself.
- **Event Log dependency:** many high-sensitivity storylines assume logs exist and were retained—cleared or disabled logging hurts visibility.
- **Memory depth:** advanced fileless / in-memory stories still depend heavily on your external tools and process.
- **Governance:** there is **no built-in redaction**; optional AI/upload features need **your** policy (keys, endpoints, allowlists). Treat defaults as unsafe for sensitive environments until configured.

---

<details>
<summary><strong>Optional: longer positioning note</strong> (design-level; not validated on real cases)</summary>

**Summary:** IR_Collect fits **early–mid** incident work when you need to narrow *who / what / which file / which remote host or share / which window in time*. It is intentionally **not** a centralized SOAR/SIEM, a memory framework, or an auto-verdict engine.

**Strengths (design intent):** facts-only outputs; raw + normalized together; dual EVTX/CSV log story; regression/self-test discipline in development; graph + minute-level timeline handoff for investigation narrative.

**Limits:** export-only treatment for some artifacts (e.g. ShellBags) until parsed in-app; junior analysts still carry interpretation load; roadmap items include stricter “low impact” modes, richer non–Event-Log pivots, redaction profiles, and stronger config/upload controls.

**One line:** a **fast Windows collection and correlation base**—strong at structuring evidence and cross-source pivot; weaker at zero-footprint forensics, deep memory analytics, and automated attribution.

</details>

---

## Documentation (Traditional Chinese)

These files are in-repo on GitHub (browse under **`docs/`**):

| Document | Contents |
|----------|----------|
| [docs/FIELD_SOP.md](docs/FIELD_SOP.md) | Short on-scene SOP: collection, first-pass triage, multi-host correlation, handoff/exports, quick troubleshooting |
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) | Full operator manual (GUI / CLI / import / investigation / exports) |
| [docs/README.md](docs/README.md) | Project doc index, deeper usage notes (extends beyond this table) |
| [docs/SPEC.md](docs/SPEC.md) | Development spec, version history, roadmap; **v0.22.0 draft** candidates (low-impact mode, memory handoff, non–Event-Log pivots, ShellBags parsing, guided hunt pack, governance, case/baseline diff) |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Changelog, including recent doc additions |

**Issue reports and discussions** are welcome. Build scripts and the rest of the source tree may live only in the maintainer’s full checkout; the published binary remains on **[Releases](https://github.com/9-Security/IR_Collect/releases/latest)**.
