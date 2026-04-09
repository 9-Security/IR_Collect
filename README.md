# IR Collector (IR_Collect)

**English** | [中文（繁體）](README.zh-TW.md)

**Windows rapid on-scene collection + facts-based correlation foundation.** One portable executable, GUI or CLI—not a silent imaging platform or a full in-memory forensics suite.

## Download

**[Latest release (ZIP)](https://github.com/9-Security/IR_Collect/releases/latest)** — contains `IR_Collect.exe` only. Extract and run.

- **Runtime:** .NET Framework 4.5 or later (typical on Windows 7+).
- **GUI:** double-click `IR_Collect.exe`.
- **CLI collection:** `IR_Collect.exe -c` (prefer an elevated prompt for full logs, raw volumes, etc.).
- Prefer collection **output on removable media** to limit change on the examined system.

## Where it fits (early–mid incident)

Best when you need fast answers to:

- **Which hosts** might be in scope or affected.
- **Which account, process, file, or remote endpoint** deserves follow-up.
- **How lateral movement** likely progressed.
- **What was truly not observed** versus **what was never collected** (coverage vs. absence of activity).

*Assessment is grounded in this repository’s documentation and modules—not a substitute for findings from your own cases.*

## Practical value

- **Fast single-host triage on Windows:** one EXE, GUI/CLI, built for first-touch live response.
- **Broad collection surface:** processes, persistence, Event Logs, MFT, USN, Registry exports, browsers, Prefetch, Jump Lists, Amcache, ShimCache, SRUM—strong for suspicious execution, persistence, and user activity.
- **Not just raw drops:** facts normalization (Fact Store) so you can narrow scope with **timeline**, **entity search**, and **graph**, then return to raw artifacts to verify.
- **Lateral movement and identity abuse:** structured work around RDP, SMB, Kerberos, logons, services/tasks, and **cross-host Investigation Graph**.
- **Pivoting when logs are thin:** Jump Lists, BITS, SRUM, stored credentials, Kerberos tickets, and related artifacts still support pivoting alongside Event Logs.
- **Handoff-friendly:** Summary JSON, HTML report, and full LOG JSON for the next analyst, external tools, or reporting workflows.

## Strengths

- **Facts-only posture:** no built-in “malware” verdicts—fewer heuristic mistakes poisoning the narrative.
- **Raw + normalized together:** quick triage today, reproducible review tomorrow.
- **`collection_coverage`, parser notes, and time confidence** help separate “we didn’t see it” from “we didn’t collect it.”
- **Multi-host graph, shared entities, and timeline handoff** support sensible scoping.
- **Memory acquisition and analysis handoff** stay in the same case narrative (orchestration, sidecars, coverage)—without parsing memory images inside the tool.

## Limits

- **Still live response:** writes an output tree and leaves its own execution traces—not a zero-footprint replacement for dead-box / offline lab workflows.
- **Event Logs remain important:** cleared, disabled, or short-retention logs still blunt many storylines.
- **Memory:** external tool orchestration and validation, not embedded Volatility-class analysis—deep fileless or in-memory work still needs your specialist stack.
- **Some artifacts are first-stage parsing** (e.g. ShellBags): useful, but not full semantic recovery; see the manual and spec for known caveats.
- **Facts-only means analyst-heavy work:** great evidence packaging, not automatic attribution, prioritization, or remediation decisions.
- **Large cases:** import time, memory use, and Fact Store freshness still require operational discipline.

## Governance (v0.22+)

Separate **AI** and **Upload** endpoint allowlists; optional **redaction profile** applies only to the JSON sent for **AI Analyze** (not to exported Summary files or ZIP contents). **Collection mode profile** (`Standard` / `TriageFast` / `ForensicStrict`) in **Advanced → Settings** is recorded in `collection_coverage.json`; `ForensicStrict` blocks post-collect ZIP upload and in-app **AI Analyze**—still **not** a zero-footprint guarantee. Details: `docs/SECURITY.md`, `docs/USER_MANUAL.md`.

## In one sentence

If you need **fast collection, timelines, cross-source and cross-host correlation, and clean handoffs**, this tool has real operational value. If you need **silent imaging, deep memory analytics, or automated malicious verdicts**, it is not that class of product.

**Sweet spot:** Windows endpoint **initial assessment, scoping, lateral movement tracing**, and **evidence packaging before handoff**.

---

## Documentation

Under **`docs/`** on GitHub. **Field SOP** and **User manual** are bilingual (English `*.md`, Traditional Chinese `*.zh-TW.md`; language links at the top of each file).

| Document | Contents |
|----------|----------|
| [docs/FIELD_SOP.md](docs/FIELD_SOP.md) / [docs/FIELD_SOP.zh-TW.md](docs/FIELD_SOP.zh-TW.md) | Short on-scene SOP |
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) / [docs/USER_MANUAL.zh-TW.md](docs/USER_MANUAL.zh-TW.md) | Full operator manual |
| [docs/README.md](docs/README.md) | Doc index (Chinese-forward) |
| [docs/SPEC.md](docs/SPEC.md) | Specification, version history, roadmap |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Changelog |

**Issues and discussions** are welcome. The full source tree may exist only in the maintainer’s checkout; the shipping binary is always on **[Releases](https://github.com/9-Security/IR_Collect/releases/latest)**.
