# Guided demo — analyze, correlate, and hunt on a synthetic case

*(繁體中文版：[DEMO.zh-TW.md](DEMO.zh-TW.md))*

This is a 5-minute tour of IR_Collect's **offline analysis layer** using a small,
**synthetic** two-host case shipped in [`docs/sample-case/`](sample-case/). No real
evidence, no live host, no admin rights, no collection step — just point the
analyzer at a folder of already-collected artifacts and read the output.

Everything below is **verified against the current build** — the numbers are what
the tool actually prints, not illustrations.

## 0. Get a binary

Build or download `IR_Collect.exe` (see the main [README](../README.md)). All the
commands below are read-only and need no elevation. Replace `IR_Collect.exe` with
`.\IR_Collect.exe` in PowerShell.

## 1. The case in one paragraph

A phishing email to **jdoe** on **WKSTN-07** drops `invoice_update.exe` into
`AppData\Local\Temp` and runs it (parent: `OUTLOOK.EXE`). The actor adds a Run-key
for persistence, mounts `\\FILE-SRV01\C$`, re-runs the same binary on **FILE-SRV01**
from `C:\ProgramData\`, and clears the Security log on both machines. The one hard
link between the two hosts is the binary's SHA-1: `a94a8fe5…`.

## 2. Analyze one host

```
IR_Collect.exe -analyze docs\sample-case\WKSTN-07 wkstn07.json
```

This ingests the folder read-only, builds the fact store, evaluates the Guided
Hunt pack, and writes a `summary_v3` JSON (schema:
[`schemas/summary_v3.schema.json`](schemas/summary_v3.schema.json)). The report also
carries the tool version and a SHA-256 evidence manifest of the inputs it consumed.

The `guided_hunt.rule_matches` array contains **4** ATT&CK-mapped leads:

| Rule | Severity | ATT&CK | Why it fired |
|------|----------|--------|--------------|
| `GH-EXEC-SUSPATH-001` | High | T1204 / T1036 | `invoice_update.exe` ran from `AppData\Local\Temp` (BAM + Amcache) |
| `GH-AUTORUN-001` | Medium | T1547.001 | HKCU Run-key points into `AppData\Roaming` |
| `GH-SMB-001` | High | T1021.002 | connection to the `C$` admin share on FILE-SRV01 |
| `GH-LOGCLEAR-001` | High | T1070.001 | Security **1102** — the audit log was cleared |

The benign rows in the same CSVs (OneDrive from `Program Files`, signed 7-Zip, the
`System32` autorun, the mapped team drive) do **not** flag: the rules key on
user-writable / non-standard locations and known anti-forensic events, not on
execution or network activity alone.

Analyze the server too:

```
IR_Collect.exe -analyze docs\sample-case\FILE-SRV01 filesrv01.json
```

→ **2** matches: `GH-EXEC-SUSPATH-001` (the same binary from `C:\ProgramData\`,
seen by both Amcache and ShimCache) and `GH-LOGCLEAR-001`.

## 3. Correlate the two hosts

```
IR_Collect.exe -correlate corr.json docs\sample-case\WKSTN-07 docs\sample-case\FILE-SRV01
```

This pivots shared entities (Path / Hash / User / IP / AppId by default) across
both hosts and writes a `correlation_v1` JSON. `shared_entities` holds **2** hits:

- **Hash** `a94a8fe5…` on **both** hosts (4 facts) — the dropped binary is the same
  file, even though it was staged to a different path on each host.
- **User** `jdoe` on **both** hosts (3 facts).

The shared hash is the moment the two separate triage folders become one incident.

## 4. Expand the investigation graph

Seed a multi-hop graph on that shared hash:

```
IR_Collect.exe -graph Hash a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 2 graph.json docs\sample-case\WKSTN-07 docs\sample-case\FILE-SRV01
```

→ a `graph_v1` JSON with **18 nodes / 34 edges** across **2 hosts**. Reading it
outward from the seed:

- **depth 0** — the seed `Hash a94a8fe5…`
- **depth 1** — `FileName invoice_update.exe` (both hosts), the two drop paths
  (`…\Temp\…` on WKSTN-07, `…\ProgramData\…` on FILE-SRV01), and each host's Amcache
  `ProgramId`
- **depth 2** — the full execution context on WKSTN-07, including
  `ParentPath C:\…\Office16\OUTLOOK.EXE` — the graph walks from one hash straight
  back to the phishing origin.

## 5. Where to look next

- The rule catalog and how each fires: [`../src/Analysis/GuidedHunt.cs`](../src/Analysis/GuidedHunt.cs)
- Output contracts (for court / interop): [`schemas/`](schemas/)
- The sample itself and the exact story: [`sample-case/README.md`](sample-case/README.md)

Guided Hunt matches are **explainable leads derived from facts — not verdicts.**
They point you at the records worth reading; the conclusions stay with the analyst.
