# Sample case — "Operation Paper Trail" (synthetic)

A tiny, **hand-authored, synthetic** two-host case you can run the IR_Collect
analysis layer against without any real evidence. Every name, SID, IP, and hash
here is fictitious — this folder contains **no** collected data from any host.

Use it to see `-analyze`, `-correlate`, and `-graph` produce real output, and to
watch the Guided Hunt rules fire on a coherent intrusion story. The full
step-by-step walkthrough is in [`../DEMO.md`](../DEMO.md)
([繁體中文](../DEMO.zh-TW.md)).

## The story

A phishing email to `jdoe` on **WKSTN-07** drops and runs `invoice_update.exe`
from `AppData\Local\Temp` (parent process: `OUTLOOK.EXE`). The actor sets a Run-key
for persistence, mounts the `C$` admin share on **FILE-SRV01**, re-runs the same
binary there from `C:\ProgramData\`, and clears the Security log on both hosts.

The two hosts share one strong indicator: the SHA-1 of `invoice_update.exe`
(`a94a8fe5…`) — which is exactly what `-correlate` and `-graph` pivot on.

## Layout

```
WKSTN-07/                  patient-zero workstation
  system_info.txt          Hostname: WKSTN-07
  bam_dam.csv              BAM/DAM execution (invoice_update.exe from Temp; + a benign row)
  amcache_files.csv        Amcache file entries incl. the dropped binary's SHA-1 (+ a benign signed tool)
  autoruns_registry.csv    HKCU Run-key persistence into AppData (+ a benign HKLM entry)
  network_resources.csv    \\FILE-SRV01\C$ admin share (+ a benign mapped drive)
  EventLogs/
    Security_filtered.csv  4688 process-creation + 1102 audit-log-cleared

FILE-SRV01/                pivoted-to file server
  system_info.txt          Hostname: FILE-SRV01
  amcache_files.csv        same invoice_update.exe, same SHA-1, run from ProgramData
  shimcache_entries.csv    ShimCache execution candidate (+ a benign OS binary)
  EventLogs/
    Security_filtered.csv  4624 network logon + 1102 audit-log-cleared
```

## What fires (verified)

`-analyze WKSTN-07` → 4 Guided Hunt matches:
`GH-EXEC-SUSPATH-001` (T1204), `GH-AUTORUN-001` (T1547.001),
`GH-SMB-001` (T1021.002), `GH-LOGCLEAR-001` (T1070.001).

`-analyze FILE-SRV01` → 2 matches:
`GH-EXEC-SUSPATH-001` (T1204), `GH-LOGCLEAR-001` (T1070.001).

The deliberately-benign rows (OneDrive, 7-Zip, System32, mapped drive) do **not**
flag — the rules key on user-writable / non-standard locations, not on execution
alone.

> The self-test `GuidedHunt_demo_case_trips_expected_rules` loads this folder and
> asserts exactly these rule IDs, so the committed sample stays honest as the
> rules and normalizers evolve.
