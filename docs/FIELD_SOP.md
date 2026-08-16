# 9SEC Evidence Workbench — Field SOP (short)

**English** | [繁體中文](FIELD_SOP.zh-TW.md)

Short on-scene playbook for responders. For full operator documentation see **[USER_MANUAL.md](USER_MANUAL.md)** (English) or **[USER_MANUAL.zh-TW.md](USER_MANUAL.zh-TW.md)** (Traditional Chinese).

## 1. Pre-flight

- Prefer running `9SEC_EvidW.exe` **elevated (Administrator)**.
- Prefer running from **removable media** and writing output to removable media.
- Confirm free disk space, especially if Memory acquisition is enabled.
- For sensitive matters, verify `config.ini` AI / Upload endpoints against policy **before** collection.
- For a lower-impact run, select `ForensicStrict` in **Advanced → Settings** and keep its five safeguards enabled. Confirm the displayed output class; `unknown` is not proof of removable or trusted media.

## 2. Quick collection

### GUI

1. Run `9SEC_EvidW.exe`
2. Click `Local Collect`
3. Enter an `Evidence ID`
4. Wait for collection to finish
5. Confirm the tool auto-loads the new ZIP

Under `ForensicStrict`, review the output class and restricted steps, then complete both confirmations.
Enabled memory acquisition/analysis is skipped by default and manual Deep Scan is blocked.

### CLI

```cmd
9SEC_EvidW.exe -c
9SEC_EvidW.exe -c Case001
```

After collection you should see:

- `<EvidenceId>.zip`
- `<EvidenceId>.zip.sha256`

## 3. Read first (Summary)

After collect or import, open **Summary** in this order:

1. `collection_coverage`
2. profile, output target, acknowledgement, restrictions, and profile skips
3. `load warnings`
4. `parser notes`
5. `memory acquisition` / `memory analysis`
6. `fact store freshness`

Rules of thumb:

- Confirm collection completeness **before** inferring activity.
- Do **not** read `missing` as “this never happened.”
- Treat `skipped_by_profile` as an explicit coverage limitation; enabled profile skips make overall coverage `partial`.
- If you see parser fallback or odd sidecars, record the uncertainty in your notes.

## 4. Single-host shortest path

1. `Summary`
2. `Timeline Analysis`
3. `Facts`
4. `Event Logs`
5. `Processes`
6. `Persistence`

## 5. Multi-host shortest path

1. Import every host
2. On Dashboard run `Find Shared Entities`
3. Focus suspicious `User`, `RemoteIP`, `Share`, `ServiceName`, `TaskName`
4. Run `Build Investigation Graph`
5. Use `Open Timeline` to validate time relationships
6. Return to `Facts` for provenance as needed

## 6. Handoff exports

Most common:

- `Summary JSON`
- `HTML Report`
- `Export full LOG JSON`

Suggestions:

- Human handoff: HTML + Summary JSON first
- Downstream automation / external tooling: full LOG JSON

## 7. When to rebuild analytics

Use `Rebuild Selected Host Event Logs / Fact Store` when:

- Importing an older bundle
- `fact_store.db` shows stale
- Event Log filtered CSVs look incomplete
- You changed `EventLogDays` or `EventLogMaxEvents`

## 8. Reading Memory features

- `memory_acquisition.json` / `memory_analysis.json` are **sidecars**, not final findings.
- Sidecar `complete` does **not** guarantee the dump or analyzer output exists.
- Treat **Summary** and `collection_coverage` **Coverage** as source of truth.

## 9. Do not (on scene)

- Do not dive into Event Logs before reading `collection_coverage`.
- Do not treat tool-emitted facts as automatic malware verdicts.
- Do not treat external memory sidecar status as definitive evidence alone.
- Do not write output to the system disk of the examined host unless you have no alternative.

## 10. Quick troubleshooting

### Empty MFT tab

- Re-run elevated as Administrator
- Check `logs/ir_collect.log`
- Check MFT coverage in Summary

### Incomplete Event Logs

- Check Event Logs coverage in Summary
- Rebuild Selected Host Event Logs
- Check `logs/ir_collect.log`

### Facts / Entity search unavailable

- Confirm Fact Store was built
- Check for stale state
- Rebuild Selected Host Fact Store

### Memory shows complete but no dump

- Trust `collection_coverage`
- Inspect `memory_acquisition.json` or `memory_analysis.json`

## 11. One-line rule

**Coverage first, timeline second, correlation third, conclusions last.**
