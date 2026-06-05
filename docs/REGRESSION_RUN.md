# Automated Regression Run

Use this flow when you need a repeatable validation pass for the current
facts-only investigation pipeline before release work or after parser changes.

## Scope

The review self-tests are intended to catch regressions in high-value,
low-level behavior that is easy to break silently, including:

- Event Log normalization edge cases
- Event Log coverage parity between `.evtx` and `*_filtered.csv`
- memory acquisition coverage/status handling
- memory analysis handoff coverage/export handling
- memory-analysis output-directory safety
- Summary / HTML / `summary_v3` parser-note and artifact-count consistency
- graph-to-timeline handoff continuity
- path safety and case-loading helpers
- CLI argument handling

This does not replace the end-to-end manual smoke run in
`docs/SMOKE_RUN.md`. Use both when preparing a release.

## One-command run

From the repository root:

```cmd
run_review_regression.bat
```

For the final reasonable-endpoint gate, run:

```cmd
run_endpoint_gate.bat
```

This will:

1. build `IR_Collect_review.exe` with `INCLUDE_TESTS`
2. run `IR_Collect_review.exe -test`
3. leave the detailed result file at `%TEMP%\IR_Collect_TestResult.txt`

## Manual equivalent

```cmd
build_review.bat
IR_Collect_review.exe -test
```

## Current regression focus

The built-in self-tests currently cover:

- path traversal and relative-path safety helpers
- Event Log label normalization
- CLI unknown-argument behavior
- Event Log `1149` TargetUser fallback handling
- Event Log `5145` path-vs-share-local-path mapping
- Event Log coverage label parity rules
- memory acquisition coverage downgrade rules when the expected dump is absent
- memory analysis handoff coverage downgrade rules when the expected analysis outputs are absent
- memory analysis handoff output-dir safety
- shared / related / investigation-graph / time-window synthetic pivots
- timeline minute-precision filtering and graph-focus entity matching
- Summary tab parser-note visibility
- HTML report missing-artifact display normalization
- `summary_v3` missing-artifact count normalization
- `summary_v3` and `full_log_v3` export-schema marker stability

## When to run

Run this automated regression pass at minimum:

- after changing `EventLogNormalizer.cs`
- after changing collection coverage logic
- after changing memory acquisition orchestration
- after changing memory analysis handoff orchestration
- after changing Summary / HTML / `summary_v3` export plumbing
- after changing Investigation Graph → Timeline handoff behavior
- before release packaging/signing

If this passes, continue with the manual smoke checklist in
`docs/SMOKE_RUN.md`.
