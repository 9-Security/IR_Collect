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
- ForensicStrict output classification, acknowledgement gate, restricted-step enforcement, and export metadata
- Summary / HTML / `summary_v3` parser-note and artifact-count consistency
- graph-to-timeline handoff continuity
- path safety and case-loading helpers
- archive staging, quotas, path containment, read-only analysis workspace, and atomic output helpers
- evidence-manifest reparse policy, source mutation rejection, and untrusted bundled Fact Store handling
- MFT run-list/fixup/name ranking plus resident `$ATTRIBUTE_LIST` extension-name recovery
- UAC detection, evidence indexing, bounded Linux/macOS derivation, normalization, and provenance
- CLI argument handling

This does not replace the end-to-end manual smoke run in
`docs/SMOKE_RUN.md`. Use both when preparing a release.

## One-command run

From the repository root:

```cmd
run_review_regression.bat
```

For the complete regression, formal build, and package gate, run:

```cmd
publish_release.bat
```

This creates the release ZIP and checksum locally. Add `-Publish` only when the assets should be
uploaded to GitHub. `-SkipBuild` packages an existing formal EXE and intentionally skips regression.

This will:

1. build `%TEMP%\9SEC_EvidW_review.exe` with `INCLUDE_TESTS`
2. run `%TEMP%\9SEC_EvidW_review.exe -test`
3. delete the temporary review executable
4. leave the detailed result file at `%TEMP%\9SEC_EvidW_TestResult.txt`

## Manual equivalent

```cmd
build_review.bat
"%TEMP%\9SEC_EvidW_review.exe" -test
del /q "%TEMP%\9SEC_EvidW_review.exe"
```

## Differential parser validation

The optional Eric Zimmerman comparison no longer uses a BAT wrapper:

```cmd
powershell -ExecutionPolicy Bypass -File scripts\DiffValidate.ps1
```

The script exits successfully with an explicit skip message when the reference tools are absent.
When they are available, it builds `%TEMP%\9SEC_EvidW_review.exe` as needed and removes only the
review executable it created.

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
- output target classification for system disk, UNC network path, and unknown fixed paths
- strict policy restrictions for enabled memory acquisition/analysis and manual Deep Scan
- collector rejection of an unacknowledged strict run before output creation
- strict memory collectors writing `skipped` sidecars without launching external tools
- coverage round-trip, `partial` semantics, Summary/HTML visibility, and full LOG host metadata for strict policy
- shared / related / investigation-graph / time-window synthetic pivots
- timeline minute-precision filtering and graph-focus entity matching
- Summary tab parser-note visibility
- HTML report missing-artifact display normalization
- `summary_v3` missing-artifact count normalization
- `summary_v3` and `full_log_v3` export-schema marker stability
- `diff_v1` comparison, provenance, schema-marker, source-read-only, and CLI validation
- Fact Store build-cache exact reuse, EventLog-only incremental rebuild, non-EventLog fallback,
  corrupt-cache fallback, normalization-warning reuse, CSV bounds, and stale-store auto rebuild
- ZIP/TAR/TAR.GZ intake safety, archive entry mapping, source digest, encrypted/truncated archive
  failure behavior, and source-read-only guarantees
- UAC process/bodyfile/auth/audit/system-log/web-log/package/file-hash/network/account/shell-history/
  persistence/journal/boot/login derivation, bounds, timestamp confidence, canonical round-trip,
  Fact Store provenance, Summary, full LOG, and workspace manifest behavior
- published schema field drift for correlation, graph, diff, and Fact Store build metadata

## When to run

Run this automated regression pass at minimum:

- after changing `EventLogNormalizer.cs`
- after changing collection coverage logic
- after changing memory acquisition orchestration
- after changing memory analysis handoff orchestration
- after changing `CollectionImpactPolicy`, ForensicStrict settings, acknowledgement prompts, or Deep Scan restrictions
- after changing Summary / HTML / `summary_v3` export plumbing
- after changing Fact Store inputs, normalizers, build-cache invalidation, or persistence
- after changing archive intake, UAC detection/derivation, analysis workspace, or atomic publishing
- after changing Investigation Graph → Timeline handoff behavior
- before release packaging/signing

If this passes, continue with the manual smoke checklist in
`docs/SMOKE_RUN.md`.
