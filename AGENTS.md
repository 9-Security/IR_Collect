# IR_Collect Agent Guide

This repository is a Windows IR collector and investigation workspace built as a single portable EXE. Treat it as a `facts-only` DFIR tool, not an EDR, auto-verdict engine, or full memory forensics platform.

## Core Rules

- Preserve forensic soundness. Prefer read-only collection behavior and avoid destructive changes.
- Keep outputs UTF-8 without BOM and schema-stable per `docs/SPEC.md` and `docs/ARTIFACTS.md`.
- Avoid new dependencies or network calls unless there is an explicit configured endpoint and the task requires it.
- Keep Win7+ / .NET Framework 4.5+ / C# 5 compatibility unless the task explicitly changes project requirements.
- Build with `build.bat`.

## Settings

- Any user-configurable option must be exposed in `Advanced -> Settings`.
- Use `ConfigManager` for defaults, reads, writes, and persistence.
- Do not introduce options that are only editable in `config.ini`.

## New Artifacts And Platform Intake

- If you add a new collected artifact, also add platform intake for it.
- Update `CaseManager.LoadCase` artifact discovery so imported cases recognize the new file or pattern.
- Provide a UI view or file-list entry for the new artifact where appropriate.
- If intake cannot be completed in the same change, add an explicit follow-up note in the docs backlog instead of silently leaving the artifact orphaned.

## Facts And Export

- New structured evidence should follow the existing pipeline:
  `Collector -> Artifact -> Normalizer -> Fact Store -> Timeline / Correlation / Export`
- If a new log source is normalized and added to `FactStore.BuildFromCase`, it should flow into the full LOG JSON export automatically.
- Do not invent a separate export format for one new normalized source unless there is a strong reason.
- Keep provenance fields intact for any new facts.

## Documentation Sync

When behavior changes, update the smallest relevant set of docs:

- `docs/README.md`
- `docs/SPEC.md`
- `docs/ARTIFACTS.md`

Update additional maintenance or backlog docs only when the change actually requires it.

## Existing Source Of Truth

This file mirrors the repo-specific rules already stored in `.cursor/rules/ir-collect-agents.mdc` so tools that look for `AGENTS.md` can apply the same project guidance.
