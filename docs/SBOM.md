# IR_Collect — Software Bill of Materials (SBOM) & Dependency Governance

This document declares everything IR_Collect is built from and depends on at runtime, for
dependency governance and court-admissibility. It is maintained by hand; the authoritative
build-input list is [`build_common.rsp`](../build_common.rsp).

## Tool identity

- **Name:** IR_Collect
- **Version:** single source of truth = `AssemblyVersion` in [`src/AssemblyInfo.cs`](../src/AssemblyInfo.cs),
  read at runtime by `IR_Collect.BuildInfo` and printed by `IR_Collect.exe -version`.
- **Version surfacing:** stamped as `tool_name` + `tool_version` into every machine-readable
  output (`summary_v3`, `correlation_v1`, `graph_v1`, `full_log_v3`).

## Build

- **Output:** a single portable `IR_Collect.exe` (WinForms, `winexe`).
- **Target:** .NET Framework 4.5 / C# 5.
- **Compiler (pinned):** `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (the in-box
  .NET Framework compiler). Invoked from [`build.bat`](../build.bat) / [`build_release.bat`](../build_release.bat).
- **Build-input manifest (lockfile):** [`build_common.rsp`](../build_common.rsp) — an explicit,
  ordered list of every source file and every framework reference. **No NuGet, no MSBuild, no `.csproj`.**
- **Reproducibility limitation (disclosed):** the pinned `v4.0.30319` compiler is pre-Roslyn and
  rejects `/deterministic`; it embeds a fresh MVID + timestamp per build, so byte-identical
  reproducible builds are not achievable with this toolchain. The source + `build_common.rsp` fully
  determine the build inputs; only the PE-level identifiers vary.

## Runtime dependencies

| Component | Origin | How loaded | Governance |
|---|---|---|---|
| **.NET Framework 4.5 BCL** | OS | static reference (`/r:` in `build_common.rsp`: System, System.Core, System.Management, System.Windows.Forms, System.Drawing, System.Runtime.Serialization, System.Data, System.IO.Compression[.FileSystem]) | shipped with Windows |
| **esent.dll** | Windows system DLL | P/Invoke (`src/Utils/EseReader.cs`) | system-provided ESE engine; reads SRUM `SRUDB.dat`. Replaced the former ACE/Jet OLE DB dependency — no external Access engine is needed. |
| **wintrust.dll** | Windows system DLL | P/Invoke (`src/SignatureHelper.cs`) | Authenticode verification (`WinVerifyTrust`) |
| **System.Data.SQLite.dll** | optional, external | `Assembly.LoadFrom` **only if Authenticode-trusted** (`FactStorePersistence.IsTrustedSqliteModule`) | anti-DLL-planting gate: loaded only when signature status is `Signed-Trusted`; absence degrades the Fact Store SQLite cache and in-app browser-history parsing gracefully. |

## Not linked / not bundled

- **Eric Zimmerman (EZ) tools** under `tools/EZ/` — used only for offline **differential validation**
  of our parsers (`scripts/DiffValidate.ps1`); they are **not** invoked at runtime and are **not**
  committed (the `tools/` directory is gitignored).
- **Evidence samples** under `samples/` are local test evidence and are gitignored.

## Integrity & chain-of-custody features

- **Collection:** the output ZIP is SHA-256 hashed into a `<evidenceId>.zip.sha256` sidecar
  (`Collector.cs`), and `file_integrity.csv` records SHA-256 + Authenticode status of critical OS binaries.
- **Analysis (folder intake):** every input file is SHA-256 hashed at load time *before* any
  derivation; `summary_v3` carries the full per-file `evidence[]` manifest + a rollup `evidence_digest`,
  and `correlation_v1` / `graph_v1` carry a per-host `evidence_digest` + `evidence_file_count`. This
  cryptographically ties an analysis report to exactly the evidence it consumed.

## Code signing

- Local builds are signed by [`scripts/SignLocalBuild.ps1`](../scripts/SignLocalBuild.ps1) with a
  **self-signed** code-signing certificate (locally untrusted). A production CA / EV certificate is
  outstanding; until then SmartScreen will warn on first run. Runtime Authenticode status is checked
  via `src/SignatureHelper.cs`.
