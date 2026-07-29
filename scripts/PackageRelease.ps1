#Requires -Version 3.0
<#
.SYNOPSIS
  Zip 9SEC_Evidence_Workbench.exe for GitHub Releases (EXE-only bundle).
  Optionally run build_release.bat, then create or update a release via GitHub CLI (gh).

.EXAMPLE
  .\scripts\PackageRelease.ps1
  .\scripts\PackageRelease.ps1 -SkipBuild
  .\scripts\PackageRelease.ps1 -Version v0.21.0 -Publish
#>
param(
    [string]$Version = "",
    [switch]$SkipBuild,
    [switch]$Publish,
    [string]$Notes = "",
    [switch]$Draft
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$exePath = Join-Path $root "9SEC_Evidence_Workbench.exe"
$specPath = Join-Path $root "docs\SPEC.md"

if (-not $SkipBuild) {
    Write-Host "[+] Running build_release.bat..."
    $build = Join-Path $root "build_release.bat"
    & cmd.exe /c "cd /d `"$root`" && call `"$build`""
    if ($LASTEXITCODE -ne 0) {
        throw "build_release.bat failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "9SEC_Evidence_Workbench.exe not found at $exePath. Run build_release.bat or use -SkipBuild after building."
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    if (-not (Test-Path -LiteralPath $specPath)) {
        throw "docs\SPEC.md not found; pass -Version vX.Y.Z explicitly."
    }
    # Read UTF-8 from bytes (with or without BOM); avoid Get-Content encoding mismatches on some hosts.
    $bytes = [System.IO.File]::ReadAllBytes($specPath)
    $off = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $off = 3
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes, $off, $bytes.Length - $off)
    $lines = [regex]::Split($text, '\r?\n')
    $found = $false
    $max = [Math]::Min(18, $lines.Length)
    for ($i = 0; $i -lt $max; $i++) {
        $line = $lines[$i]
        if ($line -match '(v\d+\.\d+\.\d+)\b') {
            $Version = $Matches[1]
            $found = $true
            break
        }
    }
    if (-not $found) {
        throw "Could not parse version from docs\SPEC.md (first ~18 lines, expected vX.Y.Z). Use -Version vX.Y.Z."
    }
}

$Version = $Version.Trim()
if (-not $Version.StartsWith("v", [StringComparison]::OrdinalIgnoreCase)) {
    $Version = "v$Version"
}

$distDir = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$zipName = "9SEC_Evidence_Workbench_$Version.zip"
$zipPath = Join-Path $distDir $zipName
$checksumName = "$zipName.sha256"
$checksumPath = Join-Path $distDir $checksumName

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
if (Test-Path -LiteralPath $checksumPath) {
    Remove-Item -LiteralPath $checksumPath -Force
}
Write-Host "[+] Compressing $exePath -> $zipPath"
Compress-Archive -LiteralPath $exePath -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host "[+] OK: $zipPath"

$stream = [System.IO.File]::OpenRead($zipPath)
$hasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $hashBytes = $hasher.ComputeHash($stream)
} finally {
    $stream.Dispose()
    $hasher.Dispose()
}
$hash = ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($checksumPath, "$hash  $zipName`r`n", $utf8NoBom)
Write-Host "[+] SHA-256: $hash"
Write-Host "[+] OK: $checksumPath"

if (-not $Publish) {
    Write-Host @"

[!] Zip only (no GitHub upload). To publish:
    gh auth login
    .\scripts\PackageRelease.ps1 -SkipBuild -Publish -Version $Version

Or upload $zipPath and $checksumPath manually in the repo Releases page.
"@
    exit 0
}

$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) {
    Write-Warning "GitHub CLI (gh) not in PATH. Install: https://cli.github.com/"
    Write-Host "Zip is ready: $zipPath"
    exit 0
}

$releaseNotes = $Notes
if ([string]::IsNullOrWhiteSpace($releaseNotes)) {
    $releaseNotes = "Portable **9SEC_Evidence_Workbench.exe** only (extract and run). Windows, .NET Framework 4.5+. See repository README."
}

$tag = $Version
# gh prints "release not found" to stderr when missing; with $ErrorActionPreference Stop that would halt the script.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$null = & gh release view $tag 2>&1
$releaseExists = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prevEap

$draftArg = @()
if ($Draft) {
    $draftArg = @("--draft")
}

$ErrorActionPreference = "SilentlyContinue"
if ($releaseExists) {
    Write-Host "[+] Uploading assets to existing release $tag..."
    & gh release upload $tag $zipPath $checksumPath --clobber
    $ec = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($ec -ne 0) {
        throw "gh release upload failed"
    }
    Write-Host "[+] Uploaded $zipName and $checksumName to release $tag"
} else {
    Write-Host "[+] Creating release $tag..."
    $createArgs = @("release", "create", $tag, $zipPath, $checksumPath, "--title", "9SEC Evidence Workbench $Version", "--notes", $releaseNotes) + $draftArg
    & gh @createArgs
    $ec = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($ec -ne 0) {
        throw "gh release create failed (is the tag valid and branch pushed?)"
    }
    Write-Host "[+] Created release $tag with $zipName and $checksumName"
}
