<#
.SYNOPSIS
    Extract real artifact samples from THIS host for Phase 2.2 differential validation.

.DESCRIPTION
    Read-only acquisition of the artifacts needed to diff IR_Collect's parsers against the
    Eric Zimmerman tools on identical inputs:
      - $MFT            via IR_Collect_review.exe -dump-mft (raw volume read)
      - Amcache.hve     via a temporary Volume Shadow Copy (file is locked while Windows runs)
      - SYSTEM hive     (for AppCompatCache / ShimCache) via the same shadow copy
      - SRUDB.dat       (for SRUM) via the same shadow copy

    MUST be run elevated (Administrator): raw \\.\C: reads and copying locked system hives both
    require it. Nothing on the system is modified; the shadow copy is deleted afterward.

    Output goes to .\samples\ which is .gitignored - these are REAL evidence from your machine and
    are never committed or transmitted. They are read locally by MFTECmd/AmcacheParser/etc. and by
    IR_Collect's own parsers, and only normalized fields are compared.

.EXAMPLE
    # From an elevated PowerShell at the repo root:
    powershell -ExecutionPolicy Bypass -File scripts\CollectLocalSamples.ps1
#>
[CmdletBinding()]
param(
    [string]$Drive = "C",
    [string]$OutDir = "samples"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] This script must be run elevated (Administrator)." -ForegroundColor Red
    Write-Host "    Open an elevated PowerShell, cd to the repo, then:" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\CollectLocalSamples.ps1" -ForegroundColor Yellow
    exit 1
}

$review = Join-Path $repoRoot "IR_Collect_review.exe"
if (-not (Test-Path $review)) {
    Write-Host "[!] IR_Collect_review.exe not found - build it first (build_review.bat)." -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force (Join-Path $OutDir "mft") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $OutDir "hives") | Out-Null

# ---- 1) $MFT via our raw dumper ----
Write-Host "[*] Dumping `$MFT via IR_Collect_review.exe -dump-mft ..." -ForegroundColor Cyan
& $review -dump-mft $Drive (Join-Path $OutDir "mft") | Out-Null
$mft = Get-ChildItem (Join-Path $OutDir "mft") -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
if ($mft) { Write-Host ("    [+] " + $mft.FullName + "  (" + [math]::Round($mft.Length/1MB,1) + " MB)") -ForegroundColor Green }
else { Write-Host "    [!] `$MFT dump produced no file." -ForegroundColor Red }

# ---- 2) Locked hives via a temporary Volume Shadow Copy ----
$shadowId = $null
$deviceObject = $null
try {
    Write-Host "[*] Creating a temporary Volume Shadow Copy of ${Drive}: ..." -ForegroundColor Cyan
    $class = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
    $res = $class.Create("${Drive}:\", "ClientAccessible")
    if ($res.ReturnValue -ne 0) { throw ("Win32_ShadowCopy.Create returned " + $res.ReturnValue) }
    $shadowId = $res.ShadowID
    $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowId }
    $deviceObject = $shadow.DeviceObject   # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    Write-Host ("    [+] Shadow device: " + $deviceObject) -ForegroundColor Green

    # A hive captured from a live system is "dirty" (pending transaction-log replay). The Eric Zimmerman
    # tools parse the file directly and abort on a dirty hive, while our own parser uses reg load (which
    # self-heals in memory). So for the two REGISTRY hives we copy then replay them into a clean, log-free
    # hive via reg load + reg save, which both tools can then parse. SRUDB.dat is an ESE database, not a
    # registry hive, and SrumECmd reads it directly - it is just copied.
    $targets = @(
        @{ Src = "Windows\appcompat\Programs\Amcache.hve"; Dst = "hives\Amcache.hve"; Replay = $true },
        @{ Src = "Windows\System32\config\SYSTEM";         Dst = "hives\SYSTEM";      Replay = $true },
        @{ Src = "Windows\System32\sru\SRUDB.dat";         Dst = "hives\SRUDB.dat";   Replay = $false }
    )
    $replayIdx = 0
    foreach ($t in $targets) {
        $srcPath = $deviceObject + "\" + $t.Src
        $dstPath = Join-Path $OutDir $t.Dst
        try {
            Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
            $len = (Get-Item $dstPath).Length
            Write-Host ("    [+] " + $t.Dst + "  (" + [math]::Round($len/1MB,2) + " MB)") -ForegroundColor Green
        }
        catch {
            Write-Host ("    [!] could not copy " + $t.Src + ": " + $_.Exception.Message) -ForegroundColor Yellow
            continue
        }
        if ($t.Replay) {
            $mount = "HKLM\IRCOL_REPLAY_" + $replayIdx; $replayIdx++
            $clean = $dstPath + ".clean"
            try {
                & reg.exe load $mount $dstPath *> $null
                if ($LASTEXITCODE -ne 0) { throw "reg load exit $LASTEXITCODE" }
                & reg.exe save $mount $clean /y *> $null
                $saveRc = $LASTEXITCODE
                & reg.exe unload $mount *> $null
                if ($saveRc -ne 0) { throw "reg save exit $saveRc" }
                Move-Item $clean $dstPath -Force
                Write-Host ("        replayed to a clean hive (reg load/save)") -ForegroundColor DarkGreen
            }
            catch {
                Write-Host ("    [!] hive replay failed for " + $t.Dst + " (" + $_.Exception.Message + "); EZ tools may abort on the dirty hive.") -ForegroundColor Yellow
                if (Test-Path $clean) { Remove-Item $clean -Force -ErrorAction SilentlyContinue }
                & reg.exe unload $mount *> $null 2>&1
            }
        }
    }
}
catch {
    Write-Host ("[!] Shadow copy step failed: " + $_.Exception.Message) -ForegroundColor Yellow
    Write-Host "    ($MFT may still have succeeded; hives just won't be available.)" -ForegroundColor Yellow
}
finally {
    if ($shadowId) {
        try {
            Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowId } | Remove-CimInstance
            Write-Host "[*] Temporary shadow copy removed." -ForegroundColor Cyan
        }
        catch { Write-Host ("[!] Could not remove shadow copy " + $shadowId + " - remove manually with vssadmin.") -ForegroundColor Yellow }
    }
}

Write-Host ""
Write-Host "[+] Done. Samples under .\$OutDir (gitignored). Next:" -ForegroundColor Green
Write-Host "    DiffValidate.ps1 -Kind mft        (unelevated)" -ForegroundColor White
Write-Host "    DiffValidate.ps1 -Kind srum       (unelevated; needs the 64-bit ACE OLE DB provider)" -ForegroundColor White
Write-Host "    DiffValidate.ps1 -Kind amcache    (ELEVATED; our ParseHive uses reg load)" -ForegroundColor White
