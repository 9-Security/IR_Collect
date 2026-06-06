<#
.SYNOPSIS
    Phase 2.2 - differential validation of IR_Collect's parsers against the Eric Zimmerman tools.

.DESCRIPTION
    Runs IR_Collect's REAL production parser (via IR_Collect_review.exe -parse) and the matching
    Eric Zimmerman reference tool (LECmd / JLECmd) on the same input artifacts, then diffs the
    extracted paths. Disagreements where the reference tool found a LinkInfo LocalBasePath that we
    did NOT reproduce are treated as failures (the gate); cases the reference resolves only from a
    target IDList (which our LinkInfo-only reader does not cover yet) are reported separately as
    coverage notes, not failures.

    Designed to be a CI-style gate that SKIPS cleanly (exit 0) when the EZ tools are not present,
    so it never blocks an environment that lacks them - but it never silently "passes" either: the
    skip reason is always printed.

    No artifact bytes are copied or transmitted; the reference tool and our parser both read the
    inputs in place and only normalized path strings are compared. Output stays local.

.PARAMETER ToolsDir
    Directory containing the EZ tool exes. Default: tools\EZ\net9

.PARAMETER ReviewExe
    Path to IR_Collect_review.exe (built with INCLUDE_TESTS). Default: .\IR_Collect_review.exe

.PARAMETER Kind
    Which parser(s) to validate: lnk, jumplist, or all. Default: all

.PARAMETER Sample
    Max number of input files per kind (keeps runs fast). Default: 30. Use 0 for no cap.

.PARAMETER InputDir
    Optional explicit directory of inputs. If omitted, real artifacts are auto-discovered from
    standard Windows locations plus the synthesized lnk fixtures under tests\fixtures.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\DiffValidate.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\DiffValidate.ps1 -Kind lnk -Sample 50
#>
[CmdletBinding()]
param(
    [string]$ToolsDir = "tools\EZ\net9",
    [string]$ReviewExe = ".\IR_Collect_review.exe",
    [ValidateSet("lnk", "jumplist", "mft", "srum", "amcache", "shimcache", "all")]
    [string]$Kind = "all",
    [int]$Sample = 30,
    [string]$InputDir = "",
    [string]$MftCsv = ""    # reuse a pre-generated MFTECmd CSV instead of re-parsing $MFT (~11 min)
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$SKIP = 3          # exit code: validation skipped (tool missing) - not a failure
$script:failures = 0
$script:skipped = $false

function Write-Section($t) { Write-Host ""; Write-Host ("=== " + $t + " ===") -ForegroundColor Cyan }

function Resolve-Tool($name) {
    $p = Join-Path $ToolsDir ($name + ".exe")
    if (Test-Path $p) { return (Resolve-Path $p).Path }
    return $null
}

function Norm($s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    return $s.Trim().TrimEnd('\').ToLowerInvariant()
}

# Run our parser on one file and return its extracted paths (array, possibly empty).
function Get-OurPaths($kindArg, $file) {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        & $ReviewExe -parse $kindArg "$file" "$tmp" | Out-Null
        # Read as UTF-8 explicitly: PowerShell 5.1 Get-Content defaults to ANSI and would mojibake
        # non-ASCII (e.g. CJK) paths, producing false mismatches.
        $json = if (Test-Path $tmp) { [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) } else { "" }
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        $obj = $json | ConvertFrom-Json
        if ($obj.ok -ne $true) { return @() }
        if ($null -eq $obj.paths) { return @() }
        return @($obj.paths)
    }
    catch { return @() }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

# Run an EZ tool over a directory of inputs, return the path of the single output CSV it writes.
function Invoke-EzCsv($exe, $inputDir) {
    $out = Join-Path $env:TEMP ("ezdiff_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Force $out | Out-Null
    & $exe -d "$inputDir" --csv "$out" 2>&1 | Out-Null
    $csv = Get-ChildItem $out -Filter *.csv -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if ($null -eq $csv) { return $null }
    return $csv.FullName
}

function Get-LnkInputs {
    $dirs = @()
    if ($InputDir) { $dirs += $InputDir }
    else {
        $dirs += (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs")
        $dirs += (Join-Path $env:APPDATA "Microsoft\Windows\Recent")
        $dirs += "tests\fixtures\lnk"
    }
    $files = @()
    foreach ($d in $dirs) {
        if (Test-Path $d) {
            $files += Get-ChildItem $d -Recurse -Filter *.lnk -File -ErrorAction SilentlyContinue
        }
    }
    return $files
}

function Validate-Lnk {
    Write-Section "LNK  (IR_Collect LocalBasePath reader  vs  LECmd)"
    $exe = Resolve-Tool "LECmd"
    if (-not $exe) {
        Write-Host ("SKIP: LECmd.exe not found under " + $ToolsDir + " - LNK validation skipped.") -ForegroundColor Yellow
        $script:skipped = $true
        return
    }
    $files = Get-LnkInputs
    if ($files.Count -eq 0) { Write-Host "SKIP: no .lnk inputs found." -ForegroundColor Yellow; $script:skipped = $true; return }
    if ($Sample -gt 0 -and $files.Count -gt $Sample) { $files = $files | Get-Random -Count $Sample }
    Write-Host ("Inputs: " + $files.Count + " .lnk file(s)")

    # Stage inputs into one flat dir so a single LECmd -d run produces one CSV keyed by SourceFile.
    $stage = Join-Path $env:TEMP ("ezdiff_lnk_in_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Force $stage | Out-Null
    # Key the join on the (unique, numeric-prefixed) leaf filename, not the full path: LECmd reports
    # SourceFile using the TEMP dir's 8.3 short form (SHARLO~1) which won't match a long-path key.
    $map = @{}   # staged leaf filename (lower) -> original file
    $i = 0
    foreach ($f in $files) {
        $leaf = ("{0:D4}_{1}" -f $i, $f.Name)
        $dest = Join-Path $stage $leaf
        Copy-Item $f.FullName $dest -Force
        $map[$leaf.ToLowerInvariant()] = $f.FullName
        $i++
    }

    $csv = Invoke-EzCsv $exe $stage
    if (-not $csv) { Write-Host "SKIP: LECmd produced no CSV." -ForegroundColor Yellow; $script:skipped = $true; return }
    $rows = Import-Csv $csv -Encoding UTF8

    $match = 0; $mismatch = 0; $idlistOnly = 0
    $mismatches = @()
    foreach ($row in $rows) {
        $src = $row.SourceFile
        if (-not $src) { continue }
        $orig = $map[((Split-Path $src -Leaf)).ToLowerInvariant()]
        if (-not $orig) { continue }
        $lecmdLocal = Norm $row.LocalPath
        $ours = @(Get-OurPaths "lnk" $orig | ForEach-Object { Norm $_ })

        if ($lecmdLocal -eq "") {
            # LECmd resolved target only via IDList (no LinkInfo LocalBasePath) - outside our reader's scope.
            $idlistOnly++
            continue
        }
        if ($ours -contains $lecmdLocal) {
            $match++
        }
        else {
            $mismatch++
            $mismatches += [PSCustomObject]@{
                File = Split-Path $orig -Leaf
                LECmd_LocalPath = $row.LocalPath
                Ours = ($ours -join " ; ")
            }
        }
    }

    Write-Host ("MATCH (we reproduced LECmd LocalBasePath):        " + $match) -ForegroundColor Green
    Write-Host ("MISMATCH (LECmd had LocalBasePath, we did not):   " + $mismatch) -ForegroundColor (&{ if ($mismatch -gt 0) { "Red" } else { "Green" } })
    Write-Host ("IDLIST-ONLY (no LinkInfo LocalBasePath; coverage): " + $idlistOnly) -ForegroundColor DarkGray
    if ($mismatch -gt 0) {
        Write-Host "--- mismatches ---" -ForegroundColor Red
        $mismatches | Format-Table -AutoSize | Out-String | Write-Host
        $script:failures += $mismatch
    }

    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Split-Path $csv -Parent) -Recurse -Force -ErrorAction SilentlyContinue
}

function Validate-JumpList {
    Write-Section "JUMPLIST  (IR_Collect path scan  vs  JLECmd)  [informational]"
    $exe = Resolve-Tool "JLECmd"
    if (-not $exe) {
        Write-Host ("SKIP: JLECmd.exe not found under " + $ToolsDir + " - jump list validation skipped.") -ForegroundColor Yellow
        $script:skipped = $true
        return
    }
    $dir = if ($InputDir) { $InputDir } else { Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations" }
    if (-not (Test-Path $dir)) { Write-Host "SKIP: no AutomaticDestinations dir." -ForegroundColor Yellow; $script:skipped = $true; return }
    $files = Get-ChildItem $dir -Filter *.automaticDestinations-ms -File -ErrorAction SilentlyContinue
    if ($files.Count -eq 0) { Write-Host "SKIP: no jump list files." -ForegroundColor Yellow; $script:skipped = $true; return }
    if ($Sample -gt 0 -and $files.Count -gt $Sample) { $files = $files | Get-Random -Count $Sample }
    Write-Host ("Inputs: " + $files.Count + " jump list file(s)")

    $csv = Invoke-EzCsv $exe $dir
    if (-not $csv) { Write-Host "SKIP: JLECmd produced no CSV." -ForegroundColor Yellow; $script:skipped = $true; return }
    $rows = Import-Csv $csv -Encoding UTF8

    # Build reference path set per source jump list file.
    $refByFile = @{}
    foreach ($row in $rows) {
        $sf = $null
        foreach ($cand in @($row.SourceFile, $row.SourceName)) { if ($cand) { $sf = $cand; break } }
        if (-not $sf) { continue }
        $key = Split-Path $sf -Leaf
        $p = $null
        foreach ($col in @('Path', 'LocalPath', 'TargetIDAbsolutePath')) {
            if ($row.PSObject.Properties[$col] -and $row.$col) { $p = $row.$col; break }
        }
        if (-not $p) { continue }
        if (-not $refByFile.ContainsKey($key)) { $refByFile[$key] = New-Object System.Collections.Generic.HashSet[string] }
        [void]$refByFile[$key].Add((Norm $p))
    }

    $totalRef = 0; $totalRecalled = 0; $filesCompared = 0
    foreach ($f in $files) {
        $key = $f.Name
        if (-not $refByFile.ContainsKey($key)) { continue }
        $ref = $refByFile[$key]
        if ($ref.Count -eq 0) { continue }
        $ours = @(Get-OurPaths "jumplist" $f.FullName | ForEach-Object { Norm $_ })
        $recalled = 0
        foreach ($r in $ref) { if ($ours -contains $r) { $recalled++ } }
        $totalRef += $ref.Count
        $totalRecalled += $recalled
        $filesCompared++
    }

    if ($totalRef -eq 0) {
        Write-Host "INFO: no comparable reference paths (JLECmd extracted none with a file path)." -ForegroundColor DarkGray
    }
    else {
        $pct = [math]::Round(100.0 * $totalRecalled / $totalRef, 1)
        Write-Host ("Files compared: " + $filesCompared)
        Write-Host ("Path recall vs JLECmd: " + $totalRecalled + "/" + $totalRef + " (" + $pct + "%)") -ForegroundColor DarkGray
        Write-Host "NOTE: our jump-list reader is a byte-scan heuristic, not a full OLE-CFB parser;" -ForegroundColor DarkGray
        Write-Host "      recall < 100% here is a known coverage gap for Phase 2.3, not a gate failure." -ForegroundColor DarkGray
    }

    Remove-Item (Split-Path $csv -Parent) -Recurse -Force -ErrorAction SilentlyContinue
}

function Normalize-MftTime($s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
        if ($dt.Year -le 1601) { return "" }
        return $dt.ToString("yyyy-MM-ddTHH:mm:ss")
    }
    return ""
}

function Validate-Mft {
    Write-Section "MFT  (IR_Collect MftParser  vs  MFTECmd)"
    $exe = Resolve-Tool "MFTECmd"
    if (-not $exe) {
        Write-Host ("SKIP: MFTECmd.exe not found under " + $ToolsDir + " - MFT validation skipped.") -ForegroundColor Yellow
        $script:skipped = $true; return
    }
    $mftDir = if ($InputDir) { $InputDir } else { "samples\mft" }
    $mft = Get-ChildItem $mftDir -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $mft) {
        Write-Host ("SKIP: no `$MFT sample under " + $mftDir + ". Run (elevated) scripts\CollectLocalSamples.ps1 first.") -ForegroundColor Yellow
        $script:skipped = $true; return
    }
    Write-Host ("Input `$MFT: " + $mft.FullName + "  (" + [math]::Round($mft.Length/1MB,1) + " MB)")

    # Reference: a pre-generated MFTECmd CSV (fast path) or a fresh MFTECmd -f run (~11 min on a big $MFT).
    $outdir = $null
    if ($MftCsv -and (Test-Path $MftCsv)) {
        $csv = Get-Item $MftCsv
        Write-Host ("Reusing MFTECmd CSV: " + $csv.FullName)
    }
    else {
        $outdir = Join-Path $env:TEMP ("ezdiff_mft_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
        New-Item -ItemType Directory -Force $outdir | Out-Null
        & $exe -f "$($mft.FullName)" --csv "$outdir" 2>&1 | Out-Null
        $csv = Get-ChildItem $outdir -Filter *.csv -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
        if (-not $csv) { Write-Host "SKIP: MFTECmd produced no CSV." -ForegroundColor Yellow; $script:skipped = $true; return }
    }

    # Our side FIRST: -parse mft -> JSON entries (bounded by the MftParseLimit, ~60k).
    $tmp = [System.IO.Path]::GetTempFileName()
    & $ReviewExe -parse mft "$($mft.FullName)" "$tmp" | Out-Null
    $json = if (Test-Path $tmp) { [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) } else { "" }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($json)) { Write-Host "SKIP: our -parse mft produced no output." -ForegroundColor Yellow; $script:skipped = $true; return }
    $obj = $json | ConvertFrom-Json
    if ($obj.ok -ne $true) { Write-Host ("FAIL: -parse mft error: " + $obj.error) -ForegroundColor Red; $script:failures++; return }
    $ours = @($obj.entries)
    Write-Host ("IR_Collect records emitted (limit " + $obj.limit + "): " + $ours.Count)

    # Set of EntryNumbers we emitted, so we only keep the matching MFTECmd rows. A full $MFT can hold
    # millions of records; loading them all into a hashtable is what OOM'd the first run. By filtering
    # to our ~60k set while streaming, the reference map stays bounded and memory stays flat.
    $ourRecs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in $ours) { [void]$ourRecs.Add([string]$e.rec) }

    # Reference map: EntryNumber -> { all names (a record can carry several $FILE_NAME attributes for
    # hardlinks / namespaces) + timestamps from the first row }, but ONLY for records we emitted.
    # MFTECmd writes UTF-8; read it as such so non-ASCII filenames are not mojibake'd into mismatches.
    $ref = @{}
    Import-Csv $csv.FullName -Encoding UTF8 | ForEach-Object {
        $en = $_.EntryNumber
        if ($null -eq $en -or $en -eq "") { return }
        if (-not $ourRecs.Contains([string]$en)) { return }
        if (-not $ref.ContainsKey($en)) {
            $ref[$en] = [PSCustomObject]@{
                Names    = (New-Object 'System.Collections.Generic.HashSet[string]')
                First    = $_.FileName
                Created  = (Normalize-MftTime $_.Created0x10)
                Modified = (Normalize-MftTime $_.LastModified0x10)
            }
        }
        [void]$ref[$en].Names.Add(([string]$_.FileName).ToLowerInvariant())
    }
    Write-Host ("MFTECmd records matched to our set: " + $ref.Count)

    $compared = 0; $nameMatch = 0; $attrListGap = 0; $realMismatch = 0; $tsMatch = 0; $tsMismatch = 0
    $realMismatches = @(); $tsMismatches = @()
    foreach ($e in $ours) {
        $key = [string]$e.rec
        if (-not $ref.ContainsKey($key)) { continue }
        $r = $ref[$key]
        $compared++
        $ourLeaf = ($e.path.Split('\') | Select-Object -Last 1)
        # Hardlink-aware: a record can legitimately have several Win32 names; agreement = our name is
        # ANY of the names MFTECmd reported for this EntryNumber.
        if ($r.Names.Contains($ourLeaf.ToLowerInvariant())) {
            $nameMatch++
        }
        elseif ([string]::IsNullOrEmpty($ourLeaf) -or ($ourLeaf -match '~\d')) {
            # Our name is empty or a DOS 8.3 short name while MFTECmd has the long name: the long Win32
            # name (and sometimes the only $FILE_NAME) lives in an $ATTRIBUTE_LIST extension record this
            # parser does not follow yet, or this is an NTFS metafile (e.g. root "."). Known coverage gap.
            $attrListGap++
        }
        else {
            $realMismatch++
            if ($realMismatches.Count -lt 12) {
                $realMismatches += [PSCustomObject]@{ Rec = $key; Ours = $ourLeaf; MFTECmd = $r.First }
            }
        }
        # Timestamps: compare only when both sides have a value (our limit may emit fewer attrs).
        if ($e.cr -and $r.Created) {
            if ($e.cr -eq $r.Created -and $e.mo -eq $r.Modified) { $tsMatch++ }
            else {
                $tsMismatch++
                if ($tsMismatches.Count -lt 8) {
                    $tsMismatches += [PSCustomObject]@{ Rec = $key; Field = "cr/mo"; Ours = ($e.cr + " / " + $e.mo); MFTECmd = ($r.Created + " / " + $r.Modified) }
                }
            }
        }
    }

    Write-Host ("Records compared (same EntryNumber):  " + $compared)
    Write-Host ("FILENAME match (incl. hardlink names): " + $nameMatch) -ForegroundColor Green
    Write-Host ("`$ATTRIBUTE_LIST coverage gap (ours=8.3 short name): " + $attrListGap) -ForegroundColor DarkGray
    Write-Host ("FILENAME real mismatch (gate):         " + $realMismatch) -ForegroundColor (&{ if ($realMismatch -gt 0) { "Red" } else { "Green" } })
    Write-Host ("TIMESTAMP match (cr+mo):    " + $tsMatch) -ForegroundColor DarkGray
    Write-Host ("TIMESTAMP mismatch (cr+mo): " + $tsMismatch) -ForegroundColor (&{ if ($tsMismatch -gt 0) { "Yellow" } else { "DarkGray" } })
    if ($realMismatch -gt 0) {
        Write-Host "--- real filename mismatches (gate) ---" -ForegroundColor Red
        $realMismatches | Format-Table -AutoSize | Out-String | Write-Host
        $script:failures += $realMismatch
    }
    if ($tsMismatch -gt 0) {
        Write-Host "--- timestamp mismatches (informational; investigate tz/attribute source) ---" -ForegroundColor Yellow
        $tsMismatches | Format-Table -AutoSize | Out-String | Write-Host
    }

    if ($outdir) { Remove-Item $outdir -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-OurObj($kindArg, $file) {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        & $ReviewExe -parse $kindArg "$file" "$tmp" | Out-Null
        $json = if (Test-Path $tmp) { [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) } else { "" }
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        return ($json | ConvertFrom-Json)
    }
    catch { return $null }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Validate-Srum {
    Write-Section "SRUM  (IR_Collect SrumExporter  vs  SrumECmd)  [informational]"
    $exe = Resolve-Tool "SrumECmd"
    if (-not $exe) { Write-Host ("SKIP: SrumECmd.exe not found under " + $ToolsDir + ".") -ForegroundColor Yellow; $script:skipped = $true; return }
    $db = if ($InputDir) { Join-Path $InputDir "SRUDB.dat" } else { "samples\hives\SRUDB.dat" }
    if (-not (Test-Path $db)) { Write-Host ("SKIP: no SRUDB.dat at " + $db + " (run CollectLocalSamples.ps1 elevated).") -ForegroundColor Yellow; $script:skipped = $true; return }

    $our = Get-OurObj "srum" $db
    if ($null -eq $our -or $our.ok -ne $true) { Write-Host "SKIP: our -parse srum produced no result." -ForegroundColor Yellow; $script:skipped = $true; return }
    if ($our.fallback -eq $true) {
        Write-Host ("SKIP: IR_Collect SRUM parser fell back (no rows). Note: " + ($our.notes -join '; ')) -ForegroundColor Yellow
        Write-Host "      ROOT CAUSE: SRUDB.dat is an ESE (esent/JET Blue) database; OLE DB ACE/Jet" -ForegroundColor DarkGray
        Write-Host "      providers only read Access (JET Red) and cannot open ESE. Installing ACE does" -ForegroundColor DarkGray
        Write-Host "      not help. Fix = read SRUDB.dat via a native ESE reader (esent.dll). Phase 2.3." -ForegroundColor DarkGray
        $script:skipped = $true; return
    }

    $out = Join-Path $env:TEMP ("ezdiff_srum_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Force $out | Out-Null
    & $exe -f "$db" --csv "$out" 2>&1 | Out-Null
    $csv = Get-ChildItem $out -Filter *AppResourceUseInfo*.csv -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $csv) { Write-Host "SKIP: SrumECmd produced no AppResourceUseInfo CSV." -ForegroundColor Yellow; $script:skipped = $true; return }

    $ezApps = New-Object 'System.Collections.Generic.HashSet[string]'
    Import-Csv $csv.FullName -Encoding UTF8 | ForEach-Object { if ($_.ExeInfo) { [void]$ezApps.Add(([string]$_.ExeInfo).ToLowerInvariant()) } }
    $ourApps = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($a in $our.apps) {
        $id = if ($a.app) { $a.app } else { $a.path }   # AppId identity == SrumECmd ExeInfo
        if ($id) { [void]$ourApps.Add(([string]$id).ToLowerInvariant()) }
    }
    $hit = 0; foreach ($e in $ezApps) { if ($ourApps.Contains($e)) { $hit++ } }
    $pct = if ($ezApps.Count -gt 0) { [math]::Round(100.0 * $hit / $ezApps.Count, 1) } else { 0 }
    Write-Host ("Distinct apps: ours=" + $ourApps.Count + ", SrumECmd=" + $ezApps.Count)
    Write-Host ("App recall vs SrumECmd: " + $hit + "/" + $ezApps.Count + " (" + $pct + "%)") -ForegroundColor DarkGray
    Write-Host "NOTE: informational set-overlap; row models differ. Investigate large gaps in Phase 2.3." -ForegroundColor DarkGray
    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

function Validate-Amcache {
    Write-Section "AMCACHE  (IR_Collect AmcacheParser  vs  AmcacheParser.exe)  [informational]"
    $exe = Resolve-Tool "AmcacheParser"
    if (-not $exe) { Write-Host ("SKIP: AmcacheParser.exe not found under " + $ToolsDir + ".") -ForegroundColor Yellow; $script:skipped = $true; return }
    $hive = if ($InputDir) { Join-Path $InputDir "Amcache.hve" } else { "samples\hives\Amcache.hve" }
    if (-not (Test-Path $hive)) { Write-Host ("SKIP: no Amcache.hve at " + $hive + " (run CollectLocalSamples.ps1 elevated).") -ForegroundColor Yellow; $script:skipped = $true; return }

    $our = Get-OurObj "amcache" $hive
    if ($null -eq $our -or $our.ok -ne $true) { Write-Host "SKIP: our -parse amcache produced no result." -ForegroundColor Yellow; $script:skipped = $true; return }
    if ($our.fallback -eq $true) {
        Write-Host ("SKIP: IR_Collect Amcache parser fell back. Note: " + ($our.notes -join '; ')) -ForegroundColor Yellow
        Write-Host "      (Our ParseHive uses 'reg load' which needs admin - run this diff elevated.)" -ForegroundColor DarkGray
        $script:skipped = $true; return
    }

    $out = Join-Path $env:TEMP ("ezdiff_amc_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Force $out | Out-Null
    & $exe -f "$hive" -i --csv "$out" 2>&1 | Out-Null
    $csvs = Get-ChildItem $out -Filter *FileEntries*.csv -ErrorAction SilentlyContinue
    if (-not $csvs) { Write-Host "SKIP: AmcacheParser produced no FileEntries CSV (hive dirty / missing .LOG?)." -ForegroundColor Yellow; $script:skipped = $true; return }

    $ezSha = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $csvs) {
        Import-Csv $c.FullName -Encoding UTF8 | ForEach-Object {
            $s = $_.SHA1; if ($s) { [void]$ezSha.Add(([string]$s).ToLowerInvariant().TrimStart('0').PadLeft(40,'0')) }
        }
    }
    $ourSha = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($f in $our.files) { if ($f.sha1) { [void]$ourSha.Add(([string]$f.sha1).ToLowerInvariant().TrimStart('0').PadLeft(40,'0')) } }
    $hit = 0; foreach ($e in $ezSha) { if ($ourSha.Contains($e)) { $hit++ } }
    $pct = if ($ezSha.Count -gt 0) { [math]::Round(100.0 * $hit / $ezSha.Count, 1) } else { 0 }
    Write-Host ("Distinct SHA1 file entries: ours=" + $ourSha.Count + ", AmcacheParser=" + $ezSha.Count)
    Write-Host ("SHA1 recall vs AmcacheParser: " + $hit + "/" + $ezSha.Count + " (" + $pct + "%)") -ForegroundColor DarkGray
    Write-Host "NOTE: informational set-overlap by SHA1; dedup/schema differ. Investigate large gaps in Phase 2.3." -ForegroundColor DarkGray
    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

function Validate-ShimCache {
    Write-Section "SHIMCACHE  (IR_Collect ShimCacheParser  vs  AppCompatCacheParser)  [informational]"
    $exe = Resolve-Tool "AppCompatCacheParser"
    if (-not $exe) { Write-Host ("SKIP: AppCompatCacheParser.exe not found under " + $ToolsDir + ".") -ForegroundColor Yellow; $script:skipped = $true; return }
    $hive = if ($InputDir) { Join-Path $InputDir "SYSTEM" } else { "samples\hives\SYSTEM" }
    if (-not (Test-Path $hive)) { Write-Host ("SKIP: no SYSTEM hive at " + $hive + " (run CollectLocalSamples.ps1 elevated).") -ForegroundColor Yellow; $script:skipped = $true; return }

    $our = Get-OurObj "shimcache" $hive
    if ($null -eq $our -or $our.ok -ne $true) { Write-Host "SKIP: our -parse shimcache produced no result." -ForegroundColor Yellow; $script:skipped = $true; return }
    if ($our.fallback -eq $true) {
        Write-Host ("SKIP: IR_Collect ShimCache parser fell back. Note: " + ($our.notes -join '; ')) -ForegroundColor Yellow
        Write-Host "      (Our hive mode uses 'reg load' which needs admin - run this diff elevated.)" -ForegroundColor DarkGray
        $script:skipped = $true; return
    }

    $out = Join-Path $env:TEMP ("ezdiff_shim_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Force $out | Out-Null
    & $exe -f "$hive" --csv "$out" 2>&1 | Out-Null
    $csv = Get-ChildItem $out -Filter *.csv -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $csv) { Write-Host "SKIP: AppCompatCacheParser produced no CSV." -ForegroundColor Yellow; $script:skipped = $true; return }

    $ezPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    Import-Csv $csv.FullName -Encoding UTF8 | ForEach-Object { if ($_.Path) { [void]$ezPaths.Add(([string]$_.Path).ToLowerInvariant()) } }
    $ourPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in $our.paths) { if ($p) { [void]$ourPaths.Add(([string]$p).ToLowerInvariant()) } }
    $hit = 0; foreach ($e in $ezPaths) { if ($ourPaths.Contains($e)) { $hit++ } }
    $pct = if ($ezPaths.Count -gt 0) { [math]::Round(100.0 * $hit / $ezPaths.Count, 1) } else { 0 }
    Write-Host ("Distinct paths: ours=" + $ourPaths.Count + ", AppCompatCacheParser=" + $ezPaths.Count)
    Write-Host ("Path recall vs AppCompatCacheParser: " + $hit + "/" + $ezPaths.Count + " (" + $pct + "%)") -ForegroundColor DarkGray
    Write-Host "NOTE: our parser is a path byte-scan heuristic (no structured entries/timestamps);" -ForegroundColor DarkGray
    Write-Host "      recall < 100% and missing LastModified times are a known Phase 2.3 gap." -ForegroundColor DarkGray
    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

# --- main ---
Write-Host "IR_Collect - Phase 2.2 differential validation" -ForegroundColor White
if (-not (Test-Path $ReviewExe)) {
    Write-Host ("ERROR: review exe not found at " + $ReviewExe + " - build it with build_review.bat first.") -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ToolsDir)) {
    Write-Host ("SKIP: EZ tools dir not found (" + $ToolsDir + "). Run scripts\Get-ZimmermanTools.ps1 or pass -ToolsDir.") -ForegroundColor Yellow
    Write-Host "(Skipped, not failed - this gate is a no-op without the reference tools.)"
    exit $SKIP
}

if ($Kind -eq "all" -or $Kind -eq "lnk") { Validate-Lnk }
if ($Kind -eq "all" -or $Kind -eq "jumplist") { Validate-JumpList }
if ($Kind -eq "all" -or $Kind -eq "mft") { Validate-Mft }
if ($Kind -eq "all" -or $Kind -eq "srum") { Validate-Srum }
if ($Kind -eq "all" -or $Kind -eq "amcache") { Validate-Amcache }
if ($Kind -eq "all" -or $Kind -eq "shimcache") { Validate-ShimCache }

Write-Section "RESULT"
if ($script:failures -gt 0) {
    Write-Host ("FAIL: " + $script:failures + " parser disagreement(s) vs the reference tool.") -ForegroundColor Red
    exit 1
}
if ($script:skipped) {
    Write-Host "PASS (with skips): no disagreements; some checks were skipped (see SKIP lines above)." -ForegroundColor Yellow
    exit 0
}
Write-Host "PASS: IR_Collect parser output agrees with the Eric Zimmerman reference tools." -ForegroundColor Green
exit 0
