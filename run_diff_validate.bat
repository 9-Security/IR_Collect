@echo off
setlocal
cd /d "%~dp0"

REM Phase 2.2 differential-validation gate: IR_Collect parsers vs Eric Zimmerman tools.
REM Exit 0 = agreed (or cleanly skipped because the EZ tools are absent); nonzero = real disagreement.

if not exist "IR_Collect_review.exe" (
    echo [+] Building review exe first...
    call build_review.bat
    if errorlevel 1 exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File scripts\DiffValidate.ps1 %*
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
    echo [+] Diff validation passed.
    exit /b 0
)
if "%RC%"=="3" (
    echo [i] Diff validation skipped ^(Eric Zimmerman tools not present^) - treated as pass.
    exit /b 0
)
echo [!] Diff validation found parser disagreement^(s^).
exit /b %RC%
