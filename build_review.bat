@echo off
setlocal
cd /d "%~dp0"

set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "TARGET_EXE=IR_Collect_review.exe"

if not exist "%CSC%" (
    echo [!] csc.exe not found at %CSC%
    exit /b 1
)

echo [+] Compiling %TARGET_EXE% with INCLUDE_TESTS (does not overwrite IR_Collect.exe^)...
"%CSC%" /nologo /define:INCLUDE_TESTS /out:%TARGET_EXE% @build_common.rsp src\Tests\IRCollectSelfTests.cs src\Tests\FixtureCorpus.cs
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

if not exist "%TARGET_EXE%" (
    echo [!] Build did not produce %TARGET_EXE%.
    exit /b 1
)

echo [+] Build successful: %TARGET_EXE%
exit /b 0
