@echo off
setlocal
cd /d "%~dp0"

set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "RELEASE_STAGE_EXE=IR_Collect_release_candidate.exe"
set "RELEASE_EXE=IR_Collect.exe"

if not exist "%CSC%" (
    echo [!] csc.exe not found at %CSC%
    exit /b 1
)

echo [+] [1/2] Compiling release build...
if exist "%RELEASE_STAGE_EXE%" del /q "%RELEASE_STAGE_EXE%" >nul 2>&1
"%CSC%" /out:%RELEASE_STAGE_EXE% @build_common.rsp
if errorlevel 1 (
    echo [!] Release build failed.
    exit /b 1
)

if not exist "%RELEASE_STAGE_EXE%" (
    echo [!] Release build did not produce %RELEASE_STAGE_EXE%.
    exit /b 1
)

echo [+] [2/2] Signing release candidate...
call :SignFile "%RELEASE_STAGE_EXE%" "release candidate"
if errorlevel 1 exit /b 1

move /Y "%RELEASE_STAGE_EXE%" "%RELEASE_EXE%" >nul
if errorlevel 1 (
    echo [!] Failed to promote %RELEASE_STAGE_EXE% to %RELEASE_EXE%.
    exit /b 1
)

echo [+] Release gate complete.
echo [+] Release build: %RELEASE_EXE%
exit /b 0

:SignFile
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\SignLocalBuild.ps1" -TargetPath "%~1" -Label "%~2"
if errorlevel 1 (
    echo [!] Signing failed for %~2.
    exit /b 1
)
exit /b 0
