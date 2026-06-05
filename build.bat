@echo off
setlocal
cd /d "%~dp0"

set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "TARGET_EXE=IR_Collect.exe"

if not exist "%CSC%" (
    echo [!] csc.exe not found at %CSC%
    exit /b 1
)

echo [+] Compiling IR_Collect...
"%CSC%" /out:%TARGET_EXE% @build_common.rsp
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

if not exist "%TARGET_EXE%" (
    echo [!] Build did not produce %TARGET_EXE%.
    exit /b 1
)

echo [+] Build successful.
powershell -NoProfile -Command "Start-Sleep -Seconds 2"

call :SignFile "%TARGET_EXE%" "local build"
if errorlevel 1 exit /b 1

echo [+] You can run: %TARGET_EXE%
exit /b 0

:SignFile
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\SignLocalBuild.ps1" -TargetPath "%~1" -Label "%~2"
if errorlevel 1 (
    echo [!] Signing failed for %~2.
    exit /b 1
)
exit /b 0
