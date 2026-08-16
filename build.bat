@echo off
setlocal
cd /d "%~dp0"

set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "LOCAL_BUILD_DIR=%TEMP%\9SEC_EvidW-local-build"
set "TARGET_EXE=%LOCAL_BUILD_DIR%\9SEC_EvidW.exe"

if not exist "%CSC%" (
    echo [!] csc.exe not found at %CSC%
    exit /b 1
)

if not exist "%LOCAL_BUILD_DIR%" mkdir "%LOCAL_BUILD_DIR%"
if errorlevel 1 (
    echo [!] Failed to create local build directory: %LOCAL_BUILD_DIR%
    exit /b 1
)

echo [+] Compiling local build: %TARGET_EXE%...
"%CSC%" /out:"%TARGET_EXE%" @build_common.rsp
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
