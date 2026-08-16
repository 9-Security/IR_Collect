@echo off
setlocal
cd /d "%~dp0"

set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "RELEASE_EXE=9SEC_EvidW.exe"
set "RELEASE_STAGE_DIR=%~dp0.release-stage"
set "RELEASE_STAGE_EXE=%RELEASE_STAGE_DIR%\%RELEASE_EXE%"

if not exist "%CSC%" (
    echo [!] csc.exe not found at %CSC%
    exit /b 1
)

echo [+] [1/2] Compiling release build...
if exist "%RELEASE_STAGE_DIR%" rmdir /s /q "%RELEASE_STAGE_DIR%" >nul 2>&1
mkdir "%RELEASE_STAGE_DIR%"
if errorlevel 1 (
    echo [!] Failed to create release staging directory.
    exit /b 1
)

"%CSC%" /out:"%RELEASE_STAGE_EXE%" @build_common.rsp
if errorlevel 1 (
    echo [!] Release build failed.
    goto :ReleaseFailed
)

if not exist "%RELEASE_STAGE_EXE%" (
    echo [!] Release build did not produce %RELEASE_STAGE_EXE%.
    goto :ReleaseFailed
)

echo [+] [2/2] Signing release candidate...
call :SignFile "%RELEASE_STAGE_EXE%" "release candidate"
if errorlevel 1 goto :ReleaseFailed

move /Y "%RELEASE_STAGE_EXE%" "%RELEASE_EXE%" >nul
if errorlevel 1 (
    echo [!] Failed to promote %RELEASE_STAGE_EXE% to %RELEASE_EXE%.
    goto :ReleaseFailed
)
rmdir /s /q "%RELEASE_STAGE_DIR%" >nul 2>&1
if exist "9SEC_Evidence_Workbench.exe" del /q "9SEC_Evidence_Workbench.exe" >nul 2>&1
if exist "9SEC_Evidence_Workbench_review.exe" del /q "9SEC_Evidence_Workbench_review.exe" >nul 2>&1
if exist "9SEC_Evidence_Workbench_release_candidate.exe" del /q "9SEC_Evidence_Workbench_release_candidate.exe" >nul 2>&1

echo [+] Release gate complete.
echo [+] Release build: %RELEASE_EXE%
exit /b 0

:ReleaseFailed
if exist "%RELEASE_STAGE_DIR%" rmdir /s /q "%RELEASE_STAGE_DIR%" >nul 2>&1
exit /b 1

:SignFile
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\SignLocalBuild.ps1" -TargetPath "%~1" -Label "%~2" -RequireSignature -RequireTimestamp
if errorlevel 1 (
    echo [!] Signing failed for %~2.
    exit /b 1
)
exit /b 0
