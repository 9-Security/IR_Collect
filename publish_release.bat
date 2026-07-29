@echo off
setlocal
cd /d "%~dp0"
REM Package 9SEC_Evidence_Workbench.exe into dist\9SEC_Evidence_Workbench_vX.Y.Z.zip (version from docs\SPEC.md).
REM Optional: add -Publish to create/update GitHub Release via "gh" (run "gh auth login" first).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\PackageRelease.ps1" %*
if errorlevel 1 exit /b 1
exit /b 0
