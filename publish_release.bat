@echo off
setlocal
cd /d "%~dp0"
REM Package IR_Collect.exe into dist\IR_Collect_vX.Y.Z.zip (version from docs\SPEC.md).
REM Optional: add -Publish to create/update GitHub Release via "gh" (run "gh auth login" first).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\PackageRelease.ps1" %*
if errorlevel 1 exit /b 1
exit /b 0
