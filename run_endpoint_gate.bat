@echo off
setlocal
cd /d "%~dp0"

echo [+] Reasonable endpoint gate: review build + regression + production build

call run_review_regression.bat
if errorlevel 1 (
    echo [!] Review regression gate failed.
    exit /b 1
)

call build.bat
if errorlevel 1 (
    echo [!] Production build gate failed.
    exit /b 1
)

echo [+] Endpoint gate passed.
exit /b 0
