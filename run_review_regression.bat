@echo off
setlocal
cd /d "%~dp0"

call build_review.bat
if errorlevel 1 (
    echo [!] Review build failed.
    exit /b 1
)

if not exist "IR_Collect_review.exe" (
    echo [!] IR_Collect_review.exe not found after build.
    exit /b 1
)

echo [+] Running built-in regression self-tests...
IR_Collect_review.exe -test
set "RC=%ERRORLEVEL%"

if exist "%TEMP%\IR_Collect_TestResult.txt" (
    echo [+] Result file: %TEMP%\IR_Collect_TestResult.txt
)

if not "%RC%"=="0" (
    echo [!] Regression self-tests failed.
    exit /b %RC%
)

echo [+] Regression self-tests passed.
exit /b 0
