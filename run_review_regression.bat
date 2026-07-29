@echo off
setlocal
cd /d "%~dp0"

call build_review.bat
if errorlevel 1 (
    echo [!] Review build failed.
    exit /b 1
)

if not exist "9SEC_Evidence_Workbench_review.exe" (
    echo [!] 9SEC_Evidence_Workbench_review.exe not found after build.
    exit /b 1
)

echo [+] Running built-in regression self-tests...
9SEC_Evidence_Workbench_review.exe -test
set "RC=%ERRORLEVEL%"

if exist "%TEMP%\9SEC_Evidence_Workbench_TestResult.txt" (
    echo [+] Result file: %TEMP%\9SEC_Evidence_Workbench_TestResult.txt
)

if not "%RC%"=="0" (
    echo [!] Regression self-tests failed.
    exit /b %RC%
)

echo [+] Regression self-tests passed.
exit /b 0
