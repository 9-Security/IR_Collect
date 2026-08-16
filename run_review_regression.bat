@echo off
setlocal
cd /d "%~dp0"
set "REVIEW_EXE=%TEMP%\9SEC_EvidW_review.exe"

call build_review.bat
if errorlevel 1 (
    echo [!] Review build failed.
    exit /b 1
)

if not exist "%REVIEW_EXE%" (
    echo [!] Temporary review executable not found after build: %REVIEW_EXE%
    exit /b 1
)

echo [+] Running built-in regression self-tests...
"%REVIEW_EXE%" -test
set "RC=%ERRORLEVEL%"

if exist "%TEMP%\9SEC_EvidW_TestResult.txt" (
    echo [+] Result file: %TEMP%\9SEC_EvidW_TestResult.txt
)

if exist "%REVIEW_EXE%" del /q "%REVIEW_EXE%" >nul 2>&1

if not "%RC%"=="0" (
    echo [!] Regression self-tests failed.
    exit /b %RC%
)

echo [+] Regression self-tests passed.
exit /b 0
