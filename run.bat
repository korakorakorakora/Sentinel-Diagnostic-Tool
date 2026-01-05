@echo off
set "scriptName=sentinel-rcl.ps1"

:: Check if the PowerShell script actually exists in this folder
if not exist "%~dp0%scriptName%" (
    echo [!] ERROR: %scriptName% was not found in this folder!
    echo [!] Make sure you saved the PowerShell script as %scriptName% in:
    echo     %~dp0
    pause
    exit /b
)

:: Check for Administrator permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo [!] Requesting Administrator Permissions...
    powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
    exit /b
)

:: Run the integrity script
echo [!] Launching Tournament Integrity Script...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0%scriptName%"


pause
