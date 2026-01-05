@echo off
setlocal

REM Adjust if you want a different window for event log reporting:
set DaysToCheck=30

REM Run the PowerShell script from the same folder as this BAT
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0wks_health_v1.2.ps1" -DaysToCheck %DaysToCheck%

echo.
echo Done. Press any key to close this window.
pause >nul