@echo off
setlocal
set "WSK_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "WSK_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%WSK_POWERSHELL%" -NoLogo -NoProfile -STA -File "%~dp0Start-WintelSecurityGui.ps1"
set "WSK_EXIT=%ERRORLEVEL%"
if "%WSK_EXIT%"=="0" exit /b 0
echo The GUI could not start. See Docs\STARTUP.md for PowerShell policy and signature checks.
echo To view the bundled example, open Samples\Demo\SecurityAssessment.html in your browser.
pause
exit /b %WSK_EXIT%
