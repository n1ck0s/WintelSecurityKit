@echo off
setlocal
set "WSK_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "WSK_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%WSK_POWERSHELL%" -NoLogo -NoProfile -STA -File "%~dp0Start-WintelSecurityGui.ps1"
if errorlevel 1 pause
endlocal
