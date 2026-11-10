@echo off
setlocal
set "WPS_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "WPS_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if "%~1"=="" (
 "%WPS_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Online.ps1"
) else (
 "%WPS_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Online.ps1" -Installer "%~1"
)
echo.
pause
