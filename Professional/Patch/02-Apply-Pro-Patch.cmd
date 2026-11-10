@echo off
setlocal
if "%~1"=="" (
 powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Patch-WPSPro.ps1"
) else (
 powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Patch-WPSPro.ps1" -Installer "%~1"
)
set "PATCH_RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %PATCH_RESULT%
