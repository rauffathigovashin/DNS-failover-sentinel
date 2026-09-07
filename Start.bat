@echo off
chcp 65001 > nul
title DNS Shield Pro Launcher

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~dp0Start.bat' -Verb RunAs"
    exit /b
)

:admin
cd /d "%~dp0"
echo ========================================================
echo   🛡️ DNS SHIELD PRO - AUTOMATED DNS SENTINEL
echo ========================================================

:: Check for pythonw / python
where pythonw >nul 2>&1
if %errorLevel% == 0 (
    start "" pythonw "main.py"
) else (
    start "" python "main.py"
)

exit
