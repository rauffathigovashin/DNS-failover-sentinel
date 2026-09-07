@echo off
chcp 65001 > nul
title DNS Shield Pro / DNS Kalkanı Pro - Executable Builder
cd /d "%~dp0"
echo ========================================================
echo   🔨 BUILDING STANDALONE EXECUTABLE (v2.5)
echo ========================================================

:: Close running instances if possible
taskkill /F /IM DNS_Shield_Pro.exe 2>nul
taskkill /F /IM DNS_Kalkani_Pro.exe 2>nul
timeout /t 1 /nobreak >nul

python -m PyInstaller --clean DNS_Shield_Pro.spec

if %errorLevel% == 0 (
    echo.
    echo ========================================================
    echo   ✅ BUILD SUCCESSFUL!
    echo   Output executable located at: dist\DNS_Shield_Pro.exe
    echo ========================================================
) else (
    echo.
    echo ⚠️ Note: If dist\DNS_Shield_Pro.exe is currently locked by a running instance,
    echo    please exit it from your system tray and try again, or use DNS_Kalkani_Pro.exe!
)

pause
