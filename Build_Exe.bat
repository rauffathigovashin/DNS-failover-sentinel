@echo off
title DNS Shield Pro - Executable Builder
cd /d "%~dp0"
echo ========================================================
echo   BUILDING STANDALONE EXECUTABLE (v3.0)
echo ========================================================

:: Close running instances if possible
taskkill /F /IM DNS_Shield_Pro.exe 2>nul
taskkill /F /IM DNS_Kalkani_Pro.exe 2>nul
timeout /t 1 /nobreak >nul

python -m PyInstaller --clean DNS_Shield_Pro.spec

if errorlevel 1 (
    echo.
    echo ========================================================
    echo   [ERROR] Build failed!
    echo   Note: If dist\DNS_Shield_Pro.exe is locked, please exit
    echo   it from your Windows system tray and try again!
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo   [SUCCESS] BUILD COMPLETED!
    echo   Output executable located at: dist\DNS_Shield_Pro.exe
    echo ========================================================
)

pause
