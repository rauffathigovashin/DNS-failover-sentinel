@echo off
chcp 65001 > nul
title DNS Shield Pro - Executable Builder
cd /d "%~dp0"
echo ========================================================
echo   🔨 BUILDING DNS SHIELD PRO STANDALONE EXECUTABLE
echo ========================================================

python -m PyInstaller --clean DNS_Shield_Pro.spec

if %errorLevel% == 0 (
    echo.
    echo ========================================================
    echo   ✅ BUILD SUCCESSFUL!
    echo   Output executable located at: dist\DNS_Shield_Pro.exe
    echo ========================================================
) else (
    echo.
    echo ❌ Build failed with error code %errorLevel%
)

pause
