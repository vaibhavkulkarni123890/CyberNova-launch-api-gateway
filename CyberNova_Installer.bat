@echo off
title CyberNova AI Security Agent - One-Click Installer
color 0A

echo.
echo ========================================
echo    🛡️ CyberNova AI Security Agent
echo    One-Click Windows Installer
echo ========================================
echo.
echo 🚀 Starting automatic installation...
echo.

:: Set installation directory
set INSTALL_DIR=%USERPROFILE%\CyberNova
echo [1/6] Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo ✅ Directory created: %INSTALL_DIR%

:: Check Python
echo.
echo [2/6] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ⚠️ Python not found. Installing Python...
    echo 📥 Downloading Python installer...
    
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe' -OutFile '%TEMP%\python-installer.exe'}"
    
    echo 🔧 Installing Python (this may take a few minutes)...
    "%TEMP%\python-installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
    
    :: Refresh PATH
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "userpath=%%b"
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "systempath=%%b"
    set "PATH=%systempath%;%userpath%"
    
    echo ✅ Python installed successfully
) else (
    echo ✅ Python is already installed
)

:: Download agent
echo.
echo [3/6] Downloading CyberNova agent...
cd /d "%INSTALL_DIR%"
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://cybernova-launch-api-gateway.onrender.com/agent-download' -OutFile 'cybernova_agent.py' -UseBasicParsing } catch { Write-Host 'Download failed:' $_.Exception.Message }}"

if not exist "cybernova_agent.py" (
    echo ❌ Failed to download agent. Please check your internet connection.
    echo 🌐 Make sure you can access: https://cybernova-launch-api-gateway.onrender.com
    pause
    exit /b 1
)
echo ✅ Agent downloaded successfully

:: Install packages
echo.
echo [4/6] Installing required packages...
python -m pip install --upgrade pip --quiet
python -m pip install requests psutil plyer --quiet
echo ✅ Packages installed

:: Setup auto-start
echo.
echo [5/6] Setting up auto-start...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CyberNovaAgent" /t REG_SZ /d "python \"%INSTALL_DIR%\cybernova_agent.py\" --auto-start" /f >nul 2>&1

:: Create startup script
set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
echo @echo off > "%STARTUP_DIR%\CyberNova.bat"
echo cd /d "%INSTALL_DIR%" >> "%STARTUP_DIR%\CyberNova.bat"
echo python cybernova_agent.py --auto-start >> "%STARTUP_DIR%\CyberNova.bat"

:: Create desktop shortcut
echo @echo off > "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo title CyberNova Security Agent >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo cd /d "%INSTALL_DIR%" >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo echo 🛡️ Starting CyberNova Security Agent... >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo python cybernova_agent.py >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo pause >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"

echo ✅ Auto-start configured

:: Start agent
echo.
echo [6/6] Starting CyberNova agent...
start /min python "%INSTALL_DIR%\cybernova_agent.py" --auto-start

:: Wait for agent to start
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo    🎉 Installation Complete!
echo ========================================
echo.
echo ✅ CyberNova agent is now installed and running
echo 🛡️ Real-time security monitoring is ACTIVE
echo 📊 View your dashboard: https://cybernova-frontend.netlify.app/dashboard
echo 🔄 Agent will start automatically with Windows
echo 💻 Desktop shortcut created for manual control
echo.
echo 🚀 Your device is now protected!
echo.
echo The agent is running in the background and will:
echo • Scan for security threats every 30 seconds
echo • Monitor system performance and processes  
echo • Send encrypted data to your secure dashboard
echo • Start automatically when you boot Windows
echo.
echo Press any key to exit this installer...
pause >nul

:: Optional: Open dashboard
set /p choice="Would you like to open your dashboard now? (y/n): "
if /i "%choice%"=="y" start https://cybernova-frontend.netlify.app/dashboard
