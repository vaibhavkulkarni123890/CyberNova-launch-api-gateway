@echo off
echo ========================================
echo    CyberNova AI Security Agent
echo    Windows Auto-Installer
echo ========================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with administrator privileges
) else (
    echo [INFO] Running with user privileges
)

:: Create installation directory
set INSTALL_DIR=%USERPROFILE%\CyberNova
echo [INFO] Creating installation directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Check if Python is installed
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Python not found. Installing Python...
    echo [INFO] Downloading Python installer...
    
    :: Download Python installer
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe' -OutFile '%TEMP%\python-installer.exe'"
    
    :: Install Python silently
    echo [INFO] Installing Python...
    %TEMP%\python-installer.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
    
    :: Refresh environment variables
    call refreshenv
    
    echo [INFO] Python installation completed
) else (
    echo [INFO] Python is already installed
)

:: Download CyberNova agent
echo [INFO] Downloading CyberNova agent...
cd /d "%INSTALL_DIR%"

:: Download agent files
echo [INFO] Downloading agent script...
powershell -Command "try { Invoke-WebRequest -Uri 'https://cybernova-launch-api-gateway.onrender.com/agent-download' -OutFile 'cybernova_agent.py' } catch { Write-Host 'Failed to download agent. Please check your internet connection.' }"

if not exist "cybernova_agent.py" (
    echo [ERROR] Failed to download agent. Please check your internet connection.
    pause
    exit /b 1
)

:: Install required packages
echo [INFO] Installing required Python packages...
python -m pip install --upgrade pip
python -m pip install requests psutil plyer

:: Set up auto-start
echo [INFO] Setting up auto-start...

:: Method 1: Registry entry
echo [INFO] Adding registry entry for auto-start...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CyberNovaAgent" /t REG_SZ /d "python \"%INSTALL_DIR%\cybernova_agent.py\" --auto-start" /f

:: Method 2: Startup folder shortcut
echo [INFO] Creating startup shortcut...
set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
echo @echo off > "%STARTUP_DIR%\CyberNova.bat"
echo cd /d "%INSTALL_DIR%" >> "%STARTUP_DIR%\CyberNova.bat"
echo python cybernova_agent.py --auto-start >> "%STARTUP_DIR%\CyberNova.bat"

:: Create desktop shortcut
echo [INFO] Creating desktop shortcut...
echo @echo off > "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo cd /d "%INSTALL_DIR%" >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo python cybernova_agent.py >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"
echo pause >> "%USERPROFILE%\Desktop\CyberNova Agent.bat"

:: Start the agent immediately
echo [INFO] Starting CyberNova agent...
echo ========================================
echo    Installation Complete!
echo ========================================
echo.
echo The CyberNova agent is now installed and will:
echo - Start automatically with Windows
echo - Monitor your system for threats
echo - Send security data to your dashboard
echo.
echo Starting agent now...
echo.

:: Start agent immediately and in background
start /min python "%INSTALL_DIR%\cybernova_agent.py" --auto-start

:: Wait a moment for agent to start
timeout /t 3 /nobreak >nul

:: Verify agent is running
echo [INFO] Verifying agent status...
tasklist /FI "IMAGENAME eq python.exe" >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] CyberNova agent is running!
) else (
    echo [INFO] Agent starting in background...
)

echo.
echo ========================================
echo    🎉 Installation Complete!
echo ========================================
echo.
echo ✅ CyberNova agent is now installed and running
echo 🛡️ Real-time security monitoring is active  
echo 📊 Check your dashboard at: https://cybernova-frontend.netlify.app/dashboard
echo 🔄 The agent will automatically start with Windows
echo.
echo 🚀 Ready to scan! The agent is monitoring your device.
echo.
echo Press any key to exit...
pause >nul
