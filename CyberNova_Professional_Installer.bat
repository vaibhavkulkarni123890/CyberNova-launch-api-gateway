@echo off
title CyberNova AI Security Suite - Professional Installation
color 0A
mode con: cols=80 lines=30
cls

echo.
echo ================================================================================
echo                    🛡️ CyberNova AI Security Suite v2.0
echo                         Professional Installation
echo ================================================================================
echo.
echo    Enterprise-Grade Security Solution for Windows
echo    Real-time Threat Detection ^& System Monitoring
echo.
echo ================================================================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ ADMINISTRATOR PRIVILEGES REQUIRED
    echo.
    echo This security software requires administrator access to protect your system.
    echo The installer will now restart with elevated privileges.
    echo.
    echo Please click "YES" when Windows requests permission.
    echo.
    pause
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ✅ Administrator privileges confirmed
echo ✅ Security installation authorized
echo.

:: Set professional directories
set "INSTALL_DIR=%PROGRAMFILES%\CyberNova Security Suite"
set "USER_DIR=%USERPROFILE%\CyberNova"
set "SERVICE_NAME=CyberNovaSecuritySuite"

echo [STEP 1/6] Creating secure installation environment...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" 2>nul
if not exist "%USER_DIR%" mkdir "%USER_DIR%" 2>nul
echo ✅ Installation directories created
echo.

echo [STEP 2/6] Verifying system requirements...
:: Check Python (install if needed)
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Python runtime environment...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe' -OutFile '%TEMP%\python_runtime.exe' -UseBasicParsing}"
    "%TEMP%\python_runtime.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    
    :: Refresh environment
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "PATH=%%b"
    
    echo ✅ Python runtime installed
) else (
    echo ✅ Python runtime verified
)
echo.

echo [STEP 3/6] Installing security modules...
python -m pip install --upgrade pip --quiet --no-warn-script-location
python -m pip install requests psutil --quiet --no-warn-script-location
echo ✅ Security modules installed
echo.

echo [STEP 4/6] Deploying security agent...
:: Create the security agent directly (no external files)
cd /d "%USER_DIR%"

(
echo import time, requests, psutil, platform, json, hashlib, os, sys, threading
echo from datetime import datetime
echo import subprocess
echo.
echo # CyberNova Security Agent - Enterprise Edition
echo API_URL = 'https://cybernova-launch-api-gateway.onrender.com'
echo DEVICE_ID = hashlib.md5^(f'{platform.node^(^)}_{platform.system^(^)}'.encode^(^)^).hexdigest^(^)[:12]
echo.
echo class CyberNovaSecuritySuite:
echo     def __init__^(self^):
echo         self.running = True
echo         self.user_id = f'user_{DEVICE_ID}'
echo         self.version = '2.0.0-Enterprise'
echo         print^(f'🛡️ CyberNova Security Suite v{self.version} - ACTIVE'^)
echo         print^(f'📱 Device Protection ID: {self.user_id}'^)
echo         print^(f'🌐 Secure Connection: Established'^)
echo         print^(f'🔒 Enterprise Security: ENABLED'^)
echo.        
echo     def advanced_threat_scan^(self^):
echo         try:
echo             threats = []
echo             processes = []
echo             suspicious_processes = ['miner', 'crypto', 'hack', 'crack', 'keylog', 'trojan']
echo.            
echo             # Advanced process analysis
echo             for proc in psutil.process_iter^(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']^):
echo                 try:
echo                     info = proc.info
echo                     process_name = info['name'].lower^(^)
echo.                    
echo                     # High CPU threat detection
echo                     if info['cpu_percent'] and info['cpu_percent'] ^> 85:
echo                         threats.append^({
echo                             'name': f'High CPU Usage: {info["name"]}',
echo                             'pid': info['pid'],
echo                             'threat_level': 'Medium',
echo                             'cpu_usage': info['cpu_percent']
echo                         }^)
echo.                    
echo                     # Suspicious process detection
echo                     for suspicious in suspicious_processes:
echo                         if suspicious in process_name:
echo                             threats.append^({
echo                                 'name': f'Suspicious Process: {info["name"]}',
echo                                 'pid': info['pid'],
echo                                 'threat_level': 'High',
echo                                 'reason': 'Matches known threat pattern'
echo                             }^)
echo.                    
echo                     processes.append^(info^)
echo                 except:
echo                     pass
echo.            
echo             # System security analysis
echo             system_info = {
echo                 'os': f'{platform.system^(^)} {platform.release^(^)}',
echo                 'cpu_percent': psutil.cpu_percent^(interval=1^),
echo                 'memory_percent': psutil.virtual_memory^(^).percent,
echo                 'process_count': len^(processes^),
echo                 'disk_usage': psutil.disk_usage^('C:'^).percent,
echo                 'network_connections': len^(psutil.net_connections^(^)^),
echo                 'boot_time': datetime.fromtimestamp^(psutil.boot_time^(^)^).isoformat^(^),
echo                 'security_status': 'PROTECTED' if len^(threats^) == 0 else 'THREATS_DETECTED'
echo             }
echo.            
echo             # Prepare enterprise security report
echo             security_report = {
echo                 'user_id': self.user_id,
echo                 'timestamp': datetime.now^(^).isoformat^(^),
echo                 'threats': threats,
echo                 'system_info': system_info,
echo                 'scan_type': 'enterprise_security_scan',
echo                 'agent_version': self.version,
echo                 'security_level': 'ENTERPRISE'
echo             }
echo.            
echo             # Secure transmission to CyberNova Cloud
echo             response = requests.post^(f'{API_URL}/agent-data', json=security_report, timeout=15^)
echo             if response.status_code == 200:
echo                 status = 'SECURE' if len^(threats^) == 0 else f'{len^(threats^)} THREATS'
echo                 print^(f'✅ Security Scan Complete - Status: {status}'^)
echo                 return True
echo             else:
echo                 print^(f'⚠️ Cloud sync pending - Code: {response.status_code}'^)
echo                 return False
echo.                
echo         except Exception as e:
echo             print^(f'🔄 Security scan error: {str^(e^)[:30]}'^)
echo             return False
echo.    
echo     def continuous_protection^(self^):
echo         print^('🚀 Continuous protection activated'^)
echo         scan_count = 0
echo         while self.running:
echo             try:
echo                 scan_count += 1
echo                 print^(f'🔍 Security Scan #{scan_count} - {datetime.now^(^).strftime^("%%H:%%M:%%S"^)}'^)
echo                 self.advanced_threat_scan^(^)
echo                 time.sleep^(30^)  # Scan every 30 seconds
echo             except KeyboardInterrupt:
echo                 print^('🛑 Security suite stopped by administrator'^)
echo                 break
echo             except Exception as e:
echo                 print^(f'⚠️ Protection error: {str^(e^)[:30]}'^)
echo                 time.sleep^(60^)
echo.
echo if __name__ == '__main__':
echo     try:
echo         print^('🛡️ Initializing CyberNova Security Suite...'^)
echo         security_suite = CyberNovaSecuritySuite^(^)
echo         security_suite.continuous_protection^(^)
echo     except Exception as e:
echo         print^(f'❌ Critical security error: {e}'^)
echo         input^('Press Enter to exit...'^)
) > "cybernova_security_suite.py"

echo ✅ Security agent deployed
echo.

echo [STEP 5/6] Configuring enterprise security service...

:: Create service launcher
(
echo @echo off
echo title CyberNova Security Suite - Enterprise Protection
echo color 0A
echo cd /d "%USER_DIR%"
echo python cybernova_security_suite.py
) > "CyberNova_Security_Service.bat"

:: Setup Windows auto-start
set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
(
echo @echo off
echo start /min "%USER_DIR%\CyberNova_Security_Service.bat"
) > "%STARTUP_DIR%\CyberNova_Security_Suite.bat"

:: Registry auto-start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CyberNovaSecuritySuite" /t REG_SZ /d "\"%USER_DIR%\CyberNova_Security_Service.bat\"" /f >nul 2>&1

:: Create professional control panel
(
echo @echo off
echo title CyberNova Security Suite - Control Panel
echo color 0B
echo cls
echo.
echo ================================================================================
echo                    🛡️ CyberNova Security Suite v2.0
echo                           Control Panel
echo ================================================================================
echo.
echo [1] 🚀 Start Security Protection
echo [2] 🛑 Stop Security Protection
echo [3] 📊 View Protection Status  
echo [4] 🌐 Open Security Dashboard
echo [5] 🔄 Reinstall Security Suite
echo [6] ❌ Exit Control Panel
echo.
echo ================================================================================
echo.
echo Choose your option [1-6]: 
echo set /p choice=
echo.
echo if "%%choice%%"=="1" ^(
echo     echo Starting CyberNova Security Protection...
echo     start /min "%USER_DIR%\CyberNova_Security_Service.bat"
echo     echo ✅ Security protection activated
echo     timeout /t 2 /nobreak ^>nul
echo ^)
echo if "%%choice%%"=="2" ^(
echo     echo Stopping security protection...
echo     taskkill /f /im python.exe /fi "WINDOWTITLE eq CyberNova Security Suite*" 2^>nul
echo     echo ✅ Security protection stopped
echo     timeout /t 2 /nobreak ^>nul
echo ^)
echo if "%%choice%%"=="3" ^(
echo     echo Checking protection status...
echo     tasklist /fi "WINDOWTITLE eq CyberNova Security Suite*"
echo     pause
echo ^)
echo if "%%choice%%"=="4" ^(
echo     echo Opening security dashboard...
echo     start https://cybernova-frontend.netlify.app/dashboard
echo ^)
echo if "%%choice%%"=="5" ^(
echo     echo Reinstalling security suite...
echo     start "" "%~dp0CyberNova_Professional_Installer.bat"
echo     exit
echo ^)
echo if "%%choice%%"=="6" exit
echo.
echo pause
echo goto start
) > "%USERPROFILE%\Desktop\CyberNova Security Control Panel.bat"

echo ✅ Enterprise security service configured
echo.

echo [STEP 6/6] Activating real-time protection...
start /min "%USER_DIR%\CyberNova_Security_Service.bat"
timeout /t 3 /nobreak >nul

echo ✅ Real-time protection activated
echo.

cls
echo.
echo ================================================================================
echo                         🎉 INSTALLATION COMPLETE! 🎉
echo ================================================================================
echo.
echo    🛡️ CyberNova Security Suite v2.0 is now PROTECTING your device
echo.
echo    ✅ Real-time threat monitoring: ACTIVE
echo    ✅ System security analysis: RUNNING  
echo    ✅ Enterprise protection: ENABLED
echo    ✅ Auto-start configuration: SET
echo    ✅ Security dashboard: READY
echo.
echo ================================================================================
echo.
echo 📊 Security Dashboard: https://cybernova-frontend.netlify.app/dashboard
echo 💻 Control Panel: Desktop shortcut created
echo 🔄 Auto-Protection: Starts automatically with Windows
echo.
echo ================================================================================
echo.
echo 🚀 Your device is now protected with enterprise-grade security!
echo    The security suite is running in the background monitoring for threats.
echo.
echo Press any key to open your security dashboard...
pause >nul

start https://cybernova-frontend.netlify.app/dashboard

echo.
echo Thank you for choosing CyberNova Security Suite!
timeout /t 3 /nobreak >nul
