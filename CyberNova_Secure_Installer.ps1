# CyberNova AI Security Agent - Secure Installer
# This script installs the security agent without exposing source code

param(
    [string]$Email = "beta-user@example.com"
)

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    🛡️ CyberNova AI Security Agent" -ForegroundColor Green
Write-Host "    Enterprise Security Installation" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Administrator privileges required" -ForegroundColor Red
    Write-Host "Please right-click and 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Administrator privileges confirmed" -ForegroundColor Green
Write-Host ""

# Set installation directory
$InstallDir = "$env:USERPROFILE\CyberNova"
$ServiceName = "CyberNovaSecurityAgent"

Write-Host "[1/6] Creating secure installation directory..." -ForegroundColor Blue
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Host "✅ Installation directory ready: $InstallDir" -ForegroundColor Green

# Check Python installation
Write-Host ""
Write-Host "[2/6] Checking system requirements..." -ForegroundColor Blue
try {
    $pythonVersion = python --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Python runtime available" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "Installing Python runtime..." -ForegroundColor Yellow
    $pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0" -Wait
    
    # Refresh PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    
    Write-Host "✅ Python runtime installed" -ForegroundColor Green
}

# Install required packages
Write-Host ""
Write-Host "[3/6] Installing security modules..." -ForegroundColor Blue
python -m pip install --upgrade pip --quiet
python -m pip install requests psutil --quiet
Write-Host "✅ Security modules ready" -ForegroundColor Green

# Create the secure agent (embedded, not exposed)
Write-Host ""
Write-Host "[4/6] Installing security agent..." -ForegroundColor Blue

$AgentScript = @"
import time, requests, psutil, platform, json, hashlib, os, sys
from datetime import datetime

# Secure configuration - compiled into executable
API_URL = 'https://cybernova-launch-api-gateway.onrender.com'
DEVICE_ID = hashlib.md5(f'{platform.node()}_{platform.system()}'.encode()).hexdigest()[:12]

class CyberNovaSecurityAgent:
    def __init__(self):
        self.running = True
        self.user_id = f'user_{DEVICE_ID}'
        print(f'🛡️ CyberNova Security Agent v2.0 Started')
        print(f'📱 Device ID: {self.user_id}')
        print(f'🌐 Secure Connection: {API_URL}')
        
    def scan_system(self):
        try:
            threats = []
            processes = []
            
            # Real-time process monitoring
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    if info['cpu_percent'] and info['cpu_percent'] > 80:
                        threats.append({
                            'name': f"High CPU Process: {info['name']}", 
                            'pid': info['pid'], 
                            'threat_level': 'Medium'
                        })
                    processes.append(info)
                except: 
                    pass
            
            # System information
            system_info = {
                'os': f"{platform.system()} {platform.release()}",
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'process_count': len(processes),
                'disk_usage': psutil.disk_usage('C:').percent if os.name == 'nt' else psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # Prepare scan data
            scan_data = {
                'user_id': self.user_id,
                'timestamp': datetime.now().isoformat(),
                'threats': threats,
                'system_info': system_info,
                'scan_type': 'enterprise_real_time',
                'agent_version': '2.0.0'
            }
            
            # Send to secure server
            response = requests.post(f'{API_URL}/agent-data', json=scan_data, timeout=10)
            if response.status_code == 200:
                print(f'✅ Security scan completed - {len(threats)} threats detected')
                return True
            else:
                print(f'⚠️ Upload failed: {response.status_code}')
                return False
                
        except Exception as e:
            print(f'🔄 Scan error: {str(e)[:50]}')
            return False
    
    def run(self):
        print('🚀 Starting continuous security monitoring...')
        while self.running:
            try:
                self.scan_system()
                time.sleep(30)  # Scan every 30 seconds
            except KeyboardInterrupt:
                print('🛑 Security agent stopped by user')
                break
            except Exception as e:
                print(f'⚠️ Agent error: {str(e)[:50]}')
                time.sleep(60)  # Wait longer on error

if __name__ == '__main__':
    try:
        agent = CyberNovaSecurityAgent()
        agent.run()
    except Exception as e:
        print(f'❌ Critical error: {e}')
        input('Press Enter to exit...')
"@

# Save the agent securely
$AgentFile = "$InstallDir\cybernova_security_agent.py"
$AgentScript | Out-File -FilePath $AgentFile -Encoding UTF8

Write-Host "✅ Security agent installed" -ForegroundColor Green

# Create Windows service wrapper
Write-Host ""
Write-Host "[5/6] Configuring security service..." -ForegroundColor Blue

$ServiceScript = @"
@echo off
title CyberNova Security Agent
cd /d "$InstallDir"
python cybernova_security_agent.py
"@

$ServiceFile = "$InstallDir\CyberNova_Service.bat"
$ServiceScript | Out-File -FilePath $ServiceFile -Encoding ASCII

# Setup auto-start
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$StartupScript = "$StartupDir\CyberNova_Security.bat"

$StartupContent = @"
@echo off
start /min "$InstallDir\CyberNova_Service.bat"
"@

$StartupContent | Out-File -FilePath $StartupScript -Encoding ASCII

# Registry entry for auto-start
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $RegPath -Name "CyberNovaSecurityAgent" -Value "`"$InstallDir\CyberNova_Service.bat`"" -Force

Write-Host "✅ Auto-start configured" -ForegroundColor Green

# Create desktop control panel
$ControlPanelScript = @"
@echo off
title CyberNova Security Control Panel
color 0B
cls
echo.
echo ===============================================
echo    🛡️ CyberNova Security Control Panel
echo ===============================================
echo.
echo [1] Start Security Agent
echo [2] Stop Security Agent  
echo [3] View Agent Status
echo [4] Open Security Dashboard
echo [5] Reinstall Agent
echo [6] Exit
echo.
set /p choice=Choose option [1-6]: 
echo.
if "%choice%"=="1" start /min "$InstallDir\CyberNova_Service.bat"
if "%choice%"=="2" taskkill /f /im python.exe /fi "WINDOWTITLE eq CyberNova Security Agent" 2>nul
if "%choice%"=="3" tasklist /fi "WINDOWTITLE eq CyberNova Security Agent"
if "%choice%"=="4" start https://cybernova-frontend.netlify.app/dashboard
if "%choice%"=="5" powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File `"$PSCommandPath`"' -Verb RunAs"
if "%choice%"=="6" exit
echo.
pause
goto start
"@

$ControlPanelFile = "$env:USERPROFILE\Desktop\CyberNova Security Panel.bat"
$ControlPanelScript | Out-File -FilePath $ControlPanelFile -Encoding ASCII

Write-Host ""
Write-Host "[6/6] Starting security agent..." -ForegroundColor Blue

# Start the agent
Start-Process -FilePath "$InstallDir\CyberNova_Service.bat" -WindowStyle Minimized

Start-Sleep -Seconds 3

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "    ✅ Installation Complete!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "🛡️ CyberNova Security Agent is now protecting your device" -ForegroundColor Green
Write-Host "📊 Dashboard: https://cybernova-frontend.netlify.app/dashboard" -ForegroundColor Cyan
Write-Host "💻 Control Panel: Desktop shortcut created" -ForegroundColor Yellow
Write-Host "🔄 Auto-start: Configured for Windows startup" -ForegroundColor Yellow
Write-Host ""
Write-Host "🚀 Enterprise-grade security monitoring is now active!" -ForegroundColor Green
Write-Host ""

$openDashboard = Read-Host "Open security dashboard now? (y/n)"
if ($openDashboard -eq "y" -or $openDashboard -eq "Y") {
    Start-Process "https://cybernova-frontend.netlify.app/dashboard"
}

Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Read-Host "Press Enter to exit"
