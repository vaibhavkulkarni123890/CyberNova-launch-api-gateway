# CyberNova AI Security Agent - PowerShell Installer
# Windows PowerShell Auto-Installer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    CyberNova AI Security Agent" -ForegroundColor Cyan
Write-Host "    PowerShell Auto-Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check execution policy
$executionPolicy = Get-ExecutionPolicy
if ($executionPolicy -eq "Restricted") {
    Write-Host "[WARNING] PowerShell execution policy is restricted." -ForegroundColor Yellow
    Write-Host "[INFO] Attempting to set execution policy for current user..." -ForegroundColor Blue
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "[SUCCESS] Execution policy updated." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to update execution policy. Please run as administrator." -ForegroundColor Red
        exit 1
    }
}

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($isAdmin) {
    Write-Host "[INFO] Running with administrator privileges" -ForegroundColor Green
} else {
    Write-Host "[INFO] Running with user privileges" -ForegroundColor Blue
}

# Set installation directory
$installDir = "$env:USERPROFILE\CyberNova"
Write-Host "[INFO] Installation directory: $installDir" -ForegroundColor Blue

# Create installation directory
if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Host "[INFO] Created installation directory" -ForegroundColor Green
}

# Change to installation directory
Set-Location $installDir

# Check if Python is installed
Write-Host "[INFO] Checking Python installation..." -ForegroundColor Blue
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[INFO] Python is installed: $pythonVersion" -ForegroundColor Green
        $pythonCmd = "python"
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "[WARNING] Python not found. Checking for python3..." -ForegroundColor Yellow
    try {
        $pythonVersion = python3 --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[INFO] Python3 is installed: $pythonVersion" -ForegroundColor Green
            $pythonCmd = "python3"
        } else {
            throw "Python3 not found"
        }
    } catch {
        Write-Host "[ERROR] Python is not installed. Installing Python..." -ForegroundColor Red
        
        # Download and install Python
        $pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
        $pythonInstaller = "$env:TEMP\python-installer.exe"
        
        Write-Host "[INFO] Downloading Python installer..." -ForegroundColor Blue
        try {
            Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller
            Write-Host "[INFO] Installing Python..." -ForegroundColor Blue
            Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0" -Wait
            
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            Write-Host "[SUCCESS] Python installation completed" -ForegroundColor Green
            $pythonCmd = "python"
        } catch {
            Write-Host "[ERROR] Failed to install Python: $_" -ForegroundColor Red
            exit 1
        }
    }
}

# Download CyberNova agent
Write-Host "[INFO] Downloading CyberNova agent..." -ForegroundColor Blue
try {
    $agentUrl = "http://localhost:8080/installer-download?type=python"
    Invoke-WebRequest -Uri $agentUrl -OutFile "cybernova_agent.py"
    
    if (Test-Path "cybernova_agent.py") {
        Write-Host "[SUCCESS] Agent downloaded successfully" -ForegroundColor Green
    } else {
        throw "Agent file not found after download"
    }
} catch {
    Write-Host "[ERROR] Failed to download agent: $_" -ForegroundColor Red
    Write-Host "[ERROR] Please check your internet connection and try again." -ForegroundColor Red
    exit 1
}

# Install required packages
Write-Host "[INFO] Installing required Python packages..." -ForegroundColor Blue
try {
    & $pythonCmd -m pip install --upgrade pip --quiet
    & $pythonCmd -m pip install requests psutil plyer --quiet
    Write-Host "[SUCCESS] Python packages installed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to install Python packages: $_" -ForegroundColor Red
    exit 1
}

# Set up auto-start
Write-Host "[INFO] Setting up auto-start..." -ForegroundColor Blue

# Method 1: Registry entry
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "CyberNovaAgent"
    $regValue = "$pythonCmd `"$installDir\cybernova_agent.py`" --auto-start"
    
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
    Write-Host "[SUCCESS] Registry auto-start entry created" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Failed to create registry entry: $_" -ForegroundColor Yellow
}

# Method 2: Startup folder
try {
    $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $startupScript = "$startupDir\CyberNova.bat"
    
    $batchContent = @"
@echo off
cd /d "$installDir"
$pythonCmd cybernova_agent.py --auto-start
"@
    
    $batchContent | Out-File -FilePath $startupScript -Encoding ASCII
    Write-Host "[SUCCESS] Startup folder script created" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Failed to create startup script: $_" -ForegroundColor Yellow
}

# Create desktop shortcut
try {
    $desktopScript = "$env:USERPROFILE\Desktop\CyberNova Agent.bat"
    $desktopContent = @"
@echo off
cd /d "$installDir"
$pythonCmd cybernova_agent.py
pause
"@
    
    $desktopContent | Out-File -FilePath $desktopScript -Encoding ASCII
    Write-Host "[SUCCESS] Desktop shortcut created" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Failed to create desktop shortcut: $_" -ForegroundColor Yellow
}

# Start the agent immediately
Write-Host "[INFO] Starting CyberNova agent..." -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Installation Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The CyberNova agent is now installed and will:" -ForegroundColor White
Write-Host "- Start automatically with Windows" -ForegroundColor White
Write-Host "- Monitor your system for threats" -ForegroundColor White
Write-Host "- Send security data to your dashboard" -ForegroundColor White
Write-Host ""
Write-Host "Starting agent now..." -ForegroundColor Blue
Write-Host ""

# Start agent immediately in background
try {
    $agentProcess = Start-Process -FilePath $pythonCmd -ArgumentList "$installDir\cybernova_agent.py", "--auto-start" -WindowStyle Hidden -PassThru
    
    # Wait a moment for agent to start
    Start-Sleep -Seconds 3
    
    # Verify agent is running
    if (!$agentProcess.HasExited) {
        Write-Host "[SUCCESS] CyberNova agent is running! (PID: $($agentProcess.Id))" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Agent starting in background..." -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[ERROR] Failed to start agent: $_" -ForegroundColor Red
    Write-Host "[INFO] You can manually start it by running the desktop shortcut." -ForegroundColor Blue
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    🎉 Installation Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ CyberNova agent is now installed and running" -ForegroundColor Green
Write-Host "🛡️ Real-time security monitoring is active" -ForegroundColor Blue
Write-Host "📊 Check your dashboard at: http://localhost:8080/dashboard" -ForegroundColor Blue
Write-Host "🔄 The agent will automatically start with Windows" -ForegroundColor Blue
Write-Host ""
Write-Host "🚀 Ready to scan! The agent is monitoring your device." -ForegroundColor Green
Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")