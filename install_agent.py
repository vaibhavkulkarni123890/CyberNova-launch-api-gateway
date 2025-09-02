#!/usr/bin/env python3
"""
CyberNova Agent Installer
Easy installation for CyberNova Security Agent
Compatible with Python 3.8+ (Updated for latest Python versions)
"""

import os
import sys
import shutil
import subprocess
import requests
from pathlib import Path
import platform
from typing import Optional, Union

# Configuration
AGENT_URL = "http://localhost:8080/agent-download"  # Updated for beta testing
INSTALL_DIR_NAME = "CyberNova"

def download_agent(install_dir: Path) -> bool:
    """Download agent from server"""
    try:
        print("📥 Downloading CyberNova Agent...")
        
        response = requests.get(AGENT_URL, timeout=30)
        if response.status_code == 200:
            agent_file = install_dir / "cybernova_agent.py"
            agent_file.write_text(response.text, encoding='utf-8')
            print("✅ Agent downloaded successfully")
            return True
        else:
            print(f"❌ Download failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Download error: {e}")
        return False

def setup_autostart_windows(install_dir: Path) -> bool:
    """Setup Windows auto-start"""
    try:
        startup_dir = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        if not startup_dir.exists():
            print("⚠️ Windows startup folder not found")
            return False
            
        startup_script = startup_dir / "CyberNova.bat"
        startup_content = f'''@echo off
cd /d "{install_dir}"
python cybernova_agent.py
'''
        startup_script.write_text(startup_content, encoding='utf-8')
        print("✅ Windows auto-start configured")
        return True
        
    except Exception as e:
        print(f"❌ Windows setup error: {e}")
        return False

def setup_autostart_macos(install_dir: Path) -> bool:
    """Setup macOS auto-start"""
    try:
        plist_dir = Path.home() / "Library/LaunchAgents"
        plist_dir.mkdir(exist_ok=True)
        
        plist_file = plist_dir / "com.cybernova.agent.plist"
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cybernova.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>python3</string>
        <string>{install_dir}/cybernova_agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>'''
        
        plist_file.write_text(plist_content, encoding='utf-8')
        subprocess.run(["launchctl", "load", str(plist_file)], check=True)
        print("✅ macOS LaunchAgent configured")
        return True
        
    except Exception as e:
        print(f"❌ macOS setup error: {e}")
        return False

def setup_autostart_linux(install_dir: Path) -> bool:
    """Setup Linux auto-start"""
    try:
        service_dir = Path.home() / ".config/systemd/user"
        service_dir.mkdir(parents=True, exist_ok=True)
        
        service_file = service_dir / "cybernova.service"
        service_content = f'''[Unit]
Description=CyberNova Security Agent
After=network.target

[Service]
Type=simple
User={os.getenv('USER')}
ExecStart=python3 {install_dir}/cybernova_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
'''
        
        service_file.write_text(service_content, encoding='utf-8')
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "cybernova.service"], check=True)
        subprocess.run(["systemctl", "--user", "start", "cybernova.service"], check=True)
        print("✅ Linux systemd service configured")
        return True
        
    except Exception as e:
        print(f"❌ Linux setup error: {e}")
        return False

def install_dependencies() -> bool:
    """Install required Python packages"""
    try:
        print("📦 Installing dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests", "psutil"], check=True)
        print("✅ Dependencies installed")
        return True
    except Exception as e:
        print(f"❌ Dependency installation failed: {e}")
        return False

def start_agent(install_dir: Path) -> bool:
    """Start the agent immediately"""
    try:
        agent_file = install_dir / "cybernova_agent.py"
        if agent_file.exists():
            print("🚀 Starting CyberNova Agent...")
            subprocess.Popen([sys.executable, str(agent_file)])
            print("✅ Agent started successfully")
            return True
        else:
            print("❌ Agent file not found")
            return False
    except Exception as e:
        print(f"❌ Start error: {e}")
        return False

def main() -> bool:
    print("🛡️ CyberNova Security Agent Installer")
    print("=====================================")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher required")
        print(f"Current version: {sys.version}")
        return False
    
    # Create installation directory
    install_dir = Path.home() / INSTALL_DIR_NAME
    install_dir.mkdir(exist_ok=True)
    print(f"📁 Installation directory: {install_dir}")
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Download agent
    if not download_agent(install_dir):
        return False
    
    # Setup auto-start based on platform
    system = platform.system().lower()
    autostart_success = False
    
    if system == "windows":
        autostart_success = setup_autostart_windows(install_dir)
    elif system == "darwin":
        autostart_success = setup_autostart_macos(install_dir)
    elif system == "linux":
        autostart_success = setup_autostart_linux(install_dir)
    else:
        print(f"⚠️ Unsupported platform: {system}")
    
    if not autostart_success:
        print("⚠️ Auto-start setup failed, but you can run the agent manually")
    
    # Start agent immediately
    start_agent(install_dir)
    
    print("\n🎉 Installation completed!")
    print("🔍 The agent is now monitoring your device")
    print("🌐 Check your dashboard to see real-time data")
    print(f"📂 Agent installed in: {install_dir}")
    
    if autostart_success:
        print("🔄 Agent will auto-start with your system")
    else:
        print(f"⚠️ To start manually, run: python {install_dir}/cybernova_agent.py")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            input("\nPress Enter to exit...")
        else:
            input("\nInstallation failed. Press Enter to exit...")
    except KeyboardInterrupt:
        print("\n🛑 Installation cancelled by user")
    except Exception as e:
        print(f"\n❌ Installation error: {e}")
        input("Press Enter to exit...")
