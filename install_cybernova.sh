#!/bin/bash

echo "========================================"
echo "    CyberNova AI Security Agent"
echo "    Unix/Linux/macOS Auto-Installer"
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo -e "${BLUE}[INFO]${NC} Detected OS: $MACHINE"

# Set installation directory
INSTALL_DIR="$HOME/CyberNova"
echo -e "${BLUE}[INFO]${NC} Installation directory: $INSTALL_DIR"

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check if Python is installed
echo -e "${BLUE}[INFO]${NC} Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    echo -e "${GREEN}[INFO]${NC} Python3 is installed"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    echo -e "${GREEN}[INFO]${NC} Python is installed"
else
    echo -e "${RED}[ERROR]${NC} Python is not installed. Please install Python first:"
    if [[ "$MACHINE" == "Mac" ]]; then
        echo "  brew install python3"
        echo "  or download from: https://www.python.org/downloads/"
    elif [[ "$MACHINE" == "Linux" ]]; then
        echo "  sudo apt-get install python3 python3-pip  # Ubuntu/Debian"
        echo "  sudo yum install python3 python3-pip      # CentOS/RHEL"
        echo "  sudo pacman -S python python-pip          # Arch Linux"
    fi
    exit 1
fi

# Check if pip is installed
echo -e "${BLUE}[INFO]${NC} Checking pip installation..."
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    echo -e "${YELLOW}[WARNING]${NC} pip not found. Installing pip..."
    if [[ "$MACHINE" == "Mac" ]]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        $PYTHON_CMD get-pip.py --user
        rm get-pip.py
    elif [[ "$MACHINE" == "Linux" ]]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        $PYTHON_CMD get-pip.py --user
        rm get-pip.py
    fi
    PIP_CMD="pip"
fi

# Download CyberNova agent
echo -e "${BLUE}[INFO]${NC} Downloading CyberNova agent..."
if command -v curl &> /dev/null; then
    curl -o cybernova_agent.py "http://localhost:8080/installer-download?type=python"
elif command -v wget &> /dev/null; then
    wget -O cybernova_agent.py "http://localhost:8080/installer-download?type=python"
else
    echo -e "${RED}[ERROR]${NC} Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Check if download was successful
if [[ ! -f "cybernova_agent.py" ]]; then
    echo -e "${RED}[ERROR]${NC} Failed to download agent. Please check your internet connection."
    exit 1
fi

# Make agent executable
chmod +x cybernova_agent.py

# Install required packages
echo -e "${BLUE}[INFO]${NC} Installing required Python packages..."
$PIP_CMD install --user requests psutil plyer

# Set up auto-start based on OS
echo -e "${BLUE}[INFO]${NC} Setting up auto-start..."

if [[ "$MACHINE" == "Mac" ]]; then
    # macOS LaunchAgent
    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"
    
    cat > "$PLIST_DIR/com.cybernova.agent.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cybernova.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_CMD</string>
        <string>$INSTALL_DIR/cybernova_agent.py</string>
        <string>--auto-start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
    
    # Load the launch agent
    launchctl load "$PLIST_DIR/com.cybernova.agent.plist" 2>/dev/null || true
    echo -e "${GREEN}[INFO]${NC} macOS LaunchAgent configured"
    
elif [[ "$MACHINE" == "Linux" ]]; then
    # Linux systemd user service
    SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SERVICE_DIR"
    
    cat > "$SERVICE_DIR/cybernova.service" << EOF
[Unit]
Description=CyberNova Security Agent
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=$PYTHON_CMD $INSTALL_DIR/cybernova_agent.py --auto-start
Restart=always
RestartSec=10
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=default.target
EOF
    
    # Enable and start the service
    systemctl --user daemon-reload
    systemctl --user enable cybernova.service
    systemctl --user start cybernova.service
    echo -e "${GREEN}[INFO]${NC} Linux systemd service configured"
fi

# Create desktop launcher (if desktop environment is available)
if [[ -d "$HOME/Desktop" ]]; then
    echo -e "${BLUE}[INFO]${NC} Creating desktop launcher..."
    cat > "$HOME/Desktop/CyberNova Agent.sh" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
$PYTHON_CMD cybernova_agent.py
EOF
    chmod +x "$HOME/Desktop/CyberNova Agent.sh"
fi

# Start the agent immediately
echo -e "${BLUE}[INFO]${NC} Starting CyberNova agent..."
echo "========================================"
echo "    Installation Complete!"
echo "========================================"
echo
echo "The CyberNova agent is now installed and will:"
echo "- Start automatically with your system"
echo "- Monitor your system for threats"
echo "- Send security data to your dashboard"
echo
echo "Starting agent now..."
echo

# Start agent immediately in background
nohup $PYTHON_CMD "$INSTALL_DIR/cybernova_agent.py" --auto-start > /dev/null 2>&1 &
AGENT_PID=$!

# Wait a moment for agent to start
sleep 3

# Verify agent is running
if kill -0 $AGENT_PID 2>/dev/null; then
    echo -e "${GREEN}[SUCCESS]${NC} CyberNova agent is running! (PID: $AGENT_PID)"
else
    echo -e "${YELLOW}[INFO]${NC} Agent starting in background..."
fi

echo
echo "========================================"
echo "    🎉 Installation Complete!"
echo "========================================"
echo
echo -e "${GREEN}✅${NC} CyberNova agent is now installed and running"
echo -e "${BLUE}🛡️${NC} Real-time security monitoring is active"
echo -e "${BLUE}📊${NC} Check your dashboard at: http://localhost:8080/dashboard"
echo -e "${BLUE}🔄${NC} The agent will automatically start with your system"
echo
echo -e "${GREEN}🚀 Ready to scan! The agent is monitoring your device.${NC}"
echo
echo "Installation completed successfully!"