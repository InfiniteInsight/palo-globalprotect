#!/bin/bash
#
# Installation script for CEF Interceptor
# Supports systemd-based Linux distributions
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}CEF Interceptor Installation${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo ./install.sh"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VER${NC}"

# Install Python 3 if needed
echo ""
echo -e "${YELLOW}Checking Python 3...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "Installing Python 3..."
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        apt-get update
        apt-get install -y python3
    elif [ "$OS" == "rhel" ] || [ "$OS" == "rocky" ] || [ "$OS" == "centos" ]; then
        yum install -y python3
    else
        echo -e "${RED}Unsupported OS for automatic Python installation${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}Python 3 already installed: $(python3 --version)${NC}"
fi

# Create service user
echo ""
echo -e "${YELLOW}Creating service user...${NC}"
if id "cefintercept" &>/dev/null; then
    echo -e "${GREEN}User 'cefintercept' already exists${NC}"
else
    useradd -r -s /bin/false cefintercept
    echo -e "${GREEN}Created user 'cefintercept'${NC}"
fi

# Create directories
echo ""
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /opt/cef-interceptor
mkdir -p /var/log/cef-interceptor

# Copy script
echo ""
echo -e "${YELLOW}Installing CEF interceptor...${NC}"
cp cef-interceptor.py /opt/cef-interceptor/
chmod +x /opt/cef-interceptor/cef-interceptor.py
echo -e "${GREEN}Installed to /opt/cef-interceptor/cef-interceptor.py${NC}"

# Set permissions
chown -R cefintercept:cefintercept /opt/cef-interceptor
chown -R cefintercept:cefintercept /var/log/cef-interceptor

# Install systemd service
echo ""
echo -e "${YELLOW}Installing systemd service...${NC}"
cat > /etc/systemd/system/cef-interceptor.service << 'EOF'
[Unit]
Description=CEF Interceptor for Palo Alto GlobalProtect
After=network.target

[Service]
Type=simple
User=root
# Note: Running as root is required for binding to port 514
# If using non-privileged port (>1024), change User=cefintercept

ExecStart=/usr/bin/python3 /opt/cef-interceptor/cef-interceptor.py --listen-port 514 --forward-ip 127.0.0.1 --forward-port 10514 --output-protocol udp

Restart=always
RestartSec=5

StandardOutput=append:/var/log/cef-interceptor/stdout.log
StandardError=append:/var/log/cef-interceptor/stderr.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Created systemd service: /etc/systemd/system/cef-interceptor.service${NC}"

# Install logrotate config
echo ""
echo -e "${YELLOW}Installing log rotation...${NC}"
cat > /etc/logrotate.d/cef-interceptor << 'EOF'
/var/log/cef-interceptor/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 cefintercept cefintercept
    sharedscripts
    postrotate
        systemctl reload cef-interceptor >/dev/null 2>&1 || true
    endscript
}
EOF

echo -e "${GREEN}Created logrotate config: /etc/logrotate.d/cef-interceptor${NC}"

# Reload systemd
echo ""
echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload
echo -e "${GREEN}Systemd reloaded${NC}"

# Print configuration instructions
echo ""
echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT: Configure the service before starting${NC}"
echo ""
echo "Edit the service file to set the correct ports:"
echo "  sudo nano /etc/systemd/system/cef-interceptor.service"
echo ""
echo "Common configurations:"
echo "  - Default: Listen on 514, forward to localhost:10514"
echo "  - You may need to change --forward-port to match your LogStash/AMA config"
echo ""
echo "After editing, reload and start:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable cef-interceptor"
echo "  sudo systemctl start cef-interceptor"
echo ""
echo "Check status:"
echo "  sudo systemctl status cef-interceptor"
echo "  sudo tail -f /var/log/cef-interceptor/stdout.log"
echo ""
echo -e "${YELLOW}NOTE: Port 514 requires root privileges${NC}"
echo -e "If you use a non-privileged port (>1024), change User=cefintercept in the service file"
echo ""
