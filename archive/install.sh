#!/bin/bash
#
# Installation script for Palo Alto Networks Panorama GlobalProtect to CEF Forwarder
# Target: Rocky Linux 8/9
# Requirements: root/sudo access
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Installation paths
INSTALL_DIR="/opt/pano-cef-forwarder"
CONFIG_DIR="/etc/pano-cef-forwarder"
LOG_DIR="/var/log/pano-cef-forwarder"
SERVICE_USER="panocef"
SERVICE_GROUP="panocef"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Panorama GlobalProtect to CEF Forwarder - Installation      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   exit 1
fi

echo -e "${YELLOW}[1/9] Checking system requirements...${NC}"
# Check if Rocky Linux
if [ -f /etc/rocky-release ]; then
    echo "✓ Running on Rocky Linux"
    cat /etc/rocky-release
else
    echo -e "${YELLOW}Warning: Not running on Rocky Linux. Continuing anyway...${NC}"
fi

echo ""
echo -e "${YELLOW}[2/9] Installing system dependencies...${NC}"
dnf -y update || true
dnf -y install python3 python3-pip policycoreutils-python-utils nc
echo "✓ System dependencies installed"

echo ""
echo -e "${YELLOW}[3/9] Installing Python dependencies...${NC}"
pip3 install --upgrade pip
pip3 install pyyaml
echo "✓ Python dependencies installed"

echo ""
echo -e "${YELLOW}[4/9] Creating service user and group...${NC}"
if id "$SERVICE_USER" &>/dev/null; then
    echo "✓ User $SERVICE_USER already exists"
else
    useradd -r -s /sbin/nologin "$SERVICE_USER"
    echo "✓ Created user: $SERVICE_USER"
fi

echo ""
echo -e "${YELLOW}[5/9] Creating directories...${NC}"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
echo "✓ Created: $INSTALL_DIR"
echo "✓ Created: $CONFIG_DIR"
echo "✓ Created: $LOG_DIR"

echo ""
echo -e "${YELLOW}[6/9] Installing application files...${NC}"
# Copy forwarder script
cp "$SCRIPT_DIR/forwarder.py" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/forwarder.py"
echo "✓ Installed: $INSTALL_DIR/forwarder.py"

# Copy or create config if doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$SCRIPT_DIR/config.yaml" "$CONFIG_DIR/"
    echo "✓ Installed: $CONFIG_DIR/config.yaml"
    echo -e "${YELLOW}  → Please edit $CONFIG_DIR/config.yaml with your SIEM details${NC}"
else
    echo "✓ Config already exists: $CONFIG_DIR/config.yaml (not overwriting)"
fi

# Set ownership
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"
echo "✓ Set ownership to $SERVICE_USER:$SERVICE_GROUP"

echo ""
echo -e "${YELLOW}[7/9] Installing systemd service...${NC}"
cp "$SCRIPT_DIR/pano-cef-forwarder.service" /etc/systemd/system/
systemctl daemon-reload
echo "✓ Installed systemd service"

echo ""
echo -e "${YELLOW}[8/9] Configuring log rotation...${NC}"
cp "$SCRIPT_DIR/logrotate-pano-cef-forwarder" /etc/logrotate.d/pano-cef-forwarder
echo "✓ Configured log rotation"

echo ""
echo -e "${YELLOW}[9/9] Configuring SELinux (if enforcing)...${NC}"
if command -v getenforce &> /dev/null && [ "$(getenforce)" == "Enforcing" ]; then
    echo "SELinux is enforcing, configuring policies..."
    
    # Allow binding to syslog port
    semanage port -a -t syslogd_port_t -p udp 5514 2>/dev/null || \
    semanage port -m -t syslogd_port_t -p udp 5514 2>/dev/null || true
    
    # Set contexts
    chcon -R -t var_log_t "$LOG_DIR" 2>/dev/null || true
    chcon -R -t etc_t "$CONFIG_DIR" 2>/dev/null || true
    chcon -R -t bin_t "$INSTALL_DIR" 2>/dev/null || true
    
    echo "✓ SELinux policies configured"
else
    echo "✓ SELinux not enforcing, skipping"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Installation Complete!                                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo "1. Edit configuration:"
echo "   vi $CONFIG_DIR/config.yaml"
echo ""
echo "2. Start the service:"
echo "   systemctl enable pano-cef-forwarder"
echo "   systemctl start pano-cef-forwarder"
echo ""
echo "3. Check status:"
echo "   systemctl status pano-cef-forwarder"
echo ""
echo "4. View logs:"
echo "   tail -f $LOG_DIR/stdout.log"
echo "   tail -f $LOG_DIR/stderr.log"
echo ""
echo "5. Configure firewall (if needed):"
echo "   firewall-cmd --permanent --add-port=5514/udp"
echo "   firewall-cmd --reload"
echo ""
echo -e "${GREEN}Installation log: /tmp/pano-cef-install.log${NC}"
