#!/bin/bash
#
# Test script for Palo Alto Panorama GlobalProtect to CEF Forwarder
# This script sends sample GlobalProtect logs to test the forwarder
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Default test parameters
FORWARDER_HOST="127.0.0.1"
FORWARDER_PORT="5514"
PROTOCOL="udp"
NUM_MESSAGES=10

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Panorama GlobalProtect to CEF Forwarder - Test Suite        ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if nc (netcat) is available
if ! command -v nc &> /dev/null; then
    echo -e "${RED}Error: netcat (nc) is not installed${NC}"
    echo "Install with: sudo dnf install nc"
    exit 1
fi

echo -e "${YELLOW}Test Configuration:${NC}"
echo "  Target: $FORWARDER_HOST:$FORWARDER_PORT"
echo "  Protocol: $PROTOCOL"
echo "  Messages: $NUM_MESSAGES"
echo ""

# Function to send a test message
send_message() {
    local message="$1"
    local test_name="$2"
    
    echo -e "${YELLOW}Test: $test_name${NC}"
    echo "  Sending: $message"
    
    if [ "$PROTOCOL" == "udp" ]; then
        echo "$message" | nc -u -w1 "$FORWARDER_HOST" "$FORWARDER_PORT"
    else
        echo "$message" | nc -w1 "$FORWARDER_HOST" "$FORWARDER_PORT"
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓ Sent successfully${NC}"
    else
        echo -e "  ${RED}✗ Failed to send${NC}"
    fi
    echo ""
    sleep 0.5
}

echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Running Test Cases${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Test 1: Successful login (Severity = 1)
send_message '{
  "subtype": "login",
  "status": "success",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:30:45",
  "receive_time": "2025-01-15T10:30:45",
  "srcuser": "john.doe@example.com",
  "srcregion": "US-East",
  "machinename": "LAPTOP-001",
  "public_ip": "203.0.113.45",
  "private_ip": "192.168.1.100",
  "client_os": "Windows",
  "client_os_ver": "10.0.19044",
  "client_ver": "6.0.4",
  "gateway": "vpn-gw-01.example.com"
}' "Successful Login (Severity=1)"

# Test 2: Failed login (Severity = 5)
send_message '{
  "subtype": "login",
  "status": "failed",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:31:00",
  "receive_time": "2025-01-15T10:31:00",
  "srcuser": "jane.smith@example.com",
  "srcregion": "US-West",
  "machinename": "LAPTOP-002",
  "public_ip": "203.0.113.89",
  "reason": "Invalid credentials",
  "client_os": "macOS",
  "client_os_ver": "14.2.1"
}' "Failed Login (Severity=5)"

# Test 3: Gateway error (Severity = 8)
send_message '{
  "subtype": "gateway-error",
  "status": "failed",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:32:15",
  "receive_time": "2025-01-15T10:32:15",
  "srcuser": "bob.jones@example.com",
  "error_code": "E-503",
  "error": "Gateway unavailable",
  "gateway": "vpn-gw-02.example.com",
  "location": "New York"
}' "Gateway Error (Severity=8)"

# Test 4: Quarantine event (Severity = 9)
send_message '{
  "subtype": "auth",
  "status": "blocked",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:33:30",
  "receive_time": "2025-01-15T10:33:30",
  "srcuser": "alice.williams@example.com",
  "reason": "Device quarantine due to compliance failure",
  "machinename": "LAPTOP-003",
  "public_ip": "203.0.113.123",
  "hostid": "host-123-abc"
}' "Quarantine Event (Severity=9)"

# Test 5: Tunnel down (Severity = 7)
send_message '{
  "subtype": "tunnel-down",
  "status": "disconnected",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:34:45",
  "receive_time": "2025-01-15T10:34:45",
  "srcuser": "charlie.brown@example.com",
  "tunnel_type": "IPSec",
  "gateway": "vpn-gw-01.example.com",
  "login_duration": "3600"
}' "Tunnel Down (Severity=7)"

# Test 6: Key=Value format (legacy syslog)
send_message "subtype=logout status=success sender_sw_version=11.0.4 type=globalprotect serial=012345678901 srcuser=test.user@example.com gateway=vpn-gw-01.example.com login_duration=7200" \
    "Key=Value Format (Legacy)"

# Test 7: Informational event (Severity = 3, default)
send_message '{
  "subtype": "config-change",
  "status": "info",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "serial": "012345678901",
  "time_generated": "2025-01-15T10:36:00",
  "receive_time": "2025-01-15T10:36:00",
  "srcuser": "admin@example.com",
  "opaque": "Updated gateway selection type"
}' "Informational Event (Severity=3)"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Test Suite Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Verification Steps:${NC}"
echo ""
echo "1. Check forwarder logs:"
echo "   sudo tail -f /var/log/pano-cef-forwarder/stdout.log"
echo ""
echo "2. Check for CEF output on SIEM collector:"
echo "   sudo tcpdump -n -i any udp port 514 -A"
echo ""
echo "3. Verify service status:"
echo "   sudo systemctl status pano-cef-forwarder"
echo ""
echo "4. Expected CEF format:"
echo "   CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|login|1|rt=... PanOSSourceUserName=..."
echo ""
echo -e "${YELLOW}Severity Mapping Tested:${NC}"
echo "  • Severity 1 (Success) - Test #1"
echo "  • Severity 3 (Info)    - Test #7"
echo "  • Severity 5 (Failed)  - Test #2"
echo "  • Severity 7 (Tunnel)  - Test #5"
echo "  • Severity 8 (Error)   - Test #3"
echo "  • Severity 9 (Critical)- Test #4"
echo ""
