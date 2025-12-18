#!/bin/bash
#
# Test script for CEF Interceptor
# Sends sample CEF messages and verifies severity modification
#

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INTERCEPTOR_IP=${1:-127.0.0.1}
INTERCEPTOR_PORT=${2:-5514}

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}CEF Interceptor Test Suite${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""
echo "Target: $INTERCEPTOR_IP:$INTERCEPTOR_PORT"
echo ""

# Check if netcat is available
if ! command -v nc &> /dev/null; then
    echo -e "${RED}Error: netcat (nc) is required but not installed${NC}"
    exit 1
fi

# Test 1: Success event (should get severity 1)
echo -e "${YELLOW}Test 1: Success event (expected severity: 1)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|3|rt=Jan 15 2025 14:23:45 PanOSDeviceSN=001234567890 PanOSEventStatus=success PanOSSourceUserName=jdoe PanOSEndpointDeviceName=LAPTOP-123 PanOSPublicIPv4=192.168.1.100 PanOSAuthMethod=LDAP' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent success event${NC}"
echo ""
sleep 1

# Test 2: Failed event (should get severity 5)
echo -e "${YELLOW}Test 2: Failed event (expected severity: 5)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|3|rt=Jan 15 2025 14:24:12 PanOSDeviceSN=001234567890 PanOSEventStatus=failed PanOSSourceUserName=baduser PanOSEndpointDeviceName=LAPTOP-456 PanOSPublicIPv4=192.168.1.101 PanOSAuthMethod=LDAP PanOSConnectionError=Invalid credentials' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent failed event${NC}"
echo ""
sleep 1

# Test 3: Error with error code (should get severity 8)
echo -e "${YELLOW}Test 3: Connection error (expected severity: 8)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|connection-error|3|rt=Jan 15 2025 14:25:33 PanOSDeviceSN=001234567890 PanOSEventStatus=failed PanOSSourceUserName=jdoe PanOSConnectionError=Gateway timeout PanOSConnectionErrorID=5001 PanOSGateway=vpn-gw-01.example.com' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent error event${NC}"
echo ""
sleep 1

# Test 4: Quarantine event (should get severity 9)
echo -e "${YELLOW}Test 4: Quarantine event (expected severity: 9)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|quarantine|3|rt=Jan 15 2025 14:26:45 PanOSDeviceSN=001234567890 PanOSEventStatus=failed PanOSSourceUserName=jsmith PanOSEndpointDeviceName=DESKTOP-789 PanOSQuarantineReason=Missing antivirus software PanOSPublicIPv4=192.168.1.102' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent quarantine event${NC}"
echo ""
sleep 1

# Test 5: Tunnel down (should get severity 7)
echo -e "${YELLOW}Test 5: Tunnel down event (expected severity: 7)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|tunnel-down|3|rt=Jan 15 2025 14:27:21 PanOSDeviceSN=001234567890 PanOSSourceUserName=jdoe PanOSEndpointDeviceName=LAPTOP-123 PanOSConnectionError=Tunnel timeout PanOSGateway=vpn-gw-02.example.com' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent tunnel-down event${NC}"
echo ""
sleep 1

# Test 6: Generic informational (should get severity 3)
echo -e "${YELLOW}Test 6: Generic event (expected severity: 3)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|config-update|3|rt=Jan 15 2025 14:28:00 PanOSDeviceSN=001234567890 PanOSSourceUserName=admin PanOSDescription=Configuration updated successfully' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent generic event${NC}"
echo ""

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}Test suite completed!${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""
echo "Check interceptor logs to verify severity modifications:"
echo "  sudo tail -f /var/log/cef-interceptor/stdout.log"
echo ""
echo "Or if running manually, check the console output above"
echo ""
echo -e "${YELLOW}Expected severity mappings:${NC}"
echo "  Test 1 (success):     1 (Low)"
echo "  Test 2 (failed):      5 (Medium)"
echo "  Test 3 (error):       8 (High)"
echo "  Test 4 (quarantine):  9 (Critical)"
echo "  Test 5 (tunnel-down): 7 (High)"
echo "  Test 6 (generic):     3 (Informational)"
echo ""
