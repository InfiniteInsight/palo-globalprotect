#!/bin/bash
#
# Test script for CEF Interceptor - Both formats
# Tests CEF messages WITH and WITHOUT severity field
#

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

INTERCEPTOR_IP=${1:-127.0.0.1}
INTERCEPTOR_PORT=${2:-5514}

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}CEF Interceptor Test - Both Formats${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Target: $INTERCEPTOR_IP:$INTERCEPTOR_PORT"
echo ""

# Check if netcat is available
if ! command -v nc &> /dev/null; then
    echo -e "${RED}Error: netcat (nc) is required but not installed${NC}"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Scenario 1: CEF WITH Severity Field${NC}"
echo -e "${BLUE}(Testing overwrite functionality)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Success event WITH severity field (severity=3, should become 1)
echo -e "${YELLOW}Test 1a: Success event WITH severity=3 (should become 1)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|3|rt=Jan 15 2025 14:23:45 PanOSDeviceSN=001234567890 PanOSEventStatus=success PanOSSourceUserName=jdoe' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITH severity field)${NC}"
echo ""
sleep 1

# Test 2: Failed event WITH severity field (severity=3, should become 5)
echo -e "${YELLOW}Test 2a: Failed event WITH severity=3 (should become 5)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|3|rt=Jan 15 2025 14:24:12 PanOSDeviceSN=001234567890 PanOSEventStatus=failed PanOSSourceUserName=baduser' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITH severity field)${NC}"
echo ""
sleep 1

# Test 3: Quarantine event WITH severity field (severity=5, should become 9)
echo -e "${YELLOW}Test 3a: Quarantine event WITH severity=5 (should become 9)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|quarantine|5|rt=Jan 15 2025 14:26:45 PanOSDeviceSN=001234567890 PanOSQuarantineReason=Missing antivirus software' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITH severity field)${NC}"
echo ""
sleep 1

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Scenario 2: CEF WITHOUT Severity Field${NC}"
echo -e "${BLUE}(Testing insert functionality)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Success event WITHOUT severity field (should insert 1)
echo -e "${YELLOW}Test 1b: Success event WITHOUT severity (should insert 1)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|rt=Jan 15 2025 14:23:45 PanOSDeviceSN=001234567890 PanOSEventStatus=success PanOSSourceUserName=jdoe' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITHOUT severity field - missing pipe)${NC}"
echo ""
sleep 1

# Test 2: Failed event WITHOUT severity field (should insert 5)
echo -e "${YELLOW}Test 2b: Failed event WITHOUT severity (should insert 5)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|auth|rt=Jan 15 2025 14:24:12 PanOSDeviceSN=001234567890 PanOSEventStatus=failed PanOSSourceUserName=baduser' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITHOUT severity field)${NC}"
echo ""
sleep 1

# Test 3: Quarantine event WITHOUT severity field (should insert 9)
echo -e "${YELLOW}Test 3b: Quarantine event WITHOUT severity (should insert 9)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|quarantine|rt=Jan 15 2025 14:26:45 PanOSDeviceSN=001234567890 PanOSQuarantineReason=Missing antivirus software' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITHOUT severity field)${NC}"
echo ""
sleep 1

# Test 4: Error event WITHOUT severity field (should insert 8)
echo -e "${YELLOW}Test 4b: Connection error WITHOUT severity (should insert 8)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|connection-error|rt=Jan 15 2025 14:25:33 PanOSDeviceSN=001234567890 PanOSConnectionErrorID=5001 PanOSGateway=vpn-gw-01.example.com' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITHOUT severity field)${NC}"
echo ""
sleep 1

# Test 5: Tunnel down WITHOUT severity field (should insert 7)
echo -e "${YELLOW}Test 5b: Tunnel down WITHOUT severity (should insert 7)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0.1|GLOBALPROTECT|tunnel-down|rt=Jan 15 2025 14:27:21 PanOSDeviceSN=001234567890 PanOSGateway=vpn-gw-02.example.com' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (WITHOUT severity field)${NC}"
echo ""
sleep 1

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Test suite completed!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Check the output listener to verify both scenarios:"
echo ""
echo -e "${YELLOW}Expected Results:${NC}"
echo ""
echo -e "${BLUE}WITH Severity (overwrite):${NC}"
echo "  Test 1a: Severity 3 → 1 (success)"
echo "  Test 2a: Severity 3 → 5 (failed)"
echo "  Test 3a: Severity 5 → 9 (quarantine)"
echo ""
echo -e "${BLUE}WITHOUT Severity (insert):${NC}"
echo "  Test 1b: No severity → 1 inserted (success)"
echo "  Test 2b: No severity → 5 inserted (failed)"
echo "  Test 3b: No severity → 9 inserted (quarantine)"
echo "  Test 4b: No severity → 8 inserted (error)"
echo "  Test 5b: No severity → 7 inserted (tunnel-down)"
echo ""
echo "All messages should have proper CEF format with severity in position 6"
echo ""
