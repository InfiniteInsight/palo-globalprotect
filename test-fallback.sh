#!/bin/bash
#
# Test script for CEF Interceptor - Fallback Behavior
# Tests edge cases where parsing might fail but we still want severity inserted
#

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

INTERCEPTOR_IP=${1:-127.0.0.1}
INTERCEPTOR_PORT=${2:-5514}

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}CEF Interceptor Fallback Test Suite${NC}"
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
echo -e "${BLUE}Scenario 1: Valid CEF (should work normally)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${YELLOW}Test 1: Normal CEF with severity (should parse and modify)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0|GLOBALPROTECT|auth|3|PanOSEventStatus=success' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent${NC}"
echo ""
sleep 1

echo -e "${YELLOW}Test 2: Normal CEF without severity (should parse and insert)${NC}"
echo 'CEF:0|Palo Alto Networks|PAN-OS|11.0|GLOBALPROTECT|auth|PanOSEventStatus=failed' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent${NC}"
echo ""
sleep 1

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Scenario 2: Edge Cases (fallback should trigger)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${YELLOW}Test 3: CEF with special characters in extensions (might fail parsing)${NC}"
echo 'CEF:0|Vendor|Product|1.0|ID|Name|ext1=value with | pipe ext2=another' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (fallback should insert severity=5)${NC}"
echo ""
sleep 1

echo -e "${YELLOW}Test 4: Minimal CEF without severity (6 fields exactly)${NC}"
echo 'CEF:0|Vendor|Product|1.0|SigID|EventName|key1=value1 key2=value2' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (fallback should insert severity=5)${NC}"
echo ""
sleep 1

echo -e "${YELLOW}Test 5: CEF with empty extensions${NC}"
echo 'CEF:0|Vendor|Product|1.0|SigID|EventName|' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (fallback should insert severity=5)${NC}"
echo ""
sleep 1

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Scenario 3: Non-CEF messages (should forward as-is)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${YELLOW}Test 6: Plain syslog message (non-CEF)${NC}"
echo '<134>Jan 15 14:30:00 hostname some random syslog message' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (should forward unmodified)${NC}"
echo ""
sleep 1

echo -e "${YELLOW}Test 7: Random text (non-CEF)${NC}"
echo 'This is just random text, not CEF at all' | nc -u -w1 $INTERCEPTOR_IP $INTERCEPTOR_PORT
echo -e "${GREEN}✓ Sent (should forward unmodified)${NC}"
echo ""
sleep 1

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Test suite completed!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}Expected Behavior:${NC}"
echo ""
echo -e "${BLUE}Valid CEF (Tests 1-2):${NC}"
echo "  - Should parse successfully"
echo "  - Should apply intelligent severity mapping"
echo ""
echo -e "${BLUE}Edge Cases (Tests 3-5):${NC}"
echo "  - Parsing may fail due to edge cases"
echo "  - Fallback should insert severity=5"
echo "  - Messages should still be valid CEF for Sentinel"
echo ""
echo -e "${BLUE}Non-CEF (Tests 6-7):${NC}"
echo "  - Should forward completely unmodified"
echo "  - No attempt to insert severity"
echo ""
echo "Check interceptor logs for fallback messages:"
echo "  'Fallback: Inserted severity=5 into unparseable CEF message'"
echo ""
