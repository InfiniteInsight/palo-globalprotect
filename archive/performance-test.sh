#!/bin/bash
#
# Performance test script for Panorama GlobalProtect to CEF Forwarder
# Tests throughput to validate ≥25k EPS requirement
#

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Test parameters
FORWARDER_HOST="${1:-127.0.0.1}"
FORWARDER_PORT="${2:-5514}"
NUM_MESSAGES="${3:-100000}"
BATCH_SIZE="${4:-1000}"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Panorama to CEF Forwarder - Performance Test                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Test Configuration:${NC}"
echo "  Target: $FORWARDER_HOST:$FORWARDER_PORT"
echo "  Total Messages: $NUM_MESSAGES"
echo "  Batch Size: $BATCH_SIZE"
echo "  Target: ≥25,000 EPS"
echo ""

# Check dependencies
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed${NC}"
    exit 1
fi

# Create Python performance test script
cat > /tmp/perf_test.py << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
"""
High-performance load generator for CEF forwarder testing
Sends messages as fast as possible to measure throughput
"""

import socket
import time
import sys
import json
from datetime import datetime

def run_perf_test(host, port, num_messages, batch_size):
    """Send messages and measure throughput"""
    
    # Sample message templates for variety
    message_templates = [
        {
            "subtype": "login",
            "status": "success",
            "sender_sw_version": "11.0.4",
            "type": "globalprotect",
            "serial": "012345678901",
            "srcuser": "user{}@example.com",
            "gateway": "vpn-gw-01.example.com"
        },
        {
            "subtype": "logout",
            "status": "success",
            "sender_sw_version": "11.0.4",
            "type": "globalprotect",
            "serial": "012345678901",
            "srcuser": "user{}@example.com",
            "login_duration": "3600"
        },
        {
            "subtype": "auth",
            "status": "failed",
            "sender_sw_version": "11.0.4",
            "type": "globalprotect",
            "serial": "012345678901",
            "srcuser": "user{}@example.com",
            "error_code": "E-401"
        }
    ]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"Starting performance test...")
    print(f"Sending {num_messages} messages to {host}:{port}")
    print("")
    
    start_time = time.time()
    last_report = start_time
    sent_count = 0
    error_count = 0
    
    try:
        for i in range(num_messages):
            # Rotate through templates
            template = message_templates[i % len(message_templates)].copy()
            template["srcuser"] = template["srcuser"].format(i)
            template["time_generated"] = datetime.utcnow().isoformat()
            template["receive_time"] = datetime.utcnow().isoformat()
            template["eventid"] = str(1000 + (i % 1000))
            
            message = json.dumps(template)
            
            try:
                sock.sendto(message.encode('utf-8'), (host, port))
                sent_count += 1
            except Exception as e:
                error_count += 1
                if error_count < 10:  # Only print first few errors
                    print(f"Send error: {e}")
            
            # Report progress every batch
            if (i + 1) % batch_size == 0:
                current_time = time.time()
                elapsed = current_time - last_report
                batch_eps = batch_size / elapsed if elapsed > 0 else 0
                total_elapsed = current_time - start_time
                overall_eps = sent_count / total_elapsed if total_elapsed > 0 else 0
                
                print(f"Progress: {sent_count}/{num_messages} | "
                      f"Batch EPS: {batch_eps:,.0f} | "
                      f"Overall EPS: {overall_eps:,.0f} | "
                      f"Errors: {error_count}")
                
                last_report = current_time
    
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    finally:
        sock.close()
    
    end_time = time.time()
    total_elapsed = end_time - start_time
    final_eps = sent_count / total_elapsed if total_elapsed > 0 else 0
    
    print("")
    print("=" * 70)
    print("Performance Test Results")
    print("=" * 70)
    print(f"Total Messages Sent: {sent_count:,}")
    print(f"Total Errors: {error_count:,}")
    print(f"Test Duration: {total_elapsed:.2f} seconds")
    print(f"Average Throughput: {final_eps:,.0f} EPS")
    print(f"Average Latency: {(total_elapsed * 1000000 / sent_count):.2f} microseconds per event")
    print("")
    
    # Evaluate against target
    if final_eps >= 25000:
        print("✓ PASS: Throughput exceeds 25,000 EPS requirement")
        return 0
    else:
        deficit = 25000 - final_eps
        print(f"✗ FAIL: Throughput is {deficit:,.0f} EPS below requirement")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: perf_test.py <host> <port> <num_messages> <batch_size>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    num_messages = int(sys.argv[3])
    batch_size = int(sys.argv[4])
    
    sys.exit(run_perf_test(host, port, num_messages, batch_size))
PYTHON_SCRIPT

chmod +x /tmp/perf_test.py

echo -e "${YELLOW}Starting performance test...${NC}"
echo ""

# Run the performance test
python3 /tmp/perf_test.py "$FORWARDER_HOST" "$FORWARDER_PORT" "$NUM_MESSAGES" "$BATCH_SIZE"
TEST_RESULT=$?

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Performance Test Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ Performance test PASSED${NC}"
else
    echo -e "${RED}✗ Performance test FAILED${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting Tips:${NC}"
    echo "  1. Check CPU usage: top"
    echo "  2. Check network buffers: sysctl net.core.rmem_max"
    echo "  3. Increase receive buffer in forwarder.py"
    echo "  4. Consider using multiple forwarder instances"
    echo "  5. Check SIEM collector capacity"
fi

echo ""
echo -e "${YELLOW}Additional Verification:${NC}"
echo "  1. Check forwarder logs for processing stats:"
echo "     sudo tail -100 /var/log/pano-cef-forwarder/stdout.log"
echo ""
echo "  2. Monitor system resources:"
echo "     sudo systemctl status pano-cef-forwarder"
echo ""
echo "  3. Check for packet loss:"
echo "     netstat -su | grep 'packet receive errors'"
echo ""

# Cleanup
rm -f /tmp/perf_test.py

exit $TEST_RESULT
