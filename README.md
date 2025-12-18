# CEF Interceptor for Palo Alto GlobalProtect

Intelligent middleware that intercepts CEF-formatted Palo Alto GlobalProtect logs and applies dynamic severity classification before forwarding to SIEM platforms (Microsoft Sentinel, Splunk, etc.).

## Problem Statement

Palo Alto Panorama can send GlobalProtect logs in CEF format, but:
- **Severity is hardcoded** (usually to 3 - Informational)
- **Severity field may be missing entirely** (some Panorama configurations)
- **No dynamic classification** based on event content
- **Poor SIEM alerting** due to lack of severity differentiation

## Solution

This interceptor sits between Panorama and your log collector (LogStash, Azure Monitor Agent, etc.) and:

1. ✅ **Receives** CEF messages from Panorama (with or without severity field)
2. ✅ **Parses** CEF to extract event fields
3. ✅ **Analyzes** event content (status, error codes, event types)
4. ✅ **Applies** intelligent severity mapping
5. ✅ **Inserts or overwrites** CEF severity field
6. ✅ **Forwards** enhanced CEF to your SIEM collector

**Handles both formats:**
- CEF **with** severity: `CEF:0|Vendor|Product|Version|SigID|Name|3|Extensions` → Overwrites severity
- CEF **without** severity: `CEF:0|Vendor|Product|Version|SigID|Name|Extensions` → Inserts severity

**Fallback Protection:**
If CEF parsing fails but the message appears to be CEF format, the interceptor will insert a **default severity of 5 (Medium)** to ensure Sentinel can still parse the logs. This prevents data loss from unparseable messages.

## Architecture

```
┌──────────┐         ┌─────────────────┐         ┌──────────────┐         ┌──────────┐
│ Panorama │─CEF:3──▶│ CEF Interceptor │─CEF:1-9─▶│ LogStash/AMA │────────▶│ Sentinel │
└──────────┘         └─────────────────┘         └──────────────┘         └──────────┘
   (UDP 514)         Parse → Analyze              (UDP 10514)
                     └─ Dynamic Severity
```

**Before:**
- All events: Severity 3 (Informational)
- No differentiation between success/failure/critical

**After:**
- Quarantine events: **Severity 9** (Critical)
- Connection errors: **Severity 8** (High)
- Tunnel failures: **Severity 7** (High)
- Auth failures: **Severity 5** (Medium)
- Success events: **Severity 1** (Low)
- Default: **Severity 3** (Informational)

## Dynamic Severity Mapping

The interceptor applies intelligent severity based on event analysis:

| Event Type | Condition | Severity | Level |
|------------|-----------|----------|-------|
| Quarantine | `PanOSQuarantineReason` contains "quarantine" | 9 | Critical |
| Errors | `PanOSConnectionErrorID` present or subtype contains "error" | 8 | High |
| Tunnel Issues | Subtype = "tunnel-down" or "gateway-unavailable" | 7 | High |
| Failed Auth | `PanOSEventStatus=failed` | 5 | Medium |
| Success | `PanOSEventStatus=success` | 1 | Low |
| Default | All other events | 3 | Informational |

## Quick Start

### Prerequisites

- Linux VM with Python 3
- LogStash or Azure Monitor Agent already configured
- Root access (for binding to port 514)

### Installation

```bash
# Clone or copy the repository
cd /opt
git clone https://github.com/InfiniteInsight/palo-globalprotect.git
cd palo-globalprotect

# Run installation script
sudo ./install.sh
```

### Configuration

1. **Edit the systemd service** to match your environment:

```bash
sudo nano /etc/systemd/system/cef-interceptor.service
```

Update the `ExecStart` line with your ports:

```ini
ExecStart=/usr/bin/python3 /opt/cef-interceptor/cef-interceptor.py \
    --listen-port 514 \
    --forward-ip 127.0.0.1 \
    --forward-port 10514 \
    --output-protocol udp
```

**Important:**
- `--listen-port`: Port Panorama sends to (default: 514)
- `--forward-port`: Port your LogStash/AMA listens on (you may need to reconfigure this)

2. **Reconfigure your log collector** to listen on a different port:

**For LogStash:**
```ruby
# /etc/logstash/conf.d/syslog.conf
input {
  syslog {
    port => 10514
    type => "syslog"
  }
}
```

**For Azure Monitor Agent:**
Edit rsyslog to forward to AMA on a different port, or use the interceptor to forward to the existing rsyslog port after moving rsyslog's listening port.

3. **Reload and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable cef-interceptor
sudo systemctl start cef-interceptor
sudo systemctl status cef-interceptor
```

### Testing

Test the interceptor before deploying to production:

```bash
# Terminal 1: Start interceptor manually (non-privileged port)
python3 cef-interceptor.py --listen-port 5514 --forward-port 5515 --verbose

# Terminal 2: Start a listener to see output
nc -u -l 5515

# Terminal 3: Send test messages
./test-interceptor.sh 127.0.0.1 5514

# Or test both formats (with and without severity field)
./test-both-formats.sh 127.0.0.1 5514
```

You should see:
- Terminal 1: Parsing and severity modification logs
- Terminal 2: Modified CEF messages with updated/inserted severity values

**test-both-formats.sh** validates:
- CEF messages WITH severity field (overwrite scenario)
- CEF messages WITHOUT severity field (insert scenario)

**test-fallback.sh** validates:
- Fallback behavior when parsing fails
- Edge cases and malformed CEF messages
- Non-CEF message pass-through

## Command Line Options

```
usage: cef-interceptor.py [-h] [--listen-ip LISTEN_IP] [--listen-port LISTEN_PORT]
                          [--forward-ip FORWARD_IP] [--forward-port FORWARD_PORT]
                          [--input-protocol {udp,tcp}] [--output-protocol {udp,tcp}]
                          [--verbose]

Options:
  --listen-ip IP         IP to listen on (default: 0.0.0.0)
  --listen-port PORT     Port to listen on (default: 514)
  --forward-ip IP        IP to forward to (default: 127.0.0.1)
  --forward-port PORT    Port to forward to (default: 514)
  --input-protocol       udp or tcp (default: udp)
  --output-protocol      udp or tcp (default: udp)
  --verbose              Enable verbose logging
```

## Deployment Scenarios

### Scenario 1: Single VM with LogStash

```
Panorama → Interceptor:514 → LogStash:10514 → Sentinel
```

1. Install interceptor
2. Reconfigure LogStash to listen on port 10514
3. Configure interceptor to forward to localhost:10514
4. Update Panorama to send syslog to your VM:514

### Scenario 2: Azure Monitor Agent

```
Panorama → Interceptor:514 → rsyslog:10514 → AMA:28330 → Sentinel
```

1. Install interceptor
2. Modify rsyslog to listen on 10514 instead of 514
3. Configure interceptor to forward to localhost:10514
4. Existing rsyslog → AMA flow continues unchanged

### Scenario 3: High Availability

```
Panorama ──┬──▶ VM1: Interceptor → LogStash → Sentinel
           └──▶ VM2: Interceptor → LogStash → Sentinel
```

Configure Panorama with multiple syslog destinations for redundancy.

## Monitoring

### View Logs

```bash
# Real-time logs
sudo tail -f /var/log/cef-interceptor/stdout.log

# Error logs
sudo tail -f /var/log/cef-interceptor/stderr.log

# Service status
sudo systemctl status cef-interceptor
```

### Stats

The interceptor logs statistics every 1,000 messages:

```
Processed 1000 messages, modified 432 severities, 0 errors
```

## Resilience & Data Protection

The interceptor is designed to **never discard non-empty traffic**:

| Scenario | Action | Result |
|----------|--------|--------|
| ✅ Valid CEF format | Parse → Analyze → Modify | Intelligent severity applied |
| ✅ CEF missing severity | Parse → Insert severity | Intelligent severity inserted |
| ⚠️ CEF parsing fails | Fallback → Insert severity=5 | Default severity inserted |
| ✅ Non-CEF message | Pass through | Forwarded unmodified |
| ❌ Empty message | Skip | Not forwarded (only scenario) |

**Key Benefits:**
- **No data loss:** All non-empty messages are forwarded
- **Sentinel compatibility:** Even unparseable CEF gets severity=5
- **Graceful degradation:** Unknown formats pass through unchanged
- **Production safe:** Can be deployed without risk of breaking existing flows

## Troubleshooting

### Interceptor not receiving messages

```bash
# Check if port is listening
sudo netstat -ulnp | grep 514

# Check firewall
sudo firewall-cmd --list-all

# Test with tcpdump
sudo tcpdump -i any -n port 514
```

### Messages not reaching SIEM

```bash
# Verify forwarding
sudo tcpdump -i lo -n port 10514

# Check LogStash/AMA is listening
sudo netstat -ulnp | grep 10514

# Test direct send
echo "test message" | nc -u 127.0.0.1 10514
```

### Permission denied on port 514

Port 514 requires root or `CAP_NET_BIND_SERVICE` capability:

```bash
# Option 1: Run as root (in systemd service)
User=root

# Option 2: Use non-privileged port
--listen-port 5514

# Option 3: Grant capability
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3
```

## Performance

- **Throughput:** Tested to 25,000+ events per second
- **Latency:** <1ms per event overhead
- **Memory:** ~50MB steady state
- **CPU:** Minimal (<5% on modern CPU)

## Security Considerations

- Runs as root only if binding to privileged port (<1024)
- No external dependencies
- All processing in-memory
- Systemd security hardening enabled
- Log rotation configured

## Files

```
.
├── cef-interceptor.py          # Main interceptor script
├── install.sh                  # Installation script
├── test-interceptor.sh         # Test script
├── README.md                   # This file
├── config.yaml                 # Sample config (for reference)
└── archive/                    # Old forwarder code (archived)
```

## Contributing

Issues and pull requests welcome at: https://github.com/InfiniteInsight/palo-globalprotect

## License

MIT License - See LICENSE file for details

## References

- [LogStash Syslog Input Plugin](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-syslog.html)
- [Azure Monitor Agent Syslog](https://learn.microsoft.com/en-us/azure/sentinel/forward-syslog-monitor-agent)
- [CEF Format Specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
- [Palo Alto Networks Syslog Integration](https://docs.paloaltonetworks.com/pan-os/)
