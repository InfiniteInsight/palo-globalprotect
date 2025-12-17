# Palo Alto Networks Panorama GlobalProtect to CEF Forwarder

High-throughput log processing service for Rocky Linux that converts Panorama GlobalProtect syslog to CEF format with dynamic severity mapping.

## 📋 Overview

**Performance**: ≥25,000 EPS sustained with microsecond-scale overhead per event

**Features**:
- Receives Panorama GlobalProtect syslog (UDP/TCP)
- Converts to CEF with complete header including dynamic severity
- Forwards enriched CEF to SIEM (Azure Sentinel, Splunk, etc.)
- Zero external lookups - all mapping in-memory
- Systemd-managed with automatic restart
- Log rotation configured
- SELinux-ready

## 🏗️ Architecture

```
┌─────────────┐      UDP/TCP      ┌──────────────┐      UDP/TCP      ┌──────────┐
│  Panorama   │ ───────────────> │  Forwarder   │ ───────────────> │   SIEM   │
│ GlobalProtect│   Syslog 5514    │  (Python)    │   CEF 514        │ Sentinel │
└─────────────┘                   └──────────────┘                   └──────────┘
```

### Severity Mapping Logic

| Condition | Severity | Level |
|-----------|----------|-------|
| Quarantine event | 9 | Critical |
| Error code present or gateway/connection error | 8 | High |
| Tunnel down / Gateway unavailable | 7 | High |
| Failed status | 5 | Medium |
| Success status | 1 | Low |
| Default (informational) | 3 | Info |

## 📦 Installation

### Prerequisites

- Rocky Linux 8 or 9
- Root/sudo access
- Python 3.6+
- 2 vCPU / 4GB RAM minimum (for 25k+ EPS)

### Quick Install

```bash
# Clone or extract files to a directory
cd /path/to/pano-cef-forwarder

# Make install script executable
chmod +x install.sh

# Run installation as root
sudo ./install.sh
```

### Installation Process

The `install.sh` script will:

1. ✅ Check system requirements
2. ✅ Install dependencies (python3, pip, pyyaml, nc)
3. ✅ Create service user (`panocef`)
4. ✅ Create directories:
   - `/opt/pano-cef-forwarder` - Application files
   - `/etc/pano-cef-forwarder` - Configuration
   - `/var/log/pano-cef-forwarder` - Logs
5. ✅ Install forwarder service
6. ✅ Configure systemd service
7. ✅ Setup log rotation
8. ✅ Configure SELinux (if enforcing)

## ⚙️ Configuration

### Edit Configuration File

```bash
sudo vi /etc/pano-cef-forwarder/config.yaml
```

### Configuration Options

```yaml
input:
  protocol: udp         # udp | tcp
  listen_ip: "0.0.0.0"  # Bind to all interfaces
  listen_port: 5514     # Listening port

output:
  protocol: udp         # udp | tcp
  target_ip: "10.10.10.10"   # SIEM collector IP
  target_port: 514           # SIEM collector port

cef:
  default_severity: 3   # Default severity (0-10)
  vendor: "Palo Alto Networks"
  product: "PAN-OS"

performance:
  workers: 1            # Single process (tune if needed)
  queue_maxsize: 100000
  batch_send: false     # Keep false for order preservation
```

### Configure Firewall

```bash
# Allow incoming syslog on port 5514
sudo firewall-cmd --permanent --add-port=5514/udp
sudo firewall-cmd --reload
```

## 🚀 Service Management

### Start Service

```bash
# Enable at boot
sudo systemctl enable pano-cef-forwarder

# Start service
sudo systemctl start pano-cef-forwarder

# Check status
sudo systemctl status pano-cef-forwarder
```

### Stop/Restart Service

```bash
# Stop service
sudo systemctl stop pano-cef-forwarder

# Restart service
sudo systemctl restart pano-cef-forwarder

# Reload configuration (restart required)
sudo systemctl restart pano-cef-forwarder
```

### View Logs

```bash
# Real-time stdout logs
sudo tail -f /var/log/pano-cef-forwarder/stdout.log

# Real-time stderr logs (errors)
sudo tail -f /var/log/pano-cef-forwarder/stderr.log

# Systemd journal
sudo journalctl -u pano-cef-forwarder -f
```

## 🧪 Testing

### Functional Testing

Run the test suite to verify all severity mappings:

```bash
chmod +x test.sh
./test.sh
```

This sends sample messages covering all severity levels:
- Severity 1: Successful login
- Severity 3: Informational event
- Severity 5: Failed authentication
- Severity 7: Tunnel down
- Severity 8: Gateway error
- Severity 9: Quarantine event

### Performance Testing

Validate throughput meets ≥25k EPS requirement:

```bash
chmod +x performance-test.sh

# Test with 100k messages
./performance-test.sh 127.0.0.1 5514 100000 1000
```

Parameters:
1. Forwarder host (default: 127.0.0.1)
2. Forwarder port (default: 5514)
3. Number of messages (default: 100000)
4. Batch size for reporting (default: 1000)

### Manual Testing

Send a single test message:

```bash
# JSON format
echo '{
  "subtype": "login",
  "status": "success",
  "sender_sw_version": "11.0.4",
  "type": "globalprotect",
  "srcuser": "test@example.com",
  "gateway": "vpn-gw-01.example.com"
}' | nc -u -w1 127.0.0.1 5514

# Key=value format (legacy)
echo 'subtype=login status=success sender_sw_version=11.0.4 type=globalprotect' \
  | nc -u -w1 127.0.0.1 5514
```

### Verify CEF Output

Capture output on SIEM collector or test locally:

```bash
# On SIEM collector or local test
sudo tcpdump -n -i any udp port 514 -A

# Expected CEF format:
# CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|login|1|rt=... PanOSSourceUserName=...
```

## 📊 Monitoring

### Service Status

```bash
# Check service status
sudo systemctl status pano-cef-forwarder

# Check if service is active
systemctl is-active pano-cef-forwarder

# Check if service is enabled
systemctl is-enabled pano-cef-forwarder
```

### Performance Metrics

The forwarder logs throughput statistics every 10,000 messages:

```bash
sudo tail -f /var/log/pano-cef-forwarder/stdout.log
# Look for: "Processed 10000 messages, 28532 EPS"
```

### System Resource Usage

```bash
# CPU and memory usage
top -p $(pgrep -f forwarder.py)

# Network statistics
netstat -su | grep 'packet receive errors'

# Check receive buffer size
sysctl net.core.rmem_max
```

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check for errors in logs
sudo journalctl -u pano-cef-forwarder -n 50

# Verify configuration syntax
python3 -c "import yaml; yaml.safe_load(open('/etc/pano-cef-forwarder/config.yaml'))"

# Check file permissions
ls -la /opt/pano-cef-forwarder/
ls -la /etc/pano-cef-forwarder/
ls -la /var/log/pano-cef-forwarder/
```

### Not Receiving Messages

```bash
# Test if port is listening
sudo netstat -tulpn | grep 5514

# Check firewall
sudo firewall-cmd --list-all

# Send test message locally
echo 'test=message' | nc -u -w1 127.0.0.1 5514

# Check for SELinux denials
sudo ausearch -m avc -ts recent
```

### Low Throughput

```bash
# Increase receive buffer size
sudo sysctl -w net.core.rmem_max=134217728

# Check CPU usage
top -p $(pgrep -f forwarder.py)

# Consider multiple instances (different ports)
# Edit config.yaml, create pano-cef-forwarder-2.service
```

### Messages Not Reaching SIEM

```bash
# Verify SIEM collector IP/port in config
cat /etc/pano-cef-forwarder/config.yaml

# Test network connectivity
nc -zv <SIEM_IP> <SIEM_PORT>

# Capture outgoing packets
sudo tcpdump -n -i any dst port 514 -A

# Check for network errors
ip -s link show
```

### SELinux Issues

```bash
# Check if SELinux is enforcing
getenforce

# Check for denials
sudo ausearch -m avc -ts recent | grep pano

# Temporarily set to permissive (testing only)
sudo setenforce 0

# Re-apply SELinux labels
sudo chcon -R -t var_log_t /var/log/pano-cef-forwarder
sudo chcon -R -t etc_t /etc/pano-cef-forwarder
sudo chcon -R -t bin_t /opt/pano-cef-forwarder
```

## 📁 File Locations

| Path | Purpose |
|------|---------|
| `/opt/pano-cef-forwarder/forwarder.py` | Main forwarder service |
| `/etc/pano-cef-forwarder/config.yaml` | Configuration file |
| `/var/log/pano-cef-forwarder/stdout.log` | Service output logs |
| `/var/log/pano-cef-forwarder/stderr.log` | Service error logs |
| `/etc/systemd/system/pano-cef-forwarder.service` | Systemd unit file |
| `/etc/logrotate.d/pano-cef-forwarder` | Log rotation config |

## 🔐 Security

### Service User

The service runs as unprivileged user `panocef` with:
- No login shell (`/sbin/nologin`)
- Minimal permissions
- Read-only access to config
- Write access only to logs

### Systemd Hardening

The service unit includes security hardening:
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Private `/tmp` directory
- `ProtectSystem=strict` - Read-only system directories
- `ProtectHome=true` - No home directory access

### SELinux

When SELinux is enforcing:
- Port 5514 labeled as `syslogd_port_t`
- Log directory labeled as `var_log_t`
- Config directory labeled as `etc_t`
- Binary directory labeled as `bin_t`

## 📈 Performance Tuning

### For >25k EPS

1. **Use UDP**: Faster than TCP, acceptable for syslog
2. **Increase buffers**:
   ```bash
   sudo sysctl -w net.core.rmem_max=134217728
   sudo sysctl -w net.core.rmem_default=8388608
   ```
3. **Dedicated hardware**: 2+ vCPU, 4GB+ RAM
4. **Multiple instances**: Run multiple forwarders on different ports

### For >50k EPS

Consider sharding:
```bash
# Run 2 instances
# Instance 1: Port 5514
# Instance 2: Port 5515

# Configure Panorama to send to both
```

## 🔄 Upgrades

### Update Service

```bash
# Stop service
sudo systemctl stop pano-cef-forwarder

# Backup config
sudo cp /etc/pano-cef-forwarder/config.yaml /etc/pano-cef-forwarder/config.yaml.bak

# Update forwarder.py
sudo cp forwarder.py /opt/pano-cef-forwarder/

# Restart service
sudo systemctl start pano-cef-forwarder
```

## 🆘 Support

### Useful Commands

```bash
# Service status
sudo systemctl status pano-cef-forwarder

# View all logs
sudo journalctl -u pano-cef-forwarder --no-pager

# Test configuration
python3 /opt/pano-cef-forwarder/forwarder.py

# Check port binding
sudo ss -tulpn | grep 5514
```

### Log Collection

```bash
# Collect diagnostic information
tar -czf pano-cef-diagnostics.tar.gz \
  /var/log/pano-cef-forwarder/*.log \
  /etc/pano-cef-forwarder/config.yaml \
  /etc/systemd/system/pano-cef-forwarder.service
```

## 📝 CEF Format Reference

### Header Format
```
CEF:0|Palo Alto Networks|PAN-OS|<version>|<type>|<subtype>|<severity>|
```

### Extension Fields

All GlobalProtect fields are mapped to CEF extensions with `PanOS` prefix:

```
rt=<receive_time>
PanOSDeviceSN=<serial>
PanOSSourceUserName=<srcuser>
PanOSEventStatus=<status>
PanOSConnectionErrorID=<error_code>
... (see forwarder.py for complete list)
```

## 🔮 Future Enhancements

- [ ] TLS support for TCP output
- [ ] Prometheus metrics exporter
- [ ] StatsD integration
- [ ] Multi-process worker pool
- [ ] Batch sending with MTU awareness
- [ ] Health check endpoint

## 📄 License

Internal use only - Xperi Corporation

## ✅ Acceptance Criteria

- [x] Service starts via systemd and restarts on failure
- [x] Receives Panorama GlobalProtect logs
- [x] Outputs valid CEF with dynamic severity
- [x] Sustains ≥25,000 EPS in lab testing
- [x] Configuration externalized
- [x] Logs rotated automatically
- [x] SELinux compatible
