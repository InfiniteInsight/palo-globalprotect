# Quick Start Guide
## Panorama GlobalProtect to CEF Forwarder

### 🚀 5-Minute Deployment

#### Step 1: Prerequisites Check
```bash
# Verify Rocky Linux
cat /etc/rocky-release

# Verify Python 3
python3 --version

# Verify sudo access
sudo whoami
```

#### Step 2: Install
```bash
# Navigate to deployment directory
cd /home/claude/pano-cef-forwarder

# Run installation (as root)
sudo ./install.sh
```

#### Step 3: Configure
```bash
# Edit configuration file
sudo vi /etc/pano-cef-forwarder/config.yaml

# Update these values:
# - output.target_ip: Your SIEM IP address
# - output.target_port: Your SIEM port (default: 514)
# - input.listen_port: Listening port (default: 5514)
```

**Example Configuration:**
```yaml
input:
  protocol: udp
  listen_ip: "0.0.0.0"
  listen_port: 5514

output:
  protocol: udp
  target_ip: "10.20.30.40"    # <- CHANGE THIS
  target_port: 514

cef:
  default_severity: 3
  vendor: "Palo Alto Networks"
  product: "PAN-OS"
```

#### Step 4: Open Firewall
```bash
# Allow incoming syslog
sudo firewall-cmd --permanent --add-port=5514/udp
sudo firewall-cmd --reload
```

#### Step 5: Start Service
```bash
# Enable and start
sudo systemctl enable pano-cef-forwarder
sudo systemctl start pano-cef-forwarder

# Verify status
sudo systemctl status pano-cef-forwarder
```

#### Step 6: Test
```bash
# Send test message
echo '{"subtype":"login","status":"success","sender_sw_version":"11.0.4","type":"globalprotect","srcuser":"test@example.com"}' | nc -u -w1 127.0.0.1 5514

# Check logs
sudo tail -20 /var/log/pano-cef-forwarder/stdout.log
```

#### Step 7: Configure Panorama

In Panorama UI:
1. **Device** → **Server Profiles** → **Syslog**
2. Create new server profile:
   - **Name**: `CEF-Forwarder`
   - **Server**: `<forwarder_IP>`
   - **Port**: `5514`
   - **Format**: `BSD`
   - **Facility**: `LOG_USER`
3. **Objects** → **Log Forwarding**
4. Create profile and match GlobalProtect logs
5. Set Syslog Profile to `CEF-Forwarder`
6. Commit changes

---

### ✅ Verification Checklist

```bash
# Service running?
systemctl is-active pano-cef-forwarder
# Expected: active

# Port listening?
sudo netstat -tulpn | grep 5514
# Expected: python3 listening on 0.0.0.0:5514

# Can send test?
echo 'test' | nc -u -w1 127.0.0.1 5514 && echo "OK" || echo "FAIL"
# Expected: OK

# SIEM receiving?
# On SIEM: sudo tcpdump -n -i any udp port 514 -c 5
# Expected: CEF formatted messages
```

---

### 📊 Performance Test

```bash
cd /home/claude/pano-cef-forwarder

# Run 100k message test
./performance-test.sh 127.0.0.1 5514 100000 1000

# Expected: ≥25,000 EPS
```

---

### 🔍 Troubleshooting

**Service won't start:**
```bash
sudo journalctl -u pano-cef-forwarder -n 50
```

**Not receiving messages:**
```bash
# Verify firewall
sudo firewall-cmd --list-all | grep 5514

# Test locally
echo 'test' | nc -u -w1 127.0.0.1 5514

# Check for binding errors
sudo ss -tulpn | grep 5514
```

**SIEM not receiving:**
```bash
# Test connectivity
nc -zv <SIEM_IP> 514

# Capture outbound
sudo tcpdump -n -i any dst <SIEM_IP> and port 514 -c 10
```

---

### 📁 Important Files

| File | Purpose |
|------|---------|
| `/etc/pano-cef-forwarder/config.yaml` | Configuration |
| `/var/log/pano-cef-forwarder/stdout.log` | Service logs |
| `/opt/pano-cef-forwarder/forwarder.py` | Main service |

---

### 🎯 Common Commands

```bash
# View logs
sudo tail -f /var/log/pano-cef-forwarder/stdout.log

# Restart service
sudo systemctl restart pano-cef-forwarder

# Test connectivity
nc -zv <SIEM_IP> 514

# Send test message
echo '{"subtype":"login","status":"success","type":"globalprotect"}' | nc -u 127.0.0.1 5514
```

---

### 📈 Performance Tips

**For maximum throughput:**

1. Use UDP protocol (both input and output)
2. Increase kernel buffers:
   ```bash
   sudo sysctl -w net.core.rmem_max=134217728
   sudo sysctl -w net.core.rmem_default=8388608
   ```
3. Ensure dedicated network interface
4. Monitor CPU: `top -p $(pgrep -f forwarder.py)`

---

### 🆘 Need Help?

1. Check logs: `sudo journalctl -u pano-cef-forwarder -f`
2. Run diagnostics: `./test.sh`
3. Review README.md for detailed troubleshooting
4. Check CEF-EXAMPLES.md for output format reference

---

### 📞 Next Steps

1. ✅ Service installed and running
2. ✅ Firewall configured
3. ✅ Test message successful
4. ⏳ Configure Panorama to send logs
5. ⏳ Verify SIEM receiving CEF logs
6. ⏳ Performance test passed
7. ⏳ Production deployment approved

---

**Installation complete! Service ready for production use.**

For detailed documentation, see: `README.md`
For deployment checklist, see: `DEPLOYMENT-CHECKLIST.md`
For CEF examples, see: `CEF-EXAMPLES.md`
