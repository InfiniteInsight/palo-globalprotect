# Deployment Checklist - Panorama to CEF Forwarder

## Pre-Deployment

- [ ] Rocky Linux 8/9 VM provisioned
- [ ] Minimum 2 vCPU / 4GB RAM
- [ ] Network connectivity to Panorama
- [ ] Network connectivity to SIEM collector
- [ ] SIEM collector IP and port documented
- [ ] Root/sudo access available

## Installation

- [ ] Files extracted to deployment directory
- [ ] `install.sh` executed successfully
- [ ] No errors in installation output
- [ ] Service user `panocef` created
- [ ] Directories created with correct permissions

## Configuration

- [ ] `/etc/pano-cef-forwarder/config.yaml` edited
- [ ] Input protocol set (udp/tcp)
- [ ] Input port configured (default: 5514)
- [ ] Output target_ip set to SIEM IP
- [ ] Output target_port set to SIEM port (default: 514)
- [ ] Firewall rule added for input port

## Verification

- [ ] Service starts: `systemctl start pano-cef-forwarder`
- [ ] Service enabled: `systemctl enable pano-cef-forwarder`
- [ ] Service status shows "active (running)"
- [ ] Port listening: `netstat -tulpn | grep 5514`
- [ ] Test message sent successfully
- [ ] CEF output visible on SIEM collector

## Testing

- [ ] Functional test passed (`./test.sh`)
- [ ] All severity levels tested (1,3,5,7,8,9)
- [ ] Performance test passed (`./performance-test.sh`)
- [ ] Throughput ≥25,000 EPS achieved
- [ ] No error messages in logs
- [ ] CEF format validated

## Panorama Configuration

- [ ] Panorama syslog forwarding configured
- [ ] Target IP set to forwarder IP
- [ ] Target port set to 5514 (or configured port)
- [ ] Protocol matches forwarder (UDP recommended)
- [ ] Log types: GlobalProtect
- [ ] Facility: user (local3-local7)
- [ ] Test log sent from Panorama

## Production Readiness

- [ ] Log rotation configured (automatic)
- [ ] SELinux configured (if enforcing)
- [ ] Monitoring alerts configured
- [ ] Backup of configuration file
- [ ] Documentation updated with IPs/ports
- [ ] Runbook created for operations team
- [ ] Contact information documented

## Monitoring

- [ ] Service status check added to monitoring
- [ ] Log file growth monitored
- [ ] Throughput metrics collected
- [ ] Error rate alerts configured
- [ ] SIEM receiving logs confirmed

## Post-Deployment

- [ ] 24-hour stability test completed
- [ ] Peak load tested
- [ ] Failover procedure documented
- [ ] Team training completed
- [ ] Handoff to operations team
- [ ] Close deployment ticket

## Quick Reference

### Service Management
```bash
sudo systemctl start pano-cef-forwarder
sudo systemctl stop pano-cef-forwarder
sudo systemctl restart pano-cef-forwarder
sudo systemctl status pano-cef-forwarder
```

### Log Viewing
```bash
sudo tail -f /var/log/pano-cef-forwarder/stdout.log
sudo tail -f /var/log/pano-cef-forwarder/stderr.log
sudo journalctl -u pano-cef-forwarder -f
```

### Testing
```bash
echo 'test message' | nc -u -w1 127.0.0.1 5514
sudo tcpdump -n -i any udp port 514 -A
```

### Configuration
```bash
sudo vi /etc/pano-cef-forwarder/config.yaml
sudo systemctl restart pano-cef-forwarder
```

## Troubleshooting Decision Tree

```
Service not starting?
  ├─ Check logs: journalctl -u pano-cef-forwarder -n 50
  ├─ Verify config: python3 -c "import yaml; yaml.safe_load(open('/etc/pano-cef-forwarder/config.yaml'))"
  └─ Check permissions: ls -la /opt/pano-cef-forwarder/

Not receiving messages?
  ├─ Port listening? netstat -tulpn | grep 5514
  ├─ Firewall open? firewall-cmd --list-all
  ├─ Test locally: echo 'test' | nc -u -w1 127.0.0.1 5514
  └─ Check Panorama config

Messages not reaching SIEM?
  ├─ Test connectivity: nc -zv <SIEM_IP> <SIEM_PORT>
  ├─ Capture outbound: tcpdump -n dst port 514 -A
  ├─ Verify SIEM config
  └─ Check network routing

Low throughput?
  ├─ Check CPU: top -p $(pgrep -f forwarder.py)
  ├─ Increase buffers: sysctl -w net.core.rmem_max=134217728
  └─ Consider multiple instances
```

## Emergency Contacts

| Role | Name | Contact |
|------|------|---------|
| Primary Engineer | Evan | - |
| Backup Engineer | - | - |
| SIEM Team | - | - |
| Network Team | - | - |
| Manager | - | - |

## Notes

Date Deployed: _______________
Deployed By: _______________
Version: 1.0
Environment: Production / Staging / Dev

Special Considerations:
_____________________________________________
_____________________________________________
_____________________________________________
