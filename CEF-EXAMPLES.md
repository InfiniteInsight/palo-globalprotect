# Sample CEF Outputs - Reference

This file shows example CEF outputs for different GlobalProtect event types.

## Severity 1 - Successful Login

**Input (JSON):**
```json
{
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
}
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|login|1|rt=2025-01-15T10:30:45 PanOSDeviceSN=012345678901 PanOSLogTimeStamp=2025-01-15T10:30:45 PanOSSourceUserName=john.doe@example.com PanOSSourceRegion=US-East PanOSEndpointDeviceName=LAPTOP-001 PanOSPublicIPv4=203.0.113.45 PanOSPrivateIPv4=192.168.1.100 PanOSEndpointOSType=Windows PanOSEndpointOSVersion=10.0.19044 PanOSGlobalProtectClientVersion=6.0.4 PanOSGateway=vpn-gw-01.example.com PanOSEventStatus=success
```

---

## Severity 5 - Failed Authentication

**Input (JSON):**
```json
{
  "subtype": "auth",
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
}
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|auth|5|rt=2025-01-15T10:31:00 PanOSDeviceSN=012345678901 PanOSLogTimeStamp=2025-01-15T10:31:00 PanOSSourceUserName=jane.smith@example.com PanOSSourceRegion=US-West PanOSEndpointDeviceName=LAPTOP-002 PanOSPublicIPv4=203.0.113.89 PanOSQuarantineReason=Invalid credentials PanOSEndpointOSType=macOS PanOSEndpointOSVersion=14.2.1 PanOSEventStatus=failed
```

---

## Severity 7 - Tunnel Down

**Input (JSON):**
```json
{
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
}
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|tunnel-down|7|rt=2025-01-15T10:34:45 PanOSDeviceSN=012345678901 PanOSLogTimeStamp=2025-01-15T10:34:45 PanOSTunnelType=IPSec PanOSSourceUserName=charlie.brown@example.com PanOSGateway=vpn-gw-01.example.com PanOSLoginDuration=3600 PanOSEventStatus=disconnected
```

---

## Severity 8 - Gateway Error

**Input (JSON):**
```json
{
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
}
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|gateway-error|8|rt=2025-01-15T10:32:15 PanOSDeviceSN=012345678901 PanOSLogTimeStamp=2025-01-15T10:32:15 PanOSSourceUserName=bob.jones@example.com PanOSConnectionError=Gateway unavailable PanOSConnectionErrorID=E-503 PanOSGateway=vpn-gw-02.example.com PanOSGPGatewayLocation=New York PanOSEventStatus=failed
```

---

## Severity 9 - Quarantine Event

**Input (JSON):**
```json
{
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
}
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|auth|9|rt=2025-01-15T10:33:30 PanOSDeviceSN=012345678901 PanOSLogTimeStamp=2025-01-15T10:33:30 PanOSSourceUserName=alice.williams@example.com PanOSEndpointDeviceName=LAPTOP-003 PanOSPublicIPv4=203.0.113.123 PanOSHostID=host-123-abc PanOSQuarantineReason=Device quarantine due to compliance failure PanOSEventStatus=blocked
```

---

## Key=Value Format (Legacy)

**Input:**
```
subtype=logout status=success sender_sw_version=11.0.4 type=globalprotect serial=012345678901 srcuser=test.user@example.com gateway=vpn-gw-01.example.com login_duration=7200
```

**Output (CEF):**
```
CEF:0|Palo Alto Networks|PAN-OS|11.0.4|globalprotect|logout|1|PanOSDeviceSN=012345678901 PanOSSourceUserName=test.user@example.com PanOSGateway=vpn-gw-01.example.com PanOSLoginDuration=7200 PanOSEventStatus=success
```

---

## CEF Field Mapping Reference

| Source Field | CEF Extension | Description |
|--------------|---------------|-------------|
| receive_time | rt | Receive timestamp |
| serial | PanOSDeviceSN | Device serial number |
| time_generated | PanOSLogTimeStamp | Log generation time |
| vsys | PanOSVirtualSystem | Virtual system |
| eventid | PanOSEventID | Event ID |
| stage | PanOSStage | Connection stage |
| auth_method | PanOSAuthMethod | Authentication method |
| tunnel_type | PanOSTunnelType | Tunnel type (IPSec, SSL) |
| srcuser | PanOSSourceUserName | Source username |
| srcregion | PanOSSourceRegion | Source region |
| machinename | PanOSEndpointDeviceName | Endpoint device name |
| public_ip | PanOSPublicIPv4 | Public IPv4 address |
| public_ipv6 | PanOSPublicIPv6 | Public IPv6 address |
| private_ip | PanOSPrivateIPv4 | Private IPv4 address |
| private_ipv6 | PanOSPrivateIPv6 | Private IPv6 address |
| hostid | PanOSHostID | Host ID |
| serialnumber | PanOSDeviceSN | Serial number |
| client_ver | PanOSGlobalProtectClientVersion | GP client version |
| client_os | PanOSEndpointOSType | Endpoint OS type |
| client_os_ver | PanOSEndpointOSVersion | Endpoint OS version |
| repeatcnt | PanOSCountOfRepeats | Repeat count |
| reason | PanOSQuarantineReason | Quarantine reason |
| error | PanOSConnectionError | Connection error |
| opaque | PanOSDescription | Description/opaque data |
| status | PanOSEventStatus | Event status |
| location | PanOSGPGatewayLocation | Gateway location |
| login_duration | PanOSLoginDuration | Login duration (seconds) |
| connect_method | PanOSConnectionMethod | Connection method |
| error_code | PanOSConnectionErrorID | Error code |
| portal | PanOSPortal | Portal name |
| seqno | PanOSSequenceNo | Sequence number |
| actionflags | PanOSActionFlags | Action flags |
| high_res_timestamp | PanOSTimeGeneratedHighResolution | High-res timestamp |
| selection_type | PanOSGatewaySelectionType | Gateway selection type |
| response_time | PanOSSSLResponseTime | SSL response time |
| priority | PanOSGatewayPriority | Gateway priority |
| attempted_gateways | PanOSAttemptedGateways | Attempted gateways |
| gateway | PanOSGateway | Gateway name |

---

## Validation Commands

### Validate CEF Header Format
```bash
# Should match: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
echo '<CEF_LINE>' | grep -E '^CEF:0\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[0-9]+\|'
```

### Extract Severity from CEF
```bash
# Extract severity (7th field)
echo '<CEF_LINE>' | cut -d'|' -f7
```

### Count Extension Fields
```bash
# Count number of key=value pairs
echo '<CEF_LINE>' | grep -o '[^ ]*=' | wc -l
```

### Verify Field Escaping
```bash
# Check for proper escaping of = and \
echo '<CEF_LINE>' | grep -E '(\\\\|\\=)'
```

---

## Integration with SIEM

### Azure Sentinel KQL Query
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where DeviceProduct == "PAN-OS"
| where DeviceEventCategory == "globalprotect"
| extend Username = extract(@"PanOSSourceUserName=([^ ]+)", 1, AdditionalExtensions)
| extend EventStatus = extract(@"PanOSEventStatus=([^ ]+)", 1, AdditionalExtensions)
| extend Gateway = extract(@"PanOSGateway=([^ ]+)", 1, AdditionalExtensions)
| project TimeGenerated, LogSeverity, DeviceEventClassID, DeviceCustomString2, Username, EventStatus, Gateway
```

### Splunk Search
```spl
sourcetype=cef DeviceVendor="Palo Alto Networks" DeviceProduct="PAN-OS"
| rex field=_raw "PanOSSourceUserName=(?<username>[^ ]+)"
| rex field=_raw "PanOSEventStatus=(?<status>[^ ]+)"
| rex field=_raw "PanOSGateway=(?<gateway>[^ ]+)"
| table _time, Severity, Name, username, status, gateway
```

---

## Notes

1. All timestamps should be in ISO 8601 format (YYYY-MM-DDTHH:MM:SS)
2. Field values containing `=` or `\` are automatically escaped
3. Empty/null fields are omitted from CEF output
4. Severity ranges from 0 (lowest) to 10 (highest)
5. The `rt` field uses the receive_time from the log
6. All custom fields are prefixed with `PanOS` for namespace isolation
