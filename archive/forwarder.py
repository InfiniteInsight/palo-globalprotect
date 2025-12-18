#!/usr/bin/env python3
"""
Minimal high-throughput UDP/TCP syslog processor for Panorama GlobalProtect -> CEF
Targets ≥25k EPS with microsecond-scale overhead per event.
"""

import socket
import sys
import yaml
import json
import time
import logging
from datetime import datetime

CONFIG_PATH = "/etc/pano-cef-forwarder/config.yaml"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config():
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing config file: {e}")
        raise


def derive_severity(fields, default=3):
    """
    Derive CEF severity (0-10) from event fields.
    Uses fast in-memory mapping with no external lookups.
    
    Priority order:
    1. Quarantine events → 9 (Critical)
    2. Success events → 1 (Low)
    3. Failed events → 5 (Medium)
    4. Error events → 8 (High)
    5. Tunnel/Gateway issues → 7 (High)
    6. Default → 3 (Informational)
    """
    status = (fields.get("status") or fields.get("$status") or "").lower()
    subtype = (fields.get("subtype") or fields.get("$subtype") or "").lower()
    reason = (fields.get("reason") or fields.get("$reason") or "").lower()
    error_code = (
        fields.get("error_code") or 
        fields.get("$error_code") or 
        fields.get("error-code") or 
        fields.get("err_code")
    )
    
    # Highest priority: Quarantine
    if "quarantine" in reason:
        return 9
    
    # Success events
    if status == "success":
        return 1
    
    # Failed events
    if status == "failed":
        return 5
    
    # Error conditions
    if error_code or subtype in {"gateway-error", "connection-error"}:
        return 8
    
    # Tunnel/Gateway issues
    if subtype in {"tunnel-down", "gateway-unavailable"}:
        return 7
    
    # Default informational
    return default


def safe_val(v):
    """
    Escape CEF extension values per spec.
    CEF requires escaping backslash and equals in extension values.
    """
    if v is None:
        return ""
    s = str(v)
    # Escape backslash first, then equals
    return s.replace("\\", "\\\\").replace("=", "\\=")


def to_cef(fields, cfg):
    """
    Convert parsed fields to CEF format with dynamic severity.
    Complete field mapping per PAN-OS 10.0+ CEF specification.
    
    Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
    """
    vendor = cfg["cef"]["vendor"]
    product = cfg["cef"]["product"]
    
    # CEF Header fields
    dev_ver = fields.get("sender_sw_version") or fields.get("$sender_sw_version") or "-"
    sig_id = fields.get("type") or fields.get("$type") or "-"
    name = fields.get("subtype") or fields.get("$subtype") or "-"
    severity = derive_severity(fields, cfg["cef"]["default_severity"])
    
    # Construct CEF header
    header = f"CEF:0|{vendor}|{product}|{dev_ver}|{sig_id}|{name}|{severity}|"
    
    # CEF Extensions - Complete PAN-OS GlobalProtect field mapping
    # Includes both standard CEF fields and custom PanOS fields
    ext_pairs = [
        # Standard CEF predefined fields
        ("rt", fields.get("receive_time") or fields.get("$receive_time") or fields.get("log_time")),
        ("start", fields.get("time_generated") or fields.get("$time_generated")),
        ("src", fields.get("public_ip") or fields.get("$public_ip")),
        ("c6a2", fields.get("public_ipv6") or fields.get("$public_ipv6")),
        ("shost", fields.get("machinename") or fields.get("$machinename") or fields.get("endpoint_device_name")),
        ("suser", fields.get("srcuser") or fields.get("$srcuser") or fields.get("source_user")),
        ("sntdom", fields.get("source_user_domain") or fields.get("$source_user_domain")),
        ("suid", fields.get("source_user_uuid") or fields.get("$source_user_uuid")),
        ("duser", fields.get("dest_user") or fields.get("$dest_user")),
        ("dntdom", fields.get("dest_user_domain") or fields.get("$dest_user_domain")),
        ("duid", fields.get("dest_user_uuid") or fields.get("$dest_user_uuid")),
        ("outcome", fields.get("status") or fields.get("$status")),
        ("sourceServiceName", fields.get("log_source") or fields.get("$log_source")),
        ("deviceExternalID", fields.get("log_source_id") or fields.get("$log_source_id")),
        ("dvchost", fields.get("log_source_name") or fields.get("$log_source_name")),
        ("cs3", fields.get("vsys_name") or fields.get("$vsys_name")),
        
        # Custom PanOS fields - Device & Config
        ("PanOSDeviceSN", fields.get("serial") or fields.get("$serial")),
        ("PanOSConfigVersion", fields.get("config_version") or fields.get("$config_version")),
        ("PanOSDeviceName", fields.get("device_name") or fields.get("$device_name")),
        ("PanOSPanoramaSN", fields.get("panorama_serial") or fields.get("$panorama_serial")),
        
        # Virtual System
        ("PanOSVirtualSystem", fields.get("vsys") or fields.get("$vsys")),
        ("PanOSVirtualSystemID", fields.get("vsys_id") or fields.get("$vsys_id")),
        ("PanOSVirtualSystemName", fields.get("vsys_name") or fields.get("$vsys_name")),
        
        # Event Information
        ("PanOSEventID", fields.get("eventid") or fields.get("$eventid")),
        ("PanOSEventIDValue", fields.get("event_id_value") or fields.get("$event_id_value")),
        ("PanOSLogTimeStamp", fields.get("time_generated") or fields.get("$time_generated")),
        ("PanOSTimeGeneratedHighResolution", fields.get("high_res_timestamp") or fields.get("$high_res_timestamp")),
        ("PanOSLogSubtype", fields.get("log_subtype") or fields.get("$log_subtype") or fields.get("subtype")),
        
        # Connection & Auth
        ("PanOSStage", fields.get("stage") or fields.get("$stage")),
        ("PanOSAuthMethod", fields.get("auth_method") or fields.get("$auth_method")),
        ("PanOSTunnelType", fields.get("tunnel_type") or fields.get("$tunnel_type") or fields.get("tunnel")),
        
        # User & Location
        ("PanOSSourceUserName", fields.get("srcuser") or fields.get("$srcuser")),
        ("PanOSSourceRegion", fields.get("srcregion") or fields.get("$srcregion") or fields.get("source_region")),
        
        # Endpoint Information
        ("PanOSEndpointDeviceName", fields.get("machinename") or fields.get("$machinename")),
        ("PanOSEndpointSN", fields.get("endpoint_serial_number") or fields.get("$endpoint_serial_number") or fields.get("endpoint_sn")),
        ("PanOSGlobalProtectClientVersion", fields.get("client_ver") or fields.get("$client_ver") or fields.get("endpoint_gp_version")),
        ("PanOSEndpointOSType", fields.get("client_os") or fields.get("$client_os") or fields.get("endpoint_os_type")),
        ("PanOSEndpointOSVersion", fields.get("client_os_ver") or fields.get("$client_os_ver") or fields.get("endpoint_os_version")),
        ("PanOSHostID", fields.get("hostid") or fields.get("$hostid") or fields.get("host_id")),
        
        # Network Addresses
        ("PanOSPublicIPv4", fields.get("public_ip") or fields.get("$public_ip")),
        ("PanOSPublicIPv6", fields.get("public_ipv6") or fields.get("$public_ipv6")),
        ("PanOSPrivateIPv4", fields.get("private_ip") or fields.get("$private_ip")),
        ("PanOSPrivateIPv6", fields.get("private_ipv6") or fields.get("$private_ipv6")),
        
        # Event Status & Errors
        ("PanOSEventStatus", fields.get("status") or fields.get("$status")),
        ("PanOSQuarantineReason", fields.get("reason") or fields.get("$reason") or fields.get("quarantine_reason")),
        ("PanOSConnectionError", fields.get("error") or fields.get("$error") or fields.get("connection_error")),
        ("PanOSConnectionErrorID", fields.get("error_code") or fields.get("$error_code") or fields.get("connection_error_id")),
        ("PanOSDescription", fields.get("opaque") or fields.get("$opaque")),
        
        # Gateway Information
        ("PanOSGateway", fields.get("gateway") or fields.get("$gateway")),
        ("PanOSGlobalProtectGatewayLocation", fields.get("location") or fields.get("$location") or fields.get("gpg_location")),
        ("PanOSGatewaySelectionType", fields.get("selection_type") or fields.get("$selection_type") or fields.get("gateway_selection_type")),
        ("PanOSGatewayPriority", fields.get("priority") or fields.get("$priority") or fields.get("gateway_priority")),
        ("PanOSAttemptedGateways", fields.get("attempted_gateways") or fields.get("$attempted_gateways")),
        ("PanOSPortal", fields.get("portal") or fields.get("$portal")),
        
        # Connection Metrics
        ("PanOSLoginDuration", fields.get("login_duration") or fields.get("$login_duration")),
        ("PanOSConnectionMethod", fields.get("connect_method") or fields.get("$connect_method") or fields.get("connection_method")),
        ("PanOSSSLResponseTime", fields.get("response_time") or fields.get("$response_time") or fields.get("ssl_response_time")),
        
        # Logging Metadata
        ("PanOSCountOfRepeats", fields.get("repeatcnt") or fields.get("$repeatcnt") or fields.get("count_of_repeats")),
        ("PanOSSequenceNo", fields.get("seqno") or fields.get("$seqno") or fields.get("sequence_no")),
        ("PanOSActionFlags", fields.get("actionflags") or fields.get("$actionflags")),
        
        # Device Group Hierarchy
        ("PanOSDGHierarchyLevel1", fields.get("dg_hier_level_1") or fields.get("$dg_hier_level_1")),
        ("PanOSDGHierarchyLevel2", fields.get("dg_hier_level_2") or fields.get("$dg_hier_level_2")),
        ("PanOSDGHierarchyLevel3", fields.get("dg_hier_level_3") or fields.get("$dg_hier_level_3")),
        ("PanOSDGHierarchyLevel4", fields.get("dg_hier_level_4") or fields.get("$dg_hier_level_4")),
        
        # Log Source Information
        ("LogSourceGroupID", fields.get("log_source_group_id") or fields.get("$log_source_group_id")),
        ("PanOSLogSourceTimeZoneOffset", fields.get("log_source_tz_offset") or fields.get("$log_source_tz_offset")),
        
        # Platform & Tenant Information
        ("PlatformType", fields.get("platform_type") or fields.get("$platform_type")),
        ("PanOSTenantID", fields.get("customer_id") or fields.get("$customer_id") or fields.get("tenant_id")),
        ("ProjectName", fields.get("project_name") or fields.get("$project_name")),
        
        # Prisma-specific flags
        ("PanOSIsPrismaNetworks", fields.get("is_prisma_branch") or fields.get("$is_prisma_branch")),
        ("PanOSIsPrismaUsers", fields.get("is_prisma_mobile") or fields.get("$is_prisma_mobile")),
        
        # Log Management flags
        ("PanOSIsDuplicateLog", fields.get("is_dup_log") or fields.get("$is_dup_log")),
        ("PanOSLogExported", fields.get("is_exported") or fields.get("$is_exported")),
        ("PanOSLogForwarded", fields.get("is_forwarded") or fields.get("$is_forwarded")),
    ]
    
    # Build extensions string
    ext = " ".join([f"{k}={safe_val(v)}" for k, v in ext_pairs if v is not None])
    
    return header + ext


def parse_panorama_line(line):
    """
    Parse incoming syslog line - supports both JSON and key=value formats.
    Optimized for speed with minimal processing.
    """
    line = line.strip()
    if not line:
        return {}
    
    # Try JSON first (fast path for structured logs)
    if line.startswith('{'):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
    
    # Fallback: simple key=value parser (space-delimited)
    # This is a lightweight parser - does not handle quoted values with spaces
    fields = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k.strip()] = v.strip()
    
    return fields


def run_server(cfg):
    """
    Main server loop - handles incoming syslog and forwards as CEF.
    Optimized for high throughput with minimal overhead.
    """
    in_proto = cfg["input"]["protocol"]
    out_proto = cfg["output"]["protocol"]
    listen_addr = (cfg["input"]["listen_ip"], cfg["input"]["listen_port"])
    target_addr = (cfg["output"]["target_ip"], cfg["output"]["target_port"])
    
    logger.info(f"Starting forwarder: {in_proto}://{listen_addr[0]}:{listen_addr[1]} -> {out_proto}://{target_addr[0]}:{target_addr[1]}")
    
    # Initialize output socket
    if out_proto == "udp":
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.info("Output socket: UDP")
    else:
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        out_sock.connect(target_addr)
        logger.info("Output socket: TCP (connected)")
    
    # Initialize input socket and start processing
    if in_proto == "udp":
        logger.info("Input mode: UDP")
        in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set receive buffer size for high throughput
        in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)  # 8MB
        in_sock.bind(listen_addr)
        
        logger.info("Service ready - listening for UDP packets")
        
        msg_count = 0
        start_time = time.time()
        
        while True:
            try:
                data, addr = in_sock.recvfrom(65535)
                fields = parse_panorama_line(data.decode("utf-8", errors="ignore"))
                
                if not fields:
                    continue
                
                cef = to_cef(fields, cfg)
                
                if out_proto == "udp":
                    out_sock.sendto(cef.encode("utf-8"), target_addr)
                else:
                    out_sock.sendall((cef + "\n").encode("utf-8"))
                
                msg_count += 1
                
                # Log throughput stats every 10k messages
                if msg_count % 10000 == 0:
                    elapsed = time.time() - start_time
                    eps = msg_count / elapsed if elapsed > 0 else 0
                    logger.info(f"Processed {msg_count} messages, {eps:.0f} EPS")
                    
            except Exception as e:
                logger.error(f"Error processing message: {e}", exc_info=True)
                continue
    
    else:
        # TCP server mode (simple, single-threaded)
        logger.info("Input mode: TCP")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)  # 8MB
        srv.bind(listen_addr)
        srv.listen(128)
        
        logger.info("Service ready - listening for TCP connections")
        
        while True:
            try:
                conn, client_addr = srv.accept()
                logger.info(f"New connection from {client_addr}")
                
                with conn:
                    buf = b""
                    msg_count = 0
                    
                    while True:
                        chunk = conn.recv(65535)
                        if not chunk:
                            break
                        
                        buf += chunk
                        
                        # Process complete lines
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            fields = parse_panorama_line(line.decode("utf-8", errors="ignore"))
                            
                            if not fields:
                                continue
                            
                            cef = to_cef(fields, cfg)
                            
                            if out_proto == "udp":
                                out_sock.sendto(cef.encode("utf-8"), target_addr)
                            else:
                                out_sock.sendall((cef + "\n").encode("utf-8"))
                            
                            msg_count += 1
                    
                    logger.info(f"Connection closed from {client_addr}, processed {msg_count} messages")
                    
            except Exception as e:
                logger.error(f"Error handling connection: {e}", exc_info=True)
                continue


if __name__ == "__main__":
    try:
        cfg = load_config()
        run_server(cfg)
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.stderr.write(f"[ERROR] {e}\n")
        sys.stderr.flush()
        time.sleep(1)
        sys.exit(1)
