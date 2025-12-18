#!/usr/bin/env python3
"""
CEF Interceptor for Palo Alto GlobalProtect Logs
Intercepts CEF messages, applies dynamic severity mapping, and forwards to SIEM.

Flow: Panorama → Interceptor (parse + modify severity) → LogStash/AMA → Sentinel
"""

import socket
import sys
import argparse
import logging
import re
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_cef(cef_message):
    """
    Parse CEF format message into header and extensions.

    Handles both formats:
    - With severity:    CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|Extensions
    - Without severity: CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Extensions

    Returns:
        dict: {
            'version': str,
            'vendor': str,
            'product': str,
            'device_version': str,
            'signature_id': str,
            'name': str,
            'severity': str or None,
            'extensions': dict,
            'has_severity': bool
        }
    """
    cef_message = cef_message.strip()

    # CEF header pattern: CEF:Version|...|...|...|...|...|[Severity]|Extensions
    if not cef_message.startswith('CEF:'):
        logger.warning(f"Invalid CEF format (no CEF: prefix): {cef_message[:100]}")
        return None

    # Split on first 7 pipes to separate header from extensions
    parts = cef_message.split('|', 7)

    # CEF can have 7 parts (no severity) or 8 parts (with severity)
    if len(parts) < 7:
        logger.warning(f"Invalid CEF format (insufficient fields, need at least 7): {cef_message[:100]}")
        return None

    # Determine if severity field is present
    # If we have 8 parts, severity is at index 6
    # If we have 7 parts, severity is missing and extensions start at index 6
    has_severity = len(parts) == 8

    if has_severity:
        header = {
            'version': parts[0].replace('CEF:', ''),
            'vendor': parts[1],
            'product': parts[2],
            'device_version': parts[3],
            'signature_id': parts[4],
            'name': parts[5],
            'severity': parts[6],
            'extensions_raw': parts[7],
            'has_severity': True
        }
        ext_string = parts[7].strip()
    else:
        # No severity field - extensions are at index 6
        header = {
            'version': parts[0].replace('CEF:', ''),
            'vendor': parts[1],
            'product': parts[2],
            'device_version': parts[3],
            'signature_id': parts[4],
            'name': parts[5],
            'severity': None,
            'extensions_raw': parts[6],
            'has_severity': False
        }
        ext_string = parts[6].strip()

    # Parse extensions (key=value pairs, space-separated)
    # CEF extensions can have escaped = signs (\=) which should not be treated as delimiters
    extensions = {}

    # Simple regex to match key=value pairs, handling escaped equals
    # Pattern: key=value where value can contain \= but not unescaped =
    pattern = r'(\w+)=((?:[^=\s]|\\=)+)'
    matches = re.findall(pattern, ext_string)

    for key, value in matches:
        # Unescape the value (CEF escapes backslash and equals)
        value = value.replace('\\=', '=').replace('\\\\', '\\')
        extensions[key] = value

    header['extensions'] = extensions
    return header


def derive_severity(cef_data):
    """
    Derive dynamic severity (0-10) from CEF extension fields.

    Priority order:
    1. Quarantine events → 9 (Critical)
    2. Error codes or gateway/connection errors → 8 (High)
    3. Tunnel down or gateway unavailable → 7 (High)
    4. Failed authentication/status → 5 (Medium)
    5. Success events → 1 (Low)
    6. Default → 3 (Informational)

    Args:
        cef_data: Parsed CEF dictionary with extensions

    Returns:
        int: Severity level 0-10
    """
    extensions = cef_data.get('extensions', {})

    # Extract relevant fields
    status = extensions.get('PanOSEventStatus', '').lower()
    subtype = cef_data.get('name', '').lower()  # CEF Name field = subtype
    reason = extensions.get('PanOSQuarantineReason', '').lower()
    error_code = extensions.get('PanOSConnectionErrorID', '')
    error = extensions.get('PanOSConnectionError', '').lower()

    # Priority 1: Quarantine events
    if 'quarantine' in reason and reason != '':
        return 9

    # Priority 2: Error codes or specific error subtypes
    if error_code or 'error' in subtype:
        return 8

    # Priority 3: Tunnel/Gateway issues
    if 'tunnel' in subtype and 'down' in subtype:
        return 7
    if 'gateway' in subtype and ('unavailable' in subtype or 'error' in subtype):
        return 7

    # Priority 4: Failed events
    if status == 'failed' or status == 'failure':
        return 5

    # Priority 5: Success events
    if status == 'success' or status == 'successful':
        return 1

    # Default: Informational
    return 3


def modify_cef_severity(cef_message, new_severity):
    """
    Modify or insert the severity field in a CEF message.

    Handles both scenarios:
    - If severity field exists: Overwrites it
    - If severity field is missing: Inserts it in the correct position

    Args:
        cef_message: Original CEF message string
        new_severity: New severity value (0-10)

    Returns:
        str: Modified CEF message
    """
    parts = cef_message.split('|', 7)

    if len(parts) < 7:
        logger.error("Cannot modify CEF severity: invalid format (need at least 7 fields)")
        return cef_message

    if len(parts) == 8:
        # Has severity field - overwrite it (index 6)
        parts[6] = str(new_severity)
        return '|'.join(parts)
    else:
        # Missing severity field - insert it at index 6
        # Current: CEF:0|Vendor|Product|Version|SigID|Name|Extensions
        # Target:  CEF:0|Vendor|Product|Version|SigID|Name|Severity|Extensions
        # parts[0-5] are header, parts[6] is extensions
        parts_with_severity = parts[:6] + [str(new_severity)] + [parts[6]]
        return '|'.join(parts_with_severity)


def fallback_insert_severity(cef_message, default_severity=5):
    """
    Best-effort attempt to insert default severity into CEF-like messages.

    Used when full parsing fails but the message appears to be CEF format.
    This ensures Sentinel can still parse the logs even if our parser fails.

    Args:
        cef_message: Original message string
        default_severity: Severity to insert (default: 5 - Medium)

    Returns:
        str: Message with severity inserted if possible, otherwise original
    """
    cef_message = cef_message.strip()

    # Only attempt if message looks like CEF
    if not cef_message.startswith('CEF:'):
        return cef_message

    # Try simple pipe-based insertion
    parts = cef_message.split('|', 7)

    # If we have exactly 7 parts (6 pipes), likely missing severity
    if len(parts) == 7:
        # Insert severity at position 6
        parts_with_severity = parts[:6] + [str(default_severity)] + [parts[6]]
        result = '|'.join(parts_with_severity)
        logger.info(f"Fallback: Inserted severity={default_severity} into unparseable CEF message")
        return result

    # If we have 8 parts but parsing failed, might have malformed severity
    # Replace whatever is at position 6 with default
    if len(parts) == 8:
        parts[6] = str(default_severity)
        result = '|'.join(parts)
        logger.info(f"Fallback: Replaced potentially malformed severity with {default_severity}")
        return result

    # Can't safely modify - return original
    logger.warning(f"Fallback: Cannot insert severity, forwarding original (parts={len(parts)})")
    return cef_message


def run_interceptor(listen_ip, listen_port, forward_ip, forward_port,
                   input_protocol='udp', output_protocol='udp'):
    """
    Main interceptor loop.

    Listens for CEF messages, applies severity mapping, and forwards to SIEM agent.
    """
    logger.info(f"Starting CEF Interceptor")
    logger.info(f"Input:  {input_protocol.upper()}://{listen_ip}:{listen_port}")
    logger.info(f"Output: {output_protocol.upper()}://{forward_ip}:{forward_port}")

    # Create input socket
    if input_protocol.lower() == 'udp':
        in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)  # 8MB buffer
        in_sock.bind((listen_ip, listen_port))
        logger.info(f"Listening on UDP {listen_ip}:{listen_port}")
    else:
        in_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        in_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        in_sock.bind((listen_ip, listen_port))
        in_sock.listen(128)
        logger.info(f"Listening on TCP {listen_ip}:{listen_port}")

    # Create output socket
    if output_protocol.lower() == 'udp':
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.info("Output socket: UDP")
    else:
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        out_sock.connect((forward_ip, forward_port))
        logger.info(f"Output socket: TCP (connected to {forward_ip}:{forward_port})")

    msg_count = 0
    modified_count = 0
    error_count = 0

    try:
        if input_protocol.lower() == 'udp':
            # UDP mode: receive datagrams
            while True:
                try:
                    data, addr = in_sock.recvfrom(65535)
                    cef_message = data.decode('utf-8', errors='ignore').strip()

                    if not cef_message:
                        continue

                    # Parse CEF
                    cef_data = parse_cef(cef_message)

                    if cef_data:
                        # Derive dynamic severity
                        new_severity = derive_severity(cef_data)
                        old_severity = cef_data.get('severity', 'unknown')

                        # Modify CEF message
                        modified_cef = modify_cef_severity(cef_message, new_severity)

                        # Forward to SIEM agent
                        if output_protocol.lower() == 'udp':
                            out_sock.sendto(modified_cef.encode('utf-8'), (forward_ip, forward_port))
                        else:
                            out_sock.sendall((modified_cef + '\n').encode('utf-8'))

                        msg_count += 1
                        if str(new_severity) != str(old_severity):
                            modified_count += 1

                        # Log stats every 1000 messages
                        if msg_count % 1000 == 0:
                            logger.info(f"Processed {msg_count} messages, modified {modified_count} severities, {error_count} errors")
                    else:
                        error_count += 1
                        # Parsing failed - try fallback severity insertion
                        fallback_cef = fallback_insert_severity(cef_message, default_severity=5)
                        if output_protocol.lower() == 'udp':
                            out_sock.sendto(fallback_cef.encode('utf-8'), (forward_ip, forward_port))
                        else:
                            out_sock.sendall((fallback_cef + '\n').encode('utf-8'))

                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    error_count += 1
                    continue
        else:
            # TCP mode: accept connections
            while True:
                try:
                    conn, client_addr = in_sock.accept()
                    logger.info(f"New connection from {client_addr}")

                    with conn:
                        buf = b""

                        while True:
                            chunk = conn.recv(65535)
                            if not chunk:
                                break

                            buf += chunk

                            # Process complete lines
                            while b'\n' in buf:
                                line, buf = buf.split(b'\n', 1)
                                cef_message = line.decode('utf-8', errors='ignore').strip()

                                if not cef_message:
                                    continue

                                # Parse CEF
                                cef_data = parse_cef(cef_message)

                                if cef_data:
                                    # Derive dynamic severity
                                    new_severity = derive_severity(cef_data)
                                    old_severity = cef_data.get('severity', 'unknown')

                                    # Modify CEF message
                                    modified_cef = modify_cef_severity(cef_message, new_severity)

                                    # Forward to SIEM agent
                                    if output_protocol.lower() == 'udp':
                                        out_sock.sendto(modified_cef.encode('utf-8'), (forward_ip, forward_port))
                                    else:
                                        out_sock.sendall((modified_cef + '\n').encode('utf-8'))

                                    msg_count += 1
                                    if str(new_severity) != str(old_severity):
                                        modified_count += 1
                                else:
                                    error_count += 1
                                    # Parsing failed - try fallback severity insertion
                                    fallback_cef = fallback_insert_severity(cef_message, default_severity=5)
                                    if output_protocol.lower() == 'udp':
                                        out_sock.sendto(fallback_cef.encode('utf-8'), (forward_ip, forward_port))
                                    else:
                                        out_sock.sendall((fallback_cef + '\n').encode('utf-8'))

                    logger.info(f"Connection closed from {client_addr}, processed {msg_count} messages")

                except Exception as e:
                    logger.error(f"Error handling connection: {e}")
                    continue

    except KeyboardInterrupt:
        logger.info(f"\nInterceptor stopped by user")
        logger.info(f"Final stats: {msg_count} messages processed, {modified_count} severities modified, {error_count} errors")
    finally:
        in_sock.close()
        out_sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='CEF Interceptor - Modify Palo Alto GlobalProtect CEF severity dynamically',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Listen on UDP 514, forward to localhost:514
  sudo python3 cef-interceptor.py

  # Custom ports
  sudo python3 cef-interceptor.py --listen-port 5514 --forward-port 10514

  # TCP output to LogStash
  sudo python3 cef-interceptor.py --output-protocol tcp

  # Forward to remote host
  python3 cef-interceptor.py --listen-port 5514 --forward-ip 10.0.0.5 --forward-port 514
        """
    )

    parser.add_argument('--listen-ip', default='0.0.0.0',
                       help='IP address to listen on (default: 0.0.0.0)')
    parser.add_argument('--listen-port', type=int, default=514,
                       help='Port to listen on for incoming CEF (default: 514)')
    parser.add_argument('--forward-ip', default='127.0.0.1',
                       help='IP address to forward to (default: 127.0.0.1)')
    parser.add_argument('--forward-port', type=int, default=514,
                       help='Port to forward to (default: 514)')
    parser.add_argument('--input-protocol', choices=['udp', 'tcp'], default='udp',
                       help='Input protocol (default: udp)')
    parser.add_argument('--output-protocol', choices=['udp', 'tcp'], default='udp',
                       help='Output protocol (default: udp)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Warn if using privileged port
    if args.listen_port < 1024:
        logger.warning(f"Port {args.listen_port} is privileged - requires root or CAP_NET_BIND_SERVICE")

    run_interceptor(
        listen_ip=args.listen_ip,
        listen_port=args.listen_port,
        forward_ip=args.forward_ip,
        forward_port=args.forward_port,
        input_protocol=args.input_protocol,
        output_protocol=args.output_protocol
    )


if __name__ == '__main__':
    main()
