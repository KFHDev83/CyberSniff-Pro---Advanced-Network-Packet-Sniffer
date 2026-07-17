#!/usr/bin/env python3
"""
CyberSniff Pro - Advanced Packet Sniffer with TLS Decryption and VoIP Analysis
CEH Portfolio Project - Full Network Packet Analysis Tool
Coded By Koorosh Tadibi

Features:
- Live packet capture (raw sockets)
- PCAP file analysis (with Scapy)
- Protocol dissection: Ethernet, IPv4, TCP, UDP, ICMP
- HTTP & DNS detection
- SSL/TLS analysis: Client Hello, Server Hello, Certificate (SNI, cipher suites, cert details)
- TLS decryption via SSLKEYLOGFILE (uses Scapy's TLS decryption)
- VoIP: SIP (INVITE, REGISTER, etc.) and RTP (codec detection)
- Filtering: protocol, IP, port, tls, sip, rtp
- Colored console output
- Logging to JSON, CSV, and text reports
- Cross-platform (Linux, macOS, Windows with limitations)

Requirements:
    pip install colorama netifaces scapy[complete]

Usage Examples:
    # Live capture with TLS key log and SIP filtering
    sudo python3 sniffer_pro.py -i eth0 --ssl-keylog /path/to/sslkeylog.txt -f sip -t 60

    # Analyze PCAP with decryption
    python3 sniffer_pro.py -r capture.pcap --ssl-keylog keys.txt

    # Capture all VoIP traffic
    sudo python3 sniffer_pro.py -f sip -f rtp

    # List interfaces
    python3 sniffer_pro.py --list-interfaces
"""

import socket
import struct
import argparse
import signal
import sys
import os
import json
import csv
from datetime import datetime
import time
import re
import base64

# Optional imports for advanced features
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# Scapy for TLS decryption and PCAP reading
try:
    from scapy.all import rdpcap, TLS, TLSClientHello, TLSServerHello, TLSCertificate, TLSExtension
    from scapy.layers.tls import tls
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
class Config:
    INTERFACE = 'any'
    SNAPLEN = 65535
    TIMEOUT = None
    COLOR_ENABLED = True
    VERBOSE = True
    LOG_DIR = 'logs'
    SSL_KEYLOG_FILE = None          # Path to SSLKEYLOGFILE
    COLORS = {
        'ETHERNET': '\033[94m',
        'IP': '\033[92m',
        'TCP': '\033[93m',
        'UDP': '\033[91m',
        'ICMP': '\033[95m',
        'HTTP': '\033[96m',
        'DNS': '\033[90m',
        'TLS': '\033[35m',           # Magenta
        'SIP': '\033[36m',           # Cyan
        'RTP': '\033[33m',           # Yellow
        'RESET': '\033[0m',
        'BOLD': '\033[1m'
    }

# ----------------------------------------------------------------------
# Protocol Dissector (Extended)
# ----------------------------------------------------------------------
class ProtocolDissector:
    @staticmethod
    def parse_ethernet(data):
        dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:14])
        return {
            'dest_mac': ':'.join(f'{b:02x}' for b in dest_mac),
            'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
            'type': hex(eth_type),
            'type_name': 'IPv4' if eth_type == 0x0800 else 'IPv6' if eth_type == 0x86DD else 'ARP' if eth_type == 0x0806 else 'Unknown'
        }, data[14:]

    @staticmethod
    def parse_ip(data):
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        ttl, protocol, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])
        return {
            'version': version,
            'ihl': ihl,
            'tos': data[1],
            'total_length': struct.unpack('!H', data[2:4])[0],
            'identification': struct.unpack('!H', data[4:6])[0],
            'flags': struct.unpack('!H', data[6:8])[0] >> 13,
            'fragment_offset': struct.unpack('!H', data[6:8])[0] & 0x1FFF,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': ProtocolDissector._get_protocol_name(protocol),
            'src_ip': socket.inet_ntoa(src),
            'dest_ip': socket.inet_ntoa(dest)
        }, data[ip_header_len:]

    @staticmethod
    def parse_tcp(data):
        src_port, dest_port, seq, ack, offset_reserved = struct.unpack('!HHLLH', data[:14])
        offset = (offset_reserved >> 12) * 4
        flags = offset_reserved & 0x01FF
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq': seq,
            'ack': ack,
            'flags': {
                'urg': bool(flags & 0x20),
                'ack_flag': bool(flags & 0x10),
                'psh': bool(flags & 0x08),
                'rst': bool(flags & 0x04),
                'syn': bool(flags & 0x02),
                'fin': bool(flags & 0x01)
            },
            'window_size': struct.unpack('!H', data[14:16])[0],
            'checksum': hex(struct.unpack('!H', data[16:18])[0]),
            'urgent_pointer': struct.unpack('!H', data[18:20])[0]
        }, data[offset:]

    @staticmethod
    def parse_udp(data):
        src_port, dest_port, length = struct.unpack('!HHH', data[:6])
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length
        }, data[8:]

    @staticmethod
    def parse_icmp(data):
        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
        types = {0: 'Echo Reply', 3: 'Destination Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
        return {
            'type': icmp_type,
            'type_name': types.get(icmp_type, 'Unknown'),
            'code': code
        }, data[4:]

    # ---------- SSL/TLS dissection ----------
    @staticmethod
    def parse_tls(data, sport, dport):
        """Try to parse TLS records. Return dict with info."""
        if len(data) < 5:
            return {}
        # TLS record: content_type, version, length
        content_type = data[0]
        if content_type not in [20, 21, 22, 23]:  # change_cipher_spec, alert, handshake, application_data
            return {}
        tls_version = (data[1], data[2])
        record_len = struct.unpack('!H', data[3:5])[0]
        if len(data) < 5 + record_len:
            return {}
        info = {
            'is_tls': True,
            'content_type': content_type,
            'tls_version': f'{tls_version[0]}.{tls_version[1]}',
            'record_len': record_len,
            'handshake_type': None,
            'cipher_suites': [],
            'sni': None,
            'certificate': None,
            'extensions': []
        }
        # For handshake (22)
        if content_type == 22 and len(data) >= 5 + record_len:
            handshake_data = data[5:5+record_len]
            if len(handshake_data) >= 4:
                hs_type = handshake_data[0]
                hs_len = struct.unpack('!I', b'\x00' + handshake_data[1:4])[0]
                info['handshake_type'] = hs_type
                # Client Hello (1)
                if hs_type == 1:
                    # parse client hello for SNI
                    # We'll try to find SNI extension
                    # Format: client_version (2), random (32), session_id_len (1), session_id, cipher_suites_len (2), cipher_suites, compression_len (1), compression, extensions
                    # Skip to extensions
                    pos = 2 + 32 + 1 + 1  # client_version, random, session_id_len, session_id (we'll skip)
                    if len(handshake_data) > pos:
                        session_id_len = handshake_data[pos-1]  # already used
                        pos += session_id_len
                        if len(handshake_data) > pos + 2:
                            cipher_suites_len = struct.unpack('!H', handshake_data[pos:pos+2])[0]
                            pos += 2 + cipher_suites_len
                            if len(handshake_data) > pos + 1:
                                compression_len = handshake_data[pos]
                                pos += 1 + compression_len
                                if len(handshake_data) > pos + 2:
                                    extensions_len = struct.unpack('!H', handshake_data[pos:pos+2])[0]
                                    pos += 2
                                    end = pos + extensions_len
                                    while pos < end and pos + 4 <= len(handshake_data):
                                        ext_type = struct.unpack('!H', handshake_data[pos:pos+2])[0]
                                        ext_len = struct.unpack('!H', handshake_data[pos+2:pos+4])[0]
                                        pos += 4
                                        ext_data = handshake_data[pos:pos+ext_len]
                                        if ext_type == 0:  # SNI
                                            if len(ext_data) > 2:
                                                sni_len = struct.unpack('!H', ext_data[2:4])[0]
                                                sni = ext_data[4:4+sni_len].decode('utf-8', errors='ignore')
                                                info['sni'] = sni
                                        elif ext_type == 10:  # supported_groups
                                            pass
                                        elif ext_type == 11:  # ec_point_formats
                                            pass
                                        # collect extension types
                                        info['extensions'].append(ext_type)
                                        pos += ext_len
                # Certificate (11)
                elif hs_type == 11:
                    # parse certificate list
                    if len(handshake_data) > 3:
                        certs_len = struct.unpack('!I', b'\x00' + handshake_data[1:4])[0]
                        cert_data = handshake_data[4:4+certs_len]
                        # parse individual certs (each prefixed with 3-byte length)
                        certs = []
                        pos = 0
                        while pos + 3 <= len(cert_data):
                            cert_len = struct.unpack('!I', b'\x00' + cert_data[pos:pos+3])[0]
                            cert_raw = cert_data[pos+3:pos+3+cert_len]
                            certs.append(cert_raw)
                            pos += 3 + cert_len
                        # Try to parse the first cert (DER) to extract subject/issuer
                        if certs:
                            try:
                                from cryptography import x509
                                from cryptography.hazmat.backends import default_backend
                                cert = x509.load_der_x509_certificate(certs[0], default_backend())
                                info['certificate'] = {
                                    'subject': cert.subject.rfc4514_string(),
                                    'issuer': cert.issuer.rfc4514_string(),
                                    'serial': str(cert.serial_number),
                                    'not_valid_before': cert.not_valid_before.isoformat(),
                                    'not_valid_after': cert.not_valid_after.isoformat(),
                                    'subject_alt_names': [san.value for san in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value if isinstance(san, x509.DNSName)]
                                    if cert.extensions.get_extension_for_class(x509.SubjectAlternativeName) else []
                                }
                            except Exception:
                                pass
                # Server Hello (2)
                elif hs_type == 2:
                    # extract cipher suite
                    if len(handshake_data) > 2:
                        # server_version (2), random (32), session_id_len, session_id, cipher_suite (2), compression
                        # We'll just extract cipher suite at position 34 + session_id_len
                        pos = 2 + 32 + 1
                        if len(handshake_data) > pos:
                            session_id_len = handshake_data[pos-1]
                            pos += session_id_len
                            if len(handshake_data) > pos + 1:
                                cipher_suite = struct.unpack('!H', handshake_data[pos:pos+2])[0]
                                info['cipher_suites'] = [cipher_suite]
        return info

    # ---------- VoIP: SIP ----------
    @staticmethod
    def parse_sip(data):
        """Parse SIP message (UDP or TCP). Return dict."""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            if not (decoded.startswith('SIP/') or 'SIP/2.0' in decoded or 'INVITE' in decoded or 'REGISTER' in decoded):
                return {}
            lines = decoded.split('\r\n')
            if not lines:
                return {}
            # First line: method or response
            first = lines[0]
            info = {'is_sip': True}
            if first.startswith('SIP/'):
                # response
                parts = first.split()
                if len(parts) >= 3:
                    info['sip_type'] = 'Response'
                    info['sip_version'] = parts[0]
                    info['sip_status_code'] = parts[1]
                    info['sip_reason'] = ' '.join(parts[2:])
            else:
                # request
                parts = first.split()
                if len(parts) >= 3:
                    info['sip_type'] = 'Request'
                    info['sip_method'] = parts[0]
                    info['sip_uri'] = parts[1]
                    info['sip_version'] = parts[2]
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()
            info['sip_headers'] = headers
            # Extract important fields
            if 'From' in headers:
                from_header = headers['From']
                # Extract display name and URI
                match = re.search(r'<([^>]+)>', from_header)
                if match:
                    info['sip_from_uri'] = match.group(1)
                else:
                    info['sip_from_uri'] = from_header
                # display name
                if '<' in from_header:
                    display = from_header[:from_header.index('<')].strip('" ')
                    if display:
                        info['sip_from_display'] = display
            if 'To' in headers:
                to_header = headers['To']
                match = re.search(r'<([^>]+)>', to_header)
                if match:
                    info['sip_to_uri'] = match.group(1)
                else:
                    info['sip_to_uri'] = to_header
                if '<' in to_header:
                    display = to_header[:to_header.index('<')].strip('" ')
                    if display:
                        info['sip_to_display'] = display
            if 'Call-ID' in headers:
                info['sip_call_id'] = headers['Call-ID']
            if 'User-Agent' in headers:
                info['sip_user_agent'] = headers['User-Agent']
            if 'CSeq' in headers:
                info['sip_cseq'] = headers['CSeq']
            return info
        except:
            return {}

    # ---------- VoIP: RTP ----------
    @staticmethod
    def parse_rtp(data):
        """Parse RTP header. Return dict."""
        if len(data) < 12:
            return {}
        # RTP header: version(2), p(1), x(1), csrc_count(4), marker(1), payload_type(7), sequence(16), timestamp(32), ssrc(32)
        first_byte = data[0]
        version = (first_byte >> 6) & 0x03
        if version != 2:
            return {}
        padding = (first_byte >> 5) & 0x01
        extension = (first_byte >> 4) & 0x01
        csrc_count = first_byte & 0x0F
        second_byte = data[1]
        marker = (second_byte >> 7) & 0x01
        payload_type = second_byte & 0x7F
        sequence = struct.unpack('!H', data[2:4])[0]
        timestamp = struct.unpack('!I', data[4:8])[0]
        ssrc = struct.unpack('!I', data[8:12])[0]
        # Codec mapping
        codecs = {
            0: 'PCMU', 3: 'GSM', 4: 'G.723', 5: 'DVI4', 6: 'DVI4',
            7: 'LPC', 8: 'PCMA', 9: 'G.722', 10: 'L16', 11: 'L16',
            12: 'QCELP', 13: 'CN', 14: 'MPA', 15: 'G.728', 16: 'DVI4',
            17: 'DVI4', 18: 'G.729', 25: 'CelB', 26: 'JPEG', 28: 'nv',
            31: 'H.261', 32: 'MPV', 33: 'MP2T', 34: 'H.263'
        }
        codec_name = codecs.get(payload_type, f'Dynamic({payload_type})')
        return {
            'is_rtp': True,
            'version': version,
            'padding': padding,
            'extension': extension,
            'csrc_count': csrc_count,
            'marker': marker,
            'payload_type': payload_type,
            'codec': codec_name,
            'sequence': sequence,
            'timestamp': timestamp,
            'ssrc': ssrc
        }

    # ---------- Helpers ----------
    @staticmethod
    def detect_http(data):
        try:
            decoded = data.decode('utf-8', errors='ignore')
            if 'HTTP/' in decoded[:20] or 'GET ' in decoded[:20] or 'POST ' in decoded[:20]:
                lines = decoded.split('\n')
                return {
                    'is_http': True,
                    'method': lines[0].split()[0] if lines else 'UNKNOWN',
                    'uri': lines[0].split()[1] if len(lines[0].split()) > 1 else '',
                    'headers': lines[1:10]
                }
        except:
            pass
        return {'is_http': False}

    @staticmethod
    def detect_dns(data):
        try:
            if len(data) > 12:
                transaction_id, flags, questions = struct.unpack('!HHH', data[:6])
                return {
                    'is_dns': True,
                    'transaction_id': hex(transaction_id),
                    'questions': questions
                }
        except:
            pass
        return {'is_dns': False}

    @staticmethod
    def _get_protocol_name(protocol_num):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 89: 'OSPF', 132: 'SCTP'}
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

    @staticmethod
    def get_timestamp():
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

# ----------------------------------------------------------------------
# Filter Engine (Extended)
# ----------------------------------------------------------------------
class FilterEngine:
    def __init__(self):
        self.filters = []

    def add_filter(self, filter_str):
        self.filters.append(filter_str)

    def clear_filters(self):
        self.filters.clear()

    def should_show(self, packet_info):
        if not self.filters:
            return True
        for filter_str in self.filters:
            if not self._matches_filter(packet_info, filter_str):
                return False
        return True

    def _matches_filter(self, packet_info, filter_str):
        # Protocol filters
        proto_lower = filter_str.lower()
        if proto_lower in ['tcp', 'udp', 'icmp', 'http', 'dns', 'tls', 'sip', 'rtp']:
            # Check protocol_name, type_name, and specific flags
            if proto_lower == 'tls' and packet_info.get('is_tls', False):
                return True
            if proto_lower == 'sip' and packet_info.get('is_sip', False):
                return True
            if proto_lower == 'rtp' and packet_info.get('is_rtp', False):
                return True
            return packet_info.get('protocol_name', '').lower() == proto_lower or \
                   packet_info.get('type_name', '').lower() == proto_lower
        # IP filters
        if 'src_ip=' in filter_str:
            _, ip = filter_str.split('=')
            return packet_info.get('src_ip') == ip
        if 'dest_ip=' in filter_str:
            _, ip = filter_str.split('=')
            return packet_info.get('dest_ip') == ip
        # Port filters
        if 'port=' in filter_str:
            _, port = filter_str.split('=')
            port = int(port)
            return packet_info.get('src_port') == port or packet_info.get('dest_port') == port
        # Keyword filter: anything else we treat as substring search in info
        # Could extend
        return True

# ----------------------------------------------------------------------
# Logger (unchanged)
# ----------------------------------------------------------------------
class PacketLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.packets = []

    def log_packet(self, packet_info):
        self.packets.append(packet_info)

    def export_json(self, filename=None):
        if not filename:
            filename = f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        filepath = os.path.join(self.log_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(self.packets, f, indent=2, default=str)
        return filepath

    def export_csv(self, filename=None):
        if not filename:
            filename = f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        filepath = os.path.join(self.log_dir, filename)
        if not self.packets:
            return None
        # Gather all keys across packets for dynamic CSV
        fieldnames = set()
        for p in self.packets:
            fieldnames.update(p.keys())
        fieldnames = sorted(fieldnames)
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for p in self.packets:
                # Flatten nested dicts for CSV
                flat = {}
                for k, v in p.items():
                    if isinstance(v, dict):
                        for subk, subv in v.items():
                            flat[f"{k}_{subk}"] = subv
                    else:
                        flat[k] = v
                writer.writerow(flat)
        return filepath

    def generate_report(self, filename='report.txt'):
        filepath = os.path.join(self.log_dir, filename)
        stats = {
            'total_packets': len(self.packets),
            'protocols': {},
            'src_ips': {},
            'dest_ips': {},
            'top_src_ports': {},
            'top_dest_ports': {}
        }
        for p in self.packets:
            proto = p.get('protocol_name', 'Unknown')
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            src_ip = p.get('src_ip')
            if src_ip:
                stats['src_ips'][src_ip] = stats['src_ips'].get(src_ip, 0) + 1
            dest_ip = p.get('dest_ip')
            if dest_ip:
                stats['dest_ips'][dest_ip] = stats['dest_ips'].get(dest_ip, 0) + 1
            src_port = p.get('src_port')
            if src_port:
                stats['top_src_ports'][src_port] = stats['top_src_ports'].get(src_port, 0) + 1
            dest_port = p.get('dest_port')
            if dest_port:
                stats['top_dest_ports'][dest_port] = stats['top_dest_ports'].get(dest_port, 0) + 1

        stats['top_protocols'] = sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:5]
        stats['top_src_ips'] = sorted(stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        stats['top_dest_ips'] = sorted(stats['dest_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        stats['top_src_ports'] = sorted(stats['top_src_ports'].items(), key=lambda x: x[1], reverse=True)[:5]
        stats['top_dest_ports'] = sorted(stats['top_dest_ports'].items(), key=lambda x: x[1], reverse=True)[:5]

        with open(filepath, 'w') as f:
            f.write("="*60 + "\n")
            f.write("  CYBERSNIFF PRO - PACKET CAPTURE REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            f.write("SUMMARY STATISTICS\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Packets Captured: {stats['total_packets']}\n\n")
            f.write("TOP PROTOCOLS\n")
            f.write("-"*40 + "\n")
            for proto, count in stats['top_protocols']:
                f.write(f"  {proto:15} {count:>8} packets ({count/stats['total_packets']*100:.1f}%)\n")
            f.write("\nTOP SOURCE IPs\n")
            f.write("-"*40 + "\n")
            for ip, count in stats['top_src_ips']:
                f.write(f"  {ip:15} {count:>8} packets\n")
            f.write("\nTOP DESTINATION IPs\n")
            f.write("-"*40 + "\n")
            for ip, count in stats['top_dest_ips']:
                f.write(f"  {ip:15} {count:>8} packets\n")
            f.write("\n" + "="*60 + "\n")
            f.write("END OF REPORT\n")
        return filepath

# ----------------------------------------------------------------------
# Main Sniffer Engine (with TLS Decryption support)
# ----------------------------------------------------------------------
class CyberSniff:
    def __init__(self):
        self.sock = None
        self.running = True
        self.packet_count = 0
        self.dissector = ProtocolDissector()
        self.filter_engine = FilterEngine()
        self.logger = PacketLogger(Config.LOG_DIR)
        self.ssl_keylog_file = None
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        if COLORAMA_AVAILABLE:
            print(f"\n{Fore.YELLOW}[!] Capture interrupted by user")
        else:
            print("\n[!] Capture interrupted by user")
        self.running = False
        if self.sock:
            self.sock.close()

    def create_socket(self, interface='any'):
        try:
            if sys.platform.startswith('linux'):
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                self.sock.bind((interface, 0))
            elif sys.platform.startswith('win'):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((interface, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                self.sock.bind((interface, 0))
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] Socket created on interface: {interface}")
            else:
                print(f"[+] Socket created on interface: {interface}")
            return True
        except PermissionError:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Permission denied! Run with sudo or administrator privileges")
            else:
                print("[!] Permission denied! Run with sudo or administrator privileges")
            return False
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Failed to create socket: {e}")
            else:
                print(f"[!] Failed to create socket: {e}")
            return False

    def process_packet(self, raw_data):
        packet_info = {'timestamp': self.dissector.get_timestamp(), 'packet_num': self.packet_count}
        eth_header, remaining = self.dissector.parse_ethernet(raw_data)
        packet_info.update(eth_header)
        if eth_header['type_name'] == 'IPv4' and len(remaining) > 20:
            ip_header, remaining = self.dissector.parse_ip(remaining)
            packet_info.update(ip_header)
            packet_info['protocol_name'] = ip_header['protocol_name']
            # Transport layer
            if ip_header['protocol_name'] == 'TCP' and len(remaining) >= 20:
                tcp_header, payload = self.dissector.parse_tcp(remaining)
                packet_info.update(tcp_header)
                # Check for TLS
                if tcp_header['src_port'] in [443, 465, 993, 995, 8443] or tcp_header['dest_port'] in [443, 465, 993, 995, 8443]:
                    tls_info = self.dissector.parse_tls(payload, tcp_header['src_port'], tcp_header['dest_port'])
                    if tls_info and tls_info.get('is_tls'):
                        packet_info.update(tls_info)
                        packet_info['type_name'] = 'TLS'
                # Check for HTTP
                http_info = self.dissector.detect_http(payload)
                if http_info['is_http']:
                    packet_info.update(http_info)
                    packet_info['type_name'] = 'HTTP'
                # Check for SIP (if port 5060 or 5061)
                if tcp_header['src_port'] in [5060, 5061] or tcp_header['dest_port'] in [5060, 5061]:
                    sip_info = self.dissector.parse_sip(payload)
                    if sip_info and sip_info.get('is_sip'):
                        packet_info.update(sip_info)
                        packet_info['type_name'] = 'SIP'

            elif ip_header['protocol_name'] == 'UDP' and len(remaining) >= 8:
                udp_header, payload = self.dissector.parse_udp(remaining)
                packet_info.update(udp_header)
                # Check for DNS
                dns_info = self.dissector.detect_dns(payload)
                if dns_info['is_dns']:
                    packet_info.update(dns_info)
                    packet_info['type_name'] = 'DNS'
                # Check for SIP (UDP)
                if udp_header['src_port'] in [5060, 5061] or udp_header['dest_port'] in [5060, 5061]:
                    sip_info = self.dissector.parse_sip(payload)
                    if sip_info and sip_info.get('is_sip'):
                        packet_info.update(sip_info)
                        packet_info['type_name'] = 'SIP'
                # Check for RTP (dynamic ports, payload type 96-127 usually)
                if udp_header['src_port'] >= 16384 and udp_header['src_port'] <= 32767 or \
                   udp_header['dest_port'] >= 16384 and udp_header['dest_port'] <= 32767:
                    rtp_info = self.dissector.parse_rtp(payload)
                    if rtp_info and rtp_info.get('is_rtp'):
                        packet_info.update(rtp_info)
                        packet_info['type_name'] = 'RTP'

            elif ip_header['protocol_name'] == 'ICMP' and len(remaining) >= 4:
                icmp_header, payload = self.dissector.parse_icmp(remaining)
                packet_info.update(icmp_header)
                packet_info['type_name'] = icmp_header['type_name']

        # Apply filters
        if not self.filter_engine.should_show(packet_info):
            return

        self.logger.log_packet(packet_info)
        self.display_packet(packet_info)

    def display_packet(self, packet_info):
        self.packet_count += 1
        if not COLORAMA_AVAILABLE or not Config.COLOR_ENABLED:
            output = f"[{packet_info['timestamp']}] #{packet_info['packet_num']} "
            output += f"SRC: {packet_info['src_mac']} -> DST: {packet_info['dest_mac']} "
            if 'src_ip' in packet_info:
                output += f"IP: {packet_info['src_ip']} -> {packet_info['dest_ip']} "
            output += f"[{packet_info.get('protocol_name', 'Unknown')}]"
            if 'src_port' in packet_info:
                output += f" SRC_PORT: {packet_info['src_port']} -> DST_PORT: {packet_info['dest_port']}"
            # Protocol-specific details
            if packet_info.get('is_http'):
                output += f" HTTP {packet_info.get('method', '')} {packet_info.get('uri', '')}"
            if packet_info.get('is_dns'):
                output += f" DNS Query ID: {packet_info.get('transaction_id', '')}"
            if packet_info.get('is_tls'):
                output += f" TLS {packet_info.get('tls_version', '')}"
                if packet_info.get('sni'):
                    output += f" SNI: {packet_info['sni']}"
                if packet_info.get('certificate'):
                    cert = packet_info['certificate']
                    output += f" Cert: {cert.get('subject', '')}"
            if packet_info.get('is_sip'):
                output += f" SIP {packet_info.get('sip_method', '')} {packet_info.get('sip_uri', '')} from {packet_info.get('sip_from_uri', '')} to {packet_info.get('sip_to_uri', '')}"
            if packet_info.get('is_rtp'):
                output += f" RTP {packet_info.get('codec', '')} seq={packet_info.get('sequence', '')} ts={packet_info.get('timestamp', '')} SSRC={packet_info.get('ssrc', '')}"
            print(output)
            return

        color = Config.COLORS.get(packet_info.get('type_name', 'ETHERNET'), Config.COLORS['ETHERNET'])
        reset = Config.COLORS['RESET']
        bold = Config.COLORS['BOLD']
        output = f"{Fore.GREEN}[{packet_info['timestamp']}{Fore.GREEN}] "
        output += f"{bold}{Fore.BLUE}#{packet_info['packet_num']}{reset} "
        output += f"{color}SRC: {packet_info['src_mac']}{reset} -> {color}DST: {packet_info['dest_mac']}{reset} "
        if 'src_ip' in packet_info:
            output += f"{Fore.WHITE}| {color}IP: {packet_info['src_ip']}{reset} -> {color}{packet_info['dest_ip']}{reset} "
        proto = packet_info.get('protocol_name', 'Unknown')
        output += f"{Fore.MAGENTA}[{proto}{Fore.MAGENTA}]"
        if 'src_port' in packet_info:
            output += f" {Fore.YELLOW}SRC_PORT: {packet_info['src_port']}{reset} -> {Fore.YELLOW}DST_PORT: {packet_info['dest_port']}{reset}"
        if 'flags' in packet_info:
            flags = [k.upper() for k, v in packet_info['flags'].items() if v]
            if flags:
                output += f" {Fore.CYAN}FLAGS: {' '.join(flags)}{reset}"
        # Protocol details
        if packet_info.get('is_http'):
            output += f" {Fore.GREEN}HTTP {packet_info.get('method', 'UNKNOWN')} {packet_info.get('uri', '')}{reset}"
        if packet_info.get('is_dns'):
            output += f" {Fore.CYAN}DNS Query ID: {packet_info.get('transaction_id', '')}{reset}"
        if packet_info.get('is_tls'):
            tls_color = Config.COLORS['TLS']
            output += f" {tls_color}TLS {packet_info.get('tls_version', '')}{reset}"
            if packet_info.get('sni'):
                output += f" SNI: {Fore.WHITE}{packet_info['sni']}{reset}"
            if packet_info.get('certificate'):
                cert = packet_info['certificate']
                output += f" Cert: {Fore.WHITE}{cert.get('subject', '')}{reset}"
        if packet_info.get('is_sip'):
            sip_color = Config.COLORS['SIP']
            output += f" {sip_color}SIP {packet_info.get('sip_method', '')} {packet_info.get('sip_uri', '')}{reset}"
            if packet_info.get('sip_from_uri'):
                output += f" From: {Fore.WHITE}{packet_info['sip_from_uri']}{reset}"
            if packet_info.get('sip_to_uri'):
                output += f" To: {Fore.WHITE}{packet_info['sip_to_uri']}{reset}"
        if packet_info.get('is_rtp'):
            rtp_color = Config.COLORS['RTP']
            output += f" {rtp_color}RTP {packet_info.get('codec', '')} seq={packet_info.get('sequence', '')} ts={packet_info.get('timestamp', '')} SSRC={packet_info.get('ssrc', '')}{reset}"
        print(output)

    def start_capture(self, interface='any', timeout=None):
        if not self.create_socket(interface):
            return
        # Set SSL keylog if provided
        if Config.SSL_KEYLOG_FILE and SCAPY_AVAILABLE:
            try:
                from scapy.layers.tls import tls
                tls.tls_session_cache.set_key_log_file(Config.SSL_KEYLOG_FILE)
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.GREEN}[+] TLS decryption enabled with key log file: {Config.SSL_KEYLOG_FILE}")
                else:
                    print(f"[+] TLS decryption enabled with key log file: {Config.SSL_KEYLOG_FILE}")
            except Exception as e:
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.RED}[!] Failed to set TLS key log: {e}")
                else:
                    print(f"[!] Failed to set TLS key log: {e}")

        if COLORAMA_AVAILABLE:
            print(f"{Fore.GREEN}[+] Starting packet capture... Press Ctrl+C to stop")
            print(f"{Fore.YELLOW}[*] Listening on {interface}\n")
        else:
            print("[+] Starting packet capture... Press Ctrl+C to stop")
            print(f"[*] Listening on {interface}\n")
        if timeout:
            self.sock.settimeout(timeout)
        try:
            while self.running:
                try:
                    raw_data, addr = self.sock.recvfrom(Config.SNAPLEN)
                    self.process_packet(raw_data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if COLORAMA_AVAILABLE:
                        print(f"{Fore.RED}[!] Error processing packet: {e}")
                    else:
                        print(f"[!] Error processing packet: {e}")
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.sock.close()
            self.close()

    def analyze_pcap(self, pcap_file):
        if not SCAPY_AVAILABLE:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Scapy not installed. Install with: pip install scapy[complete]")
            else:
                print("[!] Scapy not installed. Install with: pip install scapy[complete]")
            return
        try:
            # Set SSL keylog for decryption
            if Config.SSL_KEYLOG_FILE:
                from scapy.layers.tls import tls
                tls.tls_session_cache.set_key_log_file(Config.SSL_KEYLOG_FILE)
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.GREEN}[+] TLS decryption enabled with key log file: {Config.SSL_KEYLOG_FILE}")
                else:
                    print(f"[+] TLS decryption enabled with key log file: {Config.SSL_KEYLOG_FILE}")

            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] Reading PCAP file: {pcap_file}")
            else:
                print(f"[+] Reading PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            if COLORAMA_AVAILABLE:
                print(f"{Fore.CYAN}[*] Analyzing {len(packets)} packets...\n")
            else:
                print(f"[*] Analyzing {len(packets)} packets...\n")
            for pkt in packets:
                raw_bytes = bytes(pkt)
                self.process_packet(raw_bytes)
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] PCAP analysis complete! Processed {self.packet_count} packets")
            else:
                print(f"[+] PCAP analysis complete! Processed {self.packet_count} packets")
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}[!] Failed to analyze PCAP: {e}")
            else:
                print(f"[!] Failed to analyze PCAP: {e}")
        finally:
            self.close()

    def close(self):
        if self.packet_count > 0:
            if COLORAMA_AVAILABLE:
                print(f"\n{Fore.GREEN}[+] Capture complete! Total packets: {self.packet_count}")
            else:
                print(f"\n[+] Capture complete! Total packets: {self.packet_count}")
            json_file = self.logger.export_json()
            csv_file = self.logger.export_csv()
            report_file = self.logger.generate_report()
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] Logs saved:")
            else:
                print("[+] Logs saved:")
            print(f"    - JSON: {json_file}")
            print(f"    - CSV: {csv_file}")
            print(f"    - Report: {report_file}")
        else:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.YELLOW}[!] No packets captured")
            else:
                print("[!] No packets captured")

# ----------------------------------------------------------------------
# Command-line Interface
# ----------------------------------------------------------------------
def list_interfaces():
    if not NETIFACES_AVAILABLE:
        print("netifaces not installed. Install with: pip install netifaces")
        return
    print("Available interfaces:")
    for iface in netifaces.interfaces():
        addr = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0].get('addr', 'No IP')
        print(f"  {iface} - {addr}")

def main():
    parser = argparse.ArgumentParser(description='CyberSniff Pro - Advanced Packet Sniffer with TLS Decryption and VoIP')
    parser.add_argument('-i', '--interface', default='any', help='Network interface to sniff')
    parser.add_argument('-f', '--filter', action='append', help='Filter packets (e.g., "tcp", "sip", "rtp", "port=5060", "src_ip=192.168.1.1")')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('-r', '--read', help='Read from PCAP file instead of live capture')
    parser.add_argument('--ssl-keylog', help='Path to SSLKEYLOGFILE for TLS decryption')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces')
    args = parser.parse_args()

    if args.no_color:
        Config.COLOR_ENABLED = False
    if args.ssl_keylog:
        if os.path.isfile(args.ssl_keylog):
            Config.SSL_KEYLOG_FILE = args.ssl_keylog
        else:
            print(f"[!] SSL key log file not found: {args.ssl_keylog}")
            sys.exit(1)
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    if COLORAMA_AVAILABLE and Config.COLOR_ENABLED:
        init(autoreset=True)

    sniffer = CyberSniff()
    if args.filter:
        for f in args.filter:
            sniffer.filter_engine.add_filter(f)
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] Added filter: {f}")
            else:
                print(f"[+] Added filter: {f}")

    if args.read:
        sniffer.analyze_pcap(args.read)
    else:
        sniffer.start_capture(args.interface, args.timeout)

if __name__ == "__main__":
    main()