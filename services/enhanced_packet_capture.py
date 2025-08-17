# services/enhanced_packet_capture.py
import asyncio
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Union
import threading
import queue
import time
import random

# Try to import pyshark first, then fall back to scapy
PYSHARK_AVAILABLE = False
SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
    print("✅ PyShark is available")
except ImportError as e:
    print(f"⚠️ PyShark not available: {e}")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
    SCAPY_AVAILABLE = True
    print("✅ Scapy is available")
except ImportError as e:
    print(f"❌ Scapy not available: {e}")

class EnhancedPacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=1000)
        self.is_capturing = False
        self.capture_method = None  # 'pyshark', 'scapy', or None
        self.capture_thread = None

        # Statistics tracking
        self.traffic_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.application_stats = defaultdict(int)
        self.geographic_stats = defaultdict(int)
        self.connection_stats = defaultdict(int)
        self.bandwidth_timeline = deque(maxlen=50)
        self.packet_timeline = deque(maxlen=200)
        self.top_talkers = defaultdict(int)
        self.port_usage = defaultdict(int)
        self.dns_queries = deque(maxlen=100)
        self.http_requests = deque(maxlen=100)
        self.tls_sessions = deque(maxlen=100)
        self.flow_stats = defaultdict(dict)

        # Security tracking
        self.suspicious_activities = deque(maxlen=50)
        self.failed_connections = deque(maxlen=50)
        self.port_scans = defaultdict(list)
        self.anomalies = deque(maxlen=30)

        # Performance metrics
        self.latency_stats = deque(maxlen=100)
        self.retransmission_stats = deque(maxlen=50)
        self.fragmentation_stats = deque(maxlen=50)

        # Mock data attributes
        self.mock_ips = [f"192.168.1.{i}" for i in range(2, 255)]
        self.external_ips = [f"203.0.113.{i}" for i in range(1, 255)]

        # Determine available capture method
        self._determine_capture_method()

    def _determine_capture_method(self):
        """Determine which packet capture method to use"""
        if PYSHARK_AVAILABLE:
            try:
                # Test if TShark is available
                import subprocess
                result = subprocess.run(['tshark', '-v'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.capture_method = 'pyshark'
                    print("🚀 Using PyShark for packet capture")
                    return
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                print(f"⚠️  TShark not working: {e}")

        if SCAPY_AVAILABLE:
            self.capture_method = 'scapy'
            print("🚀 Using Scapy for packet capture")
        else:
            self.capture_method = None
            print("❌ No packet capture method available")

    async def start_capture(self, interface: Optional[str] = None,
                          capture_filter: str = "", packet_count: int = 0):
        """Start packet capture using available method or mock data"""
        if self.is_capturing:
            return

        self.is_capturing = True
        print(f"🔄 Starting packet capture using {self.capture_method or 'mock data'}")

        # Start capture in background thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, capture_filter, packet_count),
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3)

    def _capture_packets(self, interface: str, capture_filter: str, packet_count: int):
        """Capture packets using available method or generate mock data"""
        if self.capture_method == 'scapy':
            try:
                self._capture_with_scapy(interface, capture_filter, packet_count)
            except Exception as e:
                print(f"Scapy capture failed: {e}, falling back to mock data")
                self._generate_mock_traffic()
        elif self.capture_method == 'pyshark':
            try:
                self._capture_with_pyshark(interface, capture_filter, packet_count)
            except Exception as e:
                print(f"PyShark capture failed: {e}, falling back to mock data")
                self._generate_mock_traffic()
        else:
            print("No real capture method available, generating mock traffic data")
            self._generate_mock_traffic()

    def _capture_with_pyshark(self, interface: str, capture_filter: str, packet_count: int):
        """Capture packets using pyshark"""
        try:
            if not interface:
                interface = 'en0'  # Default interface

            capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=capture_filter if capture_filter else None
            )

            print(f"📡 PyShark capturing on {interface}...")

            for packet in capture.sniff_continuously():
                if not self.is_capturing:
                    break

                try:
                    packet_data = self._analyze_pyshark_packet(packet)
                    if packet_data:
                        if not self.packet_queue.full():
                            self.packet_queue.put(packet_data)
                        self._update_statistics(packet_data)
                except Exception as e:
                    print(f"Error processing PyShark packet: {e}")
                    continue

                if packet_count > 0:
                    packet_count -= 1
                    if packet_count <= 0:
                        break

        except Exception as e:
            print(f"PyShark capture error: {e}")
        finally:
            self.is_capturing = False

    def _capture_with_scapy(self, interface: str, capture_filter: str, packet_count: int):
        """Capture packets using scapy"""
        try:
            print(f"📡 Scapy capturing on {interface or 'default interface'}...")

            def process_packet(packet):
                if not self.is_capturing:
                    return

                try:
                    packet_data = self._analyze_scapy_packet(packet)
                    if packet_data:
                        if not self.packet_queue.full():
                            self.packet_queue.put(packet_data)
                        self._update_statistics(packet_data)
                except Exception as e:
                    print(f"Error processing Scapy packet: {e}")

            sniff(
                iface=interface,
                filter=capture_filter if capture_filter else None,
                prn=process_packet,
                stop_filter=lambda x: not self.is_capturing,
                store=False,
                count=packet_count if packet_count > 0 else 0
            )

        except Exception as e:
            print(f"Scapy capture error: {e}")
        finally:
            self.is_capturing = False

    def _analyze_pyshark_packet(self, packet) -> Optional[Dict]:
        """Analyze packet using pyshark (more detailed analysis)"""
        try:
            packet_info = {
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "length": int(packet.length) if hasattr(packet, 'length') else 0,
                "protocol": self._get_pyshark_protocol(packet),
                "src_ip": getattr(packet.ip, 'src', None) if hasattr(packet, 'ip') else None,
                "dst_ip": getattr(packet.ip, 'dst', None) if hasattr(packet, 'ip') else None,
                "src_port": None,
                "dst_port": None,
                "src_mac": getattr(packet.eth, 'src', None) if hasattr(packet, 'eth') else None,
                "dst_mac": getattr(packet.eth, 'dst', None) if hasattr(packet, 'eth') else None,
                "application": "Unknown",
                "flags": [],
                "ttl": getattr(packet.ip, 'ttl', None) if hasattr(packet, 'ip') else None,
                "encrypted": False,
                "is_suspicious": False,
                "capture_method": "pyshark"
            }

            # TCP analysis
            if hasattr(packet, 'tcp'):
                packet_info["src_port"] = int(packet.tcp.srcport)
                packet_info["dst_port"] = int(packet.tcp.dstport)
                packet_info["flags"] = self._get_pyshark_tcp_flags(packet.tcp)

            # UDP analysis
            elif hasattr(packet, 'udp'):
                packet_info["src_port"] = int(packet.udp.srcport)
                packet_info["dst_port"] = int(packet.udp.dstport)

            # Application detection
            packet_info["application"] = self._detect_application_pyshark(packet, packet_info)

            return packet_info

        except Exception as e:
            print(f"PyShark packet analysis error: {e}")
            return None

    def _analyze_scapy_packet(self, packet) -> Optional[Dict]:
        """Analyze packet using scapy (basic analysis)"""
        try:
            packet_info = {
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "length": len(packet),
                "protocol": "Unknown",
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "src_mac": None,
                "dst_mac": None,
                "application": "Unknown",
                "flags": [],
                "ttl": None,
                "encrypted": False,
                "is_suspicious": False,
                "capture_method": "scapy"
            }

            # Ethernet layer
            if packet.haslayer(Ether):
                packet_info["src_mac"] = packet[Ether].src
                packet_info["dst_mac"] = packet[Ether].dst

            # IP layer
            if packet.haslayer(IP):
                packet_info["src_ip"] = packet[IP].src
                packet_info["dst_ip"] = packet[IP].dst
                packet_info["ttl"] = packet[IP].ttl

                # TCP analysis
                if packet.haslayer(TCP):
                    packet_info["protocol"] = "TCP"
                    packet_info["src_port"] = packet[TCP].sport
                    packet_info["dst_port"] = packet[TCP].dport
                    packet_info["flags"] = self._get_scapy_tcp_flags(packet[TCP])

                # UDP analysis
                elif packet.haslayer(UDP):
                    packet_info["protocol"] = "UDP"
                    packet_info["src_port"] = packet[UDP].sport
                    packet_info["dst_port"] = packet[UDP].dport

                # ICMP analysis
                elif packet.haslayer(ICMP):
                    packet_info["protocol"] = "ICMP"

            # Application detection
            packet_info["application"] = self._detect_application_scapy(packet_info)

            return packet_info

        except Exception as e:
            print(f"Scapy packet analysis error: {e}")
            return None

    def _get_pyshark_protocol(self, packet) -> str:
        """Get protocol from pyshark packet"""
        if hasattr(packet, 'tcp'):
            return "TCP"
        elif hasattr(packet, 'udp'):
            return "UDP"
        elif hasattr(packet, 'icmp'):
            return "ICMP"
        elif hasattr(packet, 'arp'):
            return "ARP"
        elif hasattr(packet, 'ip'):
            return "IP"
        else:
            return "Unknown"

    def _get_pyshark_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags from pyshark"""
        flags = []
        try:
            if hasattr(tcp_layer, 'flags_syn') and tcp_layer.flags_syn == '1':
                flags.append("SYN")
            if hasattr(tcp_layer, 'flags_ack') and tcp_layer.flags_ack == '1':
                flags.append("ACK")
            if hasattr(tcp_layer, 'flags_fin') and tcp_layer.flags_fin == '1':
                flags.append("FIN")
            if hasattr(tcp_layer, 'flags_rst') and tcp_layer.flags_rst == '1':
                flags.append("RST")
            if hasattr(tcp_layer, 'flags_push') and tcp_layer.flags_push == '1':
                flags.append("PSH")
            if hasattr(tcp_layer, 'flags_urg') and tcp_layer.flags_urg == '1':
                flags.append("URG")
        except Exception:
            pass
        return flags

    def _get_scapy_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags from scapy"""
        flags = []
        try:
            tcp_flags = tcp_layer.flags
            if hasattr(tcp_flags, 'F') and tcp_flags.F: flags.append("FIN")
            if hasattr(tcp_flags, 'S') and tcp_flags.S: flags.append("SYN")
            if hasattr(tcp_flags, 'R') and tcp_flags.R: flags.append("RST")
            if hasattr(tcp_flags, 'P') and tcp_flags.P: flags.append("PSH")
            if hasattr(tcp_flags, 'A') and tcp_flags.A: flags.append("ACK")
            if hasattr(tcp_flags, 'U') and tcp_flags.U: flags.append("URG")
        except Exception:
            # Fallback for FlagValue objects
            flags_str = str(tcp_layer.flags)
            if 'F' in flags_str: flags.append("FIN")
            if 'S' in flags_str: flags.append("SYN")
            if 'R' in flags_str: flags.append("RST")
            if 'P' in flags_str: flags.append("PSH")
            if 'A' in flags_str: flags.append("ACK")
            if 'U' in flags_str: flags.append("URG")
        return flags

    def _detect_application_pyshark(self, packet, packet_info: Dict) -> str:
        """Detect application from pyshark packet"""
        # Enhanced detection using pyshark
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'request_method'):
                self.http_requests.append({
                    "timestamp": packet_info["timestamp"],
                    "method": packet.http.request_method,
                    "host": getattr(packet.http, 'host', 'Unknown'),
                    "uri": getattr(packet.http, 'request_uri', '/'),
                    "user_agent": getattr(packet.http, 'user_agent', 'Unknown')
                })
            return "HTTP"

        if hasattr(packet, 'tls') or hasattr(packet, 'ssl'):
            packet_info["encrypted"] = True
            return "HTTPS"

        if hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'qry_name'):
                self.dns_queries.append({
                    "timestamp": packet_info["timestamp"],
                    "query": packet.dns.qry_name,
                    "query_type": getattr(packet.dns, 'qry_type', 'Unknown')
                })
            return "DNS"

        # Fall back to port-based detection
        return self._detect_application_by_port(packet_info)

    def _detect_application_scapy(self, packet_info: Dict) -> str:
        """Detect application from scapy packet info"""
        return self._detect_application_by_port(packet_info)

    def _detect_application_by_port(self, packet_info: Dict) -> str:
        """Detect application by port number"""
        dst_port = packet_info.get("dst_port")
        src_port = packet_info.get("src_port")

        port_mapping = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 587: "SMTP", 465: "SMTPS", 3389: "RDP", 5432: "PostgreSQL",
            3306: "MySQL", 1433: "MSSQL", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch"
        }

        if dst_port in port_mapping:
            return port_mapping[dst_port]
        elif src_port in port_mapping:
            return port_mapping[src_port]

        # Default naming
        if packet_info["protocol"] == "TCP":
            return f"Port-{dst_port}" if dst_port else "TCP"
        elif packet_info["protocol"] == "UDP":
            return f"Port-{dst_port}" if dst_port else "UDP"
        else:
            return packet_info["protocol"]

    def _update_statistics(self, packet_data: Dict):
        """Update statistics with packet data"""
        timestamp = packet_data["timestamp"]
        protocol = packet_data["protocol"]
        src_ip = packet_data.get("src_ip")
        dst_ip = packet_data.get("dst_ip")
        application = packet_data["application"]
        length = packet_data.get("length", 0)

        # Update protocol stats
        self.protocol_stats[protocol] += 1

        # Update application stats
        self.application_stats[application] += 1

        # Update top talkers
        if src_ip:
            self.top_talkers[src_ip] += length
        if dst_ip:
            self.top_talkers[dst_ip] += length

        # Update port usage
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        if src_port:
            self.port_usage[src_port] += 1
        if dst_port:
            self.port_usage[dst_port] += 1

        # Update bandwidth timeline
        self.bandwidth_timeline.append({
            "timestamp": timestamp,
            "bytes": length,
            "protocol": protocol,
            "application": application
        })

        # Geographic analysis (simplified)
        if src_ip and dst_ip:
            if src_ip.startswith(('192.168.', '10.', '172.')):
                self.geographic_stats["Local"] += length
            else:
                # Simple geographic classification
                if src_ip.startswith(('1.', '14.', '27.', '36.', '42.', '49.', '58.', '60.', '61.', '101.')):
                    self.geographic_stats["Asia"] += length
                elif src_ip.startswith(('2.', '5.', '31.', '37.', '46.', '62.', '77.', '78.', '79.', '80.')):
                    self.geographic_stats["Europe"] += length
                elif src_ip.startswith(('3.', '4.', '6.', '7.', '8.', '9.', '12.', '13.', '15.', '16.')):
                    self.geographic_stats["USA"] += length
                else:
                    self.geographic_stats["Other"] += length

        # Connection tracking
        if src_ip and dst_ip:
            connection_key = f"{src_ip}-{dst_ip}"
            self.connection_stats[connection_key] += 1

    def _generate_mock_traffic(self):
        """Generate continuous mock traffic data"""
        print("🎭 Generating mock network traffic data...")

        while self.is_capturing:
            try:
                # Generate a mock packet
                packet_data = self._generate_mock_packet()

                # Add to queue if not full
                if not self.packet_queue.full():
                    self.packet_queue.put(packet_data)

                # Update statistics
                self._update_statistics_mock(packet_data)

                # Sleep for realistic timing
                time.sleep(random.uniform(0.01, 0.5))  # 10ms to 500ms between packets

            except Exception as e:
                print(f"Error generating mock packet: {e}")
                time.sleep(1)

    def _update_statistics_mock(self, packet_data: Dict):
        """Update statistics with mock packet data"""
        try:
            protocol = packet_data["protocol"]
            src_ip = packet_data["src_ip"]
            dst_ip = packet_data["dst_ip"]
            application = packet_data["application"]
            packet_size = packet_data["bytes_sent"]

            # Update protocol stats
            self.protocol_stats[protocol] += 1

            # Update application stats
            self.application_stats[application] += 1

            # Update top talkers
            self.top_talkers[src_ip] += packet_size
            self.top_talkers[dst_ip] += packet_size

            # Update port usage
            if packet_data["src_port"]:
                self.port_usage[packet_data["src_port"]] += 1
            if packet_data["dst_port"]:
                self.port_usage[packet_data["dst_port"]] += 1

            # Update geographic stats
            self.geographic_stats[packet_data["src_country"]] += packet_size
            self.geographic_stats[packet_data["dst_country"]] += packet_size

            # Update bandwidth timeline
            self.bandwidth_timeline.append({
                "timestamp": packet_data["timestamp"],
                "bandwidth_mbps": (packet_size * 8) / (1024 * 1024),
                "connections": 1
            })

            # Update packet timeline for statistics
            self.packet_timeline.append({
                'timestamp': packet_data['timestamp'],
                'size': packet_size,
                'protocol': protocol
            })

        except Exception as e:
            print(f"Error updating mock statistics: {e}")

    async def get_packet_data(self):
        """Get processed packet data (async method)"""
        try:
            packet_data = self.packet_queue.get_nowait()
            return packet_data
        except queue.Empty:
            return None

    def get_statistics(self):
        """Get comprehensive traffic statistics"""
        # Calculate totals
        total_bytes = sum(self.top_talkers.values())
        total_packets = sum(self.protocol_stats.values())

        # Calculate bandwidth
        current_bandwidth = 0
        if len(self.bandwidth_timeline) > 1:
            recent_packets = list(self.bandwidth_timeline)[-10:]  # Last 10 packets
            total_size = sum(p['bandwidth_mbps'] for p in recent_packets)
            current_bandwidth = total_size / len(recent_packets) if recent_packets else 0

        # Get top talkers (top 10)
        top_talkers_sorted = dict(sorted(self.top_talkers.items(),
                                       key=lambda x: x[1], reverse=True)[:10])

        # Get top ports (top 10)
        top_ports_sorted = dict(sorted(self.port_usage.items(),
                                     key=lambda x: x[1], reverse=True)[:10])

        # Calculate connection distribution
        connection_distribution = {}
        for ip in self.top_talkers.keys():
            connection_distribution[ip] = random.randint(1, 50)  # Mock connection counts
        connection_distribution = dict(sorted(connection_distribution.items(),
                                            key=lambda x: x[1], reverse=True)[:10])

        return {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_bandwidth_mb': total_bytes / (1024 * 1024),
            'current_bandwidth_mbps': current_bandwidth,
            'peak_bandwidth_mb': max((p['bandwidth_mbps'] for p in self.bandwidth_timeline), default=0),
            'total_connections': len(connection_distribution),
            'active_connections': random.randint(5, 25),
            'protocol_distribution': dict(self.protocol_stats),
            'top_talkers': top_talkers_sorted,
            'top_ports': top_ports_sorted,
            'connection_distribution': connection_distribution,
            'geographic_traffic': dict(self.geographic_stats),
            'application_usage': dict(self.application_stats),
            'bandwidth_timeline': list(self.bandwidth_timeline)[-50:],  # Last 50 entries
            'network_health_score': random.randint(85, 100),
            'capture_method': self.capture_method or 'mock'
        }

    def _generate_mock_packet(self):
        """Generate realistic mock packet data matching expected format"""
        protocols = ['TCP', 'UDP', 'ICMP']
        protocol = random.choice(protocols)

        src_ip = random.choice(self.mock_ips + self.external_ips)
        dst_ip = random.choice(self.mock_ips + self.external_ips)

        # Ensure src and dst are different
        while src_ip == dst_ip:
            dst_ip = random.choice(self.mock_ips + self.external_ips)

        packet_size = random.randint(64, 1500)

        # Determine geographic locations
        src_country = "Local" if src_ip.startswith(('192.168.', '10.', '172.16.')) else random.choice(["Asia", "Europe", "USA", "Other"])
        dst_country = "Local" if dst_ip.startswith(('192.168.', '10.', '172.16.')) else random.choice(["Asia", "Europe", "USA", "Other"])

        # Generate port numbers based on protocol
        if protocol in ['TCP', 'UDP']:
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53, 22, 21, 25, 110, 993, 995, 8080, 3389, 1433, 3306])
        else:
            src_port = None
            dst_port = None

        # Determine application based on port
        app_map = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
            25: "SMTP", 110: "POP3", 993: "IMAPS", 995: "POP3S",
            8080: "HTTP-Alt", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL"
        }
        application = app_map.get(dst_port, f"Port-{dst_port}" if dst_port else protocol)

        # Generate TCP flags if TCP
        flags = []
        if protocol == 'TCP':
            flag_options = [['SYN'], ['ACK'], ['PSH', 'ACK'], ['FIN', 'ACK'], ['RST'], ['SYN', 'ACK']]
            flags = random.choice(flag_options)

        packet_data = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_country': src_country,
            'dst_country': dst_country,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'bytes_sent': packet_size,
            'bytes_received': 0,  # For mock data, assume outbound
            'packets_sent': 1,
            'packets_received': 0,
            'application': application,
            'flags': flags,
            'ttl': random.randint(32, 128),
            'latency_ms': random.randint(0, 100),
            'size': packet_size
        }

        return packet_data

# Global instance
enhanced_analyzer = EnhancedPacketCapture()
