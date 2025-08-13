# services/pyshark_packet_analyzer.py
import pyshark
import asyncio
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import queue
import time
from typing import Dict, List, Optional
import subprocess
import platform

class PysharkPacketAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=1000)
        self.is_capturing = False
        self.capture = None
        self.capture_thread = None
        
        # Enhanced statistics tracking
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
        
        # Network security tracking
        self.suspicious_activities = deque(maxlen=50)
        self.failed_connections = deque(maxlen=50)
        self.port_scans = defaultdict(list)
        self.anomalies = deque(maxlen=30)
        
        # Performance metrics
        self.latency_stats = deque(maxlen=100)
        self.retransmission_stats = deque(maxlen=50)
        self.fragmentation_stats = deque(maxlen=50)
        
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            # Get interfaces using pyshark
            interfaces = []
            if platform.system() == "Windows":
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Connected' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            interfaces.append(parts[-1])
            else:
                # Unix-like systems
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith(' '):
                        interface = line.split(':')[0]
                        if interface and not interface.startswith('lo'):
                            interfaces.append(interface)
            
            return interfaces if interfaces else ['en0', 'eth0', 'wlan0']
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ['en0', 'eth0', 'wlan0']  # Default interfaces
    
    async def start_capture(self, interface: Optional[str] = None, 
                          capture_filter: str = "", packet_count: int = 0):
        """Start packet capture using pyshark"""
        if self.is_capturing:
            return
        
        try:
            self.is_capturing = True
            
            # Auto-detect interface if not specified
            if not interface:
                interfaces = self.get_available_interfaces()
                interface = interfaces[0] if interfaces else 'en0'
            
            print(f"Starting packet capture on interface: {interface}")
            
            # Start capture in background thread
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface, capture_filter, packet_count),
                daemon=True
            )
            self.capture_thread.start()
            
        except Exception as e:
            print(f"Failed to start packet capture: {e}")
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture:
            try:
                self.capture.close()
            except:
                pass
        if self.capture_thread:
            self.capture_thread.join(timeout=3)
    
    def _capture_packets(self, interface: str, capture_filter: str, packet_count: int):
        """Capture packets in background thread"""
        try:
            # Create live capture
            self.capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=capture_filter if capture_filter else None
            )
            
            print(f"Capturing packets on {interface}...")
            
            for packet in self.capture.sniff_continuously():
                if not self.is_capturing:
                    break
                
                try:
                    packet_data = self._analyze_packet_detailed(packet)
                    if packet_data:
                        if not self.packet_queue.full():
                            self.packet_queue.put(packet_data)
                        self._update_statistics(packet_data)
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    continue
                
                if packet_count > 0:
                    packet_count -= 1
                    if packet_count <= 0:
                        break
                        
        except Exception as e:
            print(f"Packet capture error: {e}")
        finally:
            self.is_capturing = False
    
    def _analyze_packet_detailed(self, packet) -> Optional[Dict]:
        """Detailed packet analysis using pyshark"""
        try:
            packet_info = {
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "length": int(packet.length) if hasattr(packet, 'length') else 0,
                "protocol": self._get_highest_protocol(packet),
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "src_mac": None,
                "dst_mac": None,
                "application": "Unknown",
                "flags": [],
                "packet_type": "DATA",
                "direction": "UNKNOWN",
                "bytes_sent": 0,
                "bytes_received": 0,
                "ttl": None,
                "window_size": None,
                "payload_size": 0,
                "encrypted": False,
                "compression": False
            }
            
            # Ethernet layer analysis
            if hasattr(packet, 'eth'):
                packet_info["src_mac"] = packet.eth.src
                packet_info["dst_mac"] = packet.eth.dst
                packet_info["eth_type"] = packet.eth.type
            
            # IP layer analysis
            if hasattr(packet, 'ip'):
                packet_info["src_ip"] = packet.ip.src
                packet_info["dst_ip"] = packet.ip.dst
                packet_info["ttl"] = int(packet.ip.ttl)
                packet_info["ip_version"] = packet.ip.version
                packet_info["ip_header_length"] = int(packet.ip.hdr_len)
                packet_info["dscp"] = getattr(packet.ip, 'dsfield_dscp', None)
                packet_info["bytes_sent"] = int(packet.ip.len)
                
                # Fragment analysis
                if hasattr(packet.ip, 'flags_mf') and packet.ip.flags_mf == '1':
                    packet_info["fragmented"] = True
                    packet_info["fragment_offset"] = getattr(packet.ip, 'frag_offset', 0)
            
            # TCP analysis
            if hasattr(packet, 'tcp'):
                packet_info["src_port"] = int(packet.tcp.srcport)
                packet_info["dst_port"] = int(packet.tcp.dstport)
                packet_info["sequence"] = int(packet.tcp.seq)
                packet_info["acknowledgment"] = int(packet.tcp.ack)
                packet_info["window_size"] = int(packet.tcp.window_size_value)
                packet_info["tcp_header_length"] = int(packet.tcp.hdr_len)
                
                # TCP flags
                flags = []
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                    flags.append("SYN")
                if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1':
                    flags.append("ACK")
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                    flags.append("FIN")
                if hasattr(packet.tcp, 'flags_rst') and packet.tcp.flags_rst == '1':
                    flags.append("RST")
                if hasattr(packet.tcp, 'flags_push') and packet.tcp.flags_push == '1':
                    flags.append("PSH")
                if hasattr(packet.tcp, 'flags_urg') and packet.tcp.flags_urg == '1':
                    flags.append("URG")
                packet_info["flags"] = flags
                
                # Calculate payload size
                if hasattr(packet, 'data'):
                    packet_info["payload_size"] = len(packet.data.data.replace(':', '')) // 2
            
            # UDP analysis
            elif hasattr(packet, 'udp'):
                packet_info["src_port"] = int(packet.udp.srcport)
                packet_info["dst_port"] = int(packet.udp.dstport)
                packet_info["udp_length"] = int(packet.udp.length)
                
                # Calculate payload size
                packet_info["payload_size"] = int(packet.udp.length) - 8  # UDP header is 8 bytes
            
            # ICMP analysis
            elif hasattr(packet, 'icmp'):
                packet_info["icmp_type"] = int(packet.icmp.type)
                packet_info["icmp_code"] = int(packet.icmp.code)
                packet_info["protocol"] = "ICMP"
            
            # Application layer detection
            packet_info["application"] = self._detect_application_detailed(packet, packet_info)
            
            # Security analysis
            packet_info.update(self._analyze_security_aspects(packet, packet_info))
            
            # Performance analysis
            packet_info.update(self._analyze_performance_aspects(packet, packet_info))
            
            return packet_info
            
        except Exception as e:
            print(f"Packet analysis error: {e}")
            return None
    
    def _get_highest_protocol(self, packet) -> str:
        """Determine the highest layer protocol"""
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
        elif hasattr(packet, 'eth'):
            return "Ethernet"
        else:
            return "Unknown"
    
    def _detect_application_detailed(self, packet, packet_info: Dict) -> str:
        """Enhanced application detection"""
        # HTTP/HTTPS detection
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
        
        # HTTPS/TLS detection
        if hasattr(packet, 'tls') or hasattr(packet, 'ssl'):
            if hasattr(packet, 'tls'):
                self.tls_sessions.append({
                    "timestamp": packet_info["timestamp"],
                    "version": getattr(packet.tls, 'version', 'Unknown'),
                    "cipher_suite": getattr(packet.tls, 'handshake_ciphersuite', 'Unknown'),
                    "server_name": getattr(packet.tls, 'handshake_extensions_server_name', 'Unknown')
                })
            packet_info["encrypted"] = True
            return "HTTPS"
        
        # DNS detection
        if hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'qry_name'):
                self.dns_queries.append({
                    "timestamp": packet_info["timestamp"],
                    "query": packet.dns.qry_name,
                    "query_type": getattr(packet.dns, 'qry_type', 'Unknown'),
                    "response_code": getattr(packet.dns, 'rcode', 'Unknown')
                })
            return "DNS"
        
        # Port-based detection
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
        
        # Default based on protocol
        if packet_info["protocol"] == "TCP":
            return f"Port-{dst_port}" if dst_port else "TCP"
        elif packet_info["protocol"] == "UDP":
            return f"Port-{dst_port}" if dst_port else "UDP"
        else:
            return packet_info["protocol"]
    
    def _analyze_security_aspects(self, packet, packet_info: Dict) -> Dict:
        """Analyze security-related aspects of the packet"""
        security_info = {
            "is_suspicious": False,
            "threat_indicators": [],
            "risk_score": 0
        }
        
        # Port scan detection
        dst_port = packet_info.get("dst_port")
        src_ip = packet_info.get("src_ip")
        
        if dst_port and src_ip:
            if src_ip not in self.port_scans:
                self.port_scans[src_ip] = []
            
            self.port_scans[src_ip].append({
                "port": dst_port,
                "timestamp": datetime.now()
            })
            
            # Check for port scanning (multiple ports from same IP)
            recent_ports = [p for p in self.port_scans[src_ip] 
                          if datetime.now() - p["timestamp"] < timedelta(minutes=5)]
            
            if len(set(p["port"] for p in recent_ports)) > 10:
                security_info["is_suspicious"] = True
                security_info["threat_indicators"].append("Port Scan")
                security_info["risk_score"] += 30
        
        # Suspicious flags combination
        flags = packet_info.get("flags", [])
        if "SYN" in flags and "FIN" in flags:
            security_info["is_suspicious"] = True
            security_info["threat_indicators"].append("Invalid Flag Combination")
            security_info["risk_score"] += 20
        
        # Large packet size anomaly
        if packet_info.get("length", 0) > 1500:
            security_info["threat_indicators"].append("Large Packet")
            security_info["risk_score"] += 10
        
        return security_info
    
    def _analyze_performance_aspects(self, packet, packet_info: Dict) -> Dict:
        """Analyze performance-related aspects"""
        perf_info = {
            "retransmission": False,
            "out_of_order": False,
            "duplicate": False
        }
        
        # TCP-specific performance analysis
        if packet_info["protocol"] == "TCP":
            # Simple retransmission detection (basic implementation)
            seq_num = packet_info.get("sequence")
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            if seq_num and src_ip and dst_ip:
                flow_key = f"{src_ip}-{dst_ip}"
                if flow_key in self.flow_stats:
                    last_seq = self.flow_stats[flow_key].get("last_seq", 0)
                    if seq_num <= last_seq:
                        perf_info["retransmission"] = True
                
                self.flow_stats[flow_key] = {"last_seq": seq_num}
        
        return perf_info
    
    def _update_statistics(self, packet_data: Dict):
        """Update various statistics with packet data"""
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
                # Simple geographic classification based on IP ranges
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
    
    def get_packet(self) -> Optional[Dict]:
        """Get next packet from queue"""
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_comprehensive_statistics(self) -> Dict:
        """Get comprehensive traffic statistics"""
        # Calculate bandwidth metrics
        total_bytes = sum(self.top_talkers.values())
        total_bandwidth_mb = total_bytes / (1024 * 1024)
        
        # Calculate current bandwidth (last 10 seconds)
        current_time = datetime.now()
        recent_packets = [p for p in self.bandwidth_timeline 
                         if datetime.strptime(p["timestamp"], "%H:%M:%S.%f") > 
                         current_time - timedelta(seconds=10)]
        current_bytes = sum(p["bytes"] for p in recent_packets)
        current_bandwidth_mbps = (current_bytes * 8) / (10 * 1024 * 1024)  # Convert to Mbps
        
        # Get top talkers (sorted by traffic volume)
        top_talkers_sorted = dict(sorted(self.top_talkers.items(), 
                                       key=lambda x: x[1], reverse=True)[:10])
        
        # Get top ports (sorted by usage)
        top_ports_sorted = dict(sorted(self.port_usage.items(), 
                                     key=lambda x: x[1], reverse=True)[:10])
        
        # Get top applications
        top_applications = dict(sorted(self.application_stats.items(), 
                                     key=lambda x: x[1], reverse=True)[:10])
        
        # Connection distribution
        connection_distribution = dict(sorted(
            {ip: sum(1 for conn in self.connection_stats.keys() if ip in conn)
             for ip in set(ip for conn in self.connection_stats.keys() 
                          for ip in conn.split('-'))}.items(),
            key=lambda x: x[1], reverse=True)[:10])
        
        # Calculate network health score
        total_packets = sum(self.protocol_stats.values())
        error_rate = len(self.suspicious_activities) / max(total_packets, 1) * 100
        health_score = max(0, 100 - error_rate * 10)
        
        return {
            "total_bandwidth_mb": total_bandwidth_mb,
            "current_bandwidth_mbps": current_bandwidth_mbps,
            "peak_bandwidth_mb": max((p["bytes"] / (1024 * 1024) for p in self.bandwidth_timeline), default=0),
            "total_connections": len(self.connection_stats),
            "active_connections": sum(1 for v in self.connection_stats.values() if v > 0),
            "top_talkers": top_talkers_sorted,
            "protocol_distribution": dict(self.protocol_stats),
            "top_ports": top_ports_sorted,
            "connection_distribution": connection_distribution,
            "geographic_traffic": dict(self.geographic_stats),
            "application_usage": top_applications,
            "bandwidth_timeline": [
                {
                    "timestamp": p["timestamp"],
                    "bandwidth_mbps": (p["bytes"] * 8) / (1024 * 1024),  # Convert to Mbps
                    "connections": 1
                }
                for p in list(self.bandwidth_timeline)[-50:]  # Last 50 data points
            ],
            "network_health_score": health_score,
            "dns_queries": list(self.dns_queries)[-10:],  # Last 10 DNS queries
            "http_requests": list(self.http_requests)[-10:],  # Last 10 HTTP requests
            "tls_sessions": list(self.tls_sessions)[-10:],  # Last 10 TLS sessions
            "security_alerts": list(self.suspicious_activities)[-10:],  # Last 10 security alerts
            "total_packets": total_packets,
            "packet_loss_rate": 0,  # Would need more sophisticated calculation
            "average_latency": 0,    # Would need RTT calculation
            "retransmission_rate": len(self.retransmission_stats) / max(total_packets, 1) * 100
        }

# Global instance
pyshark_analyzer = PysharkPacketAnalyzer()
