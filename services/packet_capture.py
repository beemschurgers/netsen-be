# services/packet_capture.py
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json
from datetime import datetime
from collections import defaultdict, deque
import threading
import queue
import time

class ScapyPacketAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.capture_thread = None
        self.packet_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.threat_patterns = defaultdict(int)
        self.bandwidth_stats = deque(maxlen=100)
        self.packet_timeline = deque(maxlen=200)
        
    def start_capture(self, interface=None, filter_str=""):
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_packets, 
            args=(interface, filter_str),
            daemon=True
        )
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def _capture_packets(self, interface, filter_str):
        """Capture packets using Scapy"""
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing,
                store=False
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
            self.is_capturing = False
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        try:
            packet_data = self._analyze_packet(packet)
            if packet_data:
                self.packet_queue.put(packet_data)
                self._update_statistics(packet_data)
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def _analyze_packet(self, packet):
        """Analyze packet and extract relevant information"""
        packet_info = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "size": len(packet),
            "src": None,
            "dst": None,
            "protocol": "Unknown",
            "src_port": None,
            "dst_port": None,
            "flags": [],
            "is_threat": False,
            "threat_type": "BENIGN",
            "confidence": 95
        }
        
        # Ethernet layer
        if packet.haslayer(Ether):
            packet_info["eth_src"] = packet[Ether].src
            packet_info["eth_dst"] = packet[Ether].dst
        
        # IP layer analysis
        if packet.haslayer(IP):
            packet_info["src"] = packet[IP].src
            packet_info["dst"] = packet[IP].dst
            packet_info["ttl"] = packet[IP].ttl
            packet_info["ip_flags"] = packet[IP].flags
            
            # TCP analysis
            if packet.haslayer(TCP):
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["flags"] = self._get_tcp_flags(packet[TCP])
                packet_info["seq"] = packet[TCP].seq
                packet_info["ack"] = packet[TCP].ack
                
                # Check for suspicious TCP patterns
                packet_info["is_threat"], packet_info["threat_type"] = self._detect_tcp_threats(packet)
                
            # UDP analysis
            elif packet.haslayer(UDP):
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                
                # Check for suspicious UDP patterns
                packet_info["is_threat"], packet_info["threat_type"] = self._detect_udp_threats(packet)
                
            # ICMP analysis
            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["icmp_code"] = packet[ICMP].code
                
                # Check for ICMP-based threats
                packet_info["is_threat"], packet_info["threat_type"] = self._detect_icmp_threats(packet)
        
        # Application layer detection
        packet_info["application"] = self._detect_application(packet_info)
        
        return packet_info
    
    def _get_tcp_flags(self, tcp_layer):
        """Extract TCP flags"""
        flags = []
        if tcp_layer.flags.F: flags.append("FIN")
        if tcp_layer.flags.S: flags.append("SYN")
        if tcp_layer.flags.R: flags.append("RST")
        if tcp_layer.flags.P: flags.append("PSH")
        if tcp_layer.flags.A: flags.append("ACK")
        if tcp_layer.flags.U: flags.append("URG")
        return flags
    
    def _detect_tcp_threats(self, packet):
        """Detect TCP-based threats"""
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Port scanning detection (SYN scan)
        if tcp.flags.S and not tcp.flags.A:
            if tcp.dport in [22, 23, 80, 443, 3389]:  # Common target ports
                return True, "Port Scan"
        
        # SYN flood detection (simplified)
        if tcp.flags.S and not tcp.flags.A:
            if len(packet) < 60:  # Small SYN packets
                return True, "DDoS"
        
        # Suspicious high ports
        if tcp.dport > 60000:
            return True, "Suspicious Traffic"
        
        return False, "BENIGN"
    
    def _detect_udp_threats(self, packet):
        """Detect UDP-based threats"""
        udp = packet[UDP]
        
        # DNS amplification attack
        if udp.sport == 53 and len(packet) > 512:
            return True, "DDoS"
        
        # Suspicious UDP traffic
        if udp.dport in [1900, 5353]:  # UPnP, mDNS
            return True, "Network Scan"
        
        return False, "BENIGN"
    
    def _detect_icmp_threats(self, packet):
        """Detect ICMP-based threats"""
        icmp = packet[ICMP]
        
        # Ping flood detection
        if icmp.type == 8:  # Echo request
            return True, "ICMP Flood"
        
        # Suspicious ICMP types
        if icmp.type in [13, 15, 17]:  # Timestamp, info request, address mask
            return True, "Network Reconnaissance"
        
        return False, "BENIGN"
    
    def _detect_application(self, packet_info):
        """Detect application based on port and protocol"""
        if not packet_info["dst_port"]:
            return "Unknown"
        
        port_map = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis"
        }
        
        return port_map.get(packet_info["dst_port"], f"Port-{packet_info['dst_port']}")
    
    def _update_statistics(self, packet_data):
        """Update internal statistics"""
        self.packet_stats["total"] += 1
        self.protocol_stats[packet_data["protocol"]] += 1
        
        if packet_data["src"]:
            self.ip_stats[packet_data["src"]] += 1
        
        if packet_data["dst_port"]:
            self.port_stats[packet_data["dst_port"]] += 1
        
        if packet_data["is_threat"]:
            self.threat_patterns[packet_data["threat_type"]] += 1
        
        # Bandwidth tracking
        self.bandwidth_stats.append({
            "timestamp": packet_data["timestamp"],
            "bytes": packet_data["size"]
        })
        
        # Timeline tracking
        self.packet_timeline.append({
            "timestamp": packet_data["timestamp"],
            "protocol": packet_data["protocol"],
            "size": packet_data["size"],
            "is_threat": packet_data["is_threat"]
        })
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        total_packets = self.packet_stats["total"]
        threat_count = sum(self.threat_patterns.values())
        
        # Calculate bandwidth
        recent_bandwidth = list(self.bandwidth_stats)[-60:]  # Last 60 packets
        total_bytes = sum(p["bytes"] for p in recent_bandwidth)
        bandwidth_mbps = (total_bytes * 8) / (1024 * 1024) if recent_bandwidth else 0
        
        return {
            "session_stats": {
                "total_packets": total_packets,
                "threats_detected": threat_count,
                "benign_packets": total_packets - threat_count,
                "packet_rate": len(recent_bandwidth) / 60 if recent_bandwidth else 0,
                "bandwidth_mbps": bandwidth_mbps
            },
            "protocol_distribution": dict(self.protocol_stats),
            "top_sources": dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_ports": dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            "threat_breakdown": dict(self.threat_patterns),
            "packet_timeline": list(self.packet_timeline)[-50:],  # Last 50 packets
            "bandwidth_timeline": list(self.bandwidth_stats)[-50:]
        }
    
    def get_next_packet(self, timeout=1):
        """Get next packet from queue"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

# Global packet analyzer instance
packet_analyzer = ScapyPacketAnalyzer()

async def start_packet_capture(websocket: WebSocket):
    """WebSocket endpoint for real-time packet capture"""
    await websocket.accept()
    
    # Start packet capture
    packet_analyzer.start_capture()
    
    try:
        await websocket.send_json({
            "status": "Packet capture started",
            "message": "Real-time packet analysis active"
        })
        
        while True:
            # Get packet data
            packet_data = packet_analyzer.get_next_packet(timeout=0.1)
            
            if packet_data:
                # Send packet data with statistics
                response = {
                    **packet_data,
                    "session_stats": packet_analyzer.get_statistics()["session_stats"]
                }
                await websocket.send_json(response)
            else:
                # Send periodic statistics update
                stats = packet_analyzer.get_statistics()
                await websocket.send_json({
                    "type": "stats_update",
                    "statistics": stats
                })
            
            await asyncio.sleep(0.1)  # Small delay to prevent overwhelming
            
    except WebSocketDisconnect:
        print("Packet capture WebSocket disconnected")
    except Exception as e:
        print(f"Packet capture error: {e}")
    finally:
        packet_analyzer.stop_capture()
