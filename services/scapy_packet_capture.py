from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
from collections import defaultdict, deque
import threading
import time
import json
import random
from datetime import datetime
from .ml_model_service import ml_service

class ScapyPacketAnalyzer:
    def __init__(self):
        self.running = False
        self.packets = deque(maxlen=1000)
        self.statistics = {
            'total_bandwidth_mb': 0,
            'current_bandwidth_mbps': 0,
            'peak_bandwidth_mb': 0,
            'total_connections': 0,
            'active_connections': 0,
            'top_talkers': {},
            'protocol_distribution': defaultdict(int),
            'top_ports': defaultdict(int),
            'connection_distribution': defaultdict(int),
            'geographic_traffic': defaultdict(int),
            'application_usage': defaultdict(int),
            'bandwidth_timeline': deque(maxlen=50),
            'network_health_score': 100
        }
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_update = time.time()
        self.interface = None
        self.capture_method = "scapy"

    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            return get_if_list()
        except:
            return ["any", "lo0", "en0", "en1"]

    def packet_callback(self, packet):
        """Process captured packet"""
        try:
            self.packet_count += 1
            packet_size = len(packet)
            self.total_bytes += packet_size

            # Add packet to ML service for threat analysis
            ml_service.add_packet(packet)

            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.packets.append(packet_info)
                self.update_statistics(packet_info, packet_size)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'size': len(packet),
                'protocol': 'Unknown'
            }

            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'src_country': self.get_country_from_ip(packet[IP].src),
                    'dst_country': self.get_country_from_ip(packet[IP].dst),
                    'ttl': packet[IP].ttl
                })

                if TCP in packet:
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': self.get_tcp_flags(packet[TCP].flags),
                        'application': self.get_application_from_port(packet[TCP].dport)
                    })
                elif UDP in packet:
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'application': self.get_application_from_port(packet[UDP].dport)
                    })
                elif ICMP in packet:
                    packet_info.update({
                        'protocol': 'ICMP',
                        'type': packet[ICMP].type,
                        'code': packet[ICMP].code
                    })
            elif ARP in packet:
                packet_info.update({
                    'protocol': 'ARP',
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'operation': packet[ARP].op
                })

            # Add mock data for demonstration
            packet_info.update({
                'bytes_sent': random.randint(50, 1500),
                'bytes_received': 0,
                'packets_sent': 1,
                'packets_received': 0,
                'latency_ms': random.randint(0, 100)
            })

            return packet_info

        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None

    def get_tcp_flags(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        return flag_names

    def get_application_from_port(self, port):
        """Map port number to application"""
        port_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 587: "SMTP", 465: "SMTPS", 8080: "HTTP-Alt",
            3389: "RDP", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return port_map.get(port, f"Port-{port}")

    def get_country_from_ip(self, ip):
        """Simple IP to country mapping (mock implementation)"""
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local"
        elif ip.startswith("8.8.") or ip.startswith("1.1."):
            return "USA"
        else:
            # Mock geographic distribution
            countries = ["USA", "Europe", "Asia", "Other", "Local"]
            return random.choice(countries)

    def update_statistics(self, packet_info, packet_size):
        """Update network statistics"""
        current_time = time.time()

        # Update bandwidth
        self.statistics['total_bandwidth_mb'] = self.total_bytes / (1024 * 1024)

        # Calculate current bandwidth
        time_diff = current_time - self.last_update
        if time_diff > 1.0:  # Update every second
            bytes_per_sec = packet_size / time_diff
            self.statistics['current_bandwidth_mbps'] = bytes_per_sec / (1024 * 1024)
            self.last_update = current_time

        # Update peak bandwidth
        if self.statistics['current_bandwidth_mbps'] > self.statistics['peak_bandwidth_mb']:
            self.statistics['peak_bandwidth_mb'] = self.statistics['current_bandwidth_mbps']

        # Update protocol distribution
        protocol = packet_info.get('protocol', 'Unknown')
        self.statistics['protocol_distribution'][protocol] += packet_size

        # Update port statistics
        if 'src_port' in packet_info:
            self.statistics['top_ports'][packet_info['src_port']] += 1
        if 'dst_port' in packet_info:
            self.statistics['top_ports'][packet_info['dst_port']] += 1

        # Update top talkers
        if 'src_ip' in packet_info:
            self.statistics['top_talkers'][packet_info['src_ip']] = \
                self.statistics['top_talkers'].get(packet_info['src_ip'], 0) + packet_size
            self.statistics['connection_distribution'][packet_info['src_ip']] = \
                self.statistics['connection_distribution'].get(packet_info['src_ip'], 0) + 1

        if 'dst_ip' in packet_info:
            self.statistics['top_talkers'][packet_info['dst_ip']] = \
                self.statistics['top_talkers'].get(packet_info['dst_ip'], 0) + packet_size

        # Update geographic traffic
        if 'src_country' in packet_info:
            self.statistics['geographic_traffic'][packet_info['src_country']] += packet_size
        if 'dst_country' in packet_info:
            self.statistics['geographic_traffic'][packet_info['dst_country']] += packet_size

        # Update application usage
        if 'application' in packet_info:
            self.statistics['application_usage'][packet_info['application']] += packet_size

        # Update bandwidth timeline
        self.statistics['bandwidth_timeline'].append({
            'timestamp': packet_info['timestamp'],
            'bandwidth_mbps': self.statistics['current_bandwidth_mbps'],
            'connections': len(self.statistics['connection_distribution'])
        })

        # Update connection counts
        self.statistics['total_connections'] = self.packet_count
        self.statistics['active_connections'] = len(self.statistics['connection_distribution'])

        # Calculate network health score (simplified)
        error_rate = 0  # Could be calculated based on retransmissions, etc.
        latency_score = 100  # Could be calculated based on RTT measurements
        self.statistics['network_health_score'] = max(0, min(100, latency_score - error_rate))

    async def start_capture(self, interface=None):
        """Start packet capture"""
        if self.running:
            return

        self.running = True
        self.interface = interface

        try:
            print(f"Starting Scapy packet capture on interface: {interface or 'any'}")

            # Start capture in a separate thread to avoid blocking
            def capture_thread():
                try:
                    sniff(
                        iface=interface,
                        prn=self.packet_callback,
                        stop_filter=lambda x: not self.running,
                        store=0  # Don't store packets in memory
                    )
                except Exception as e:
                    print(f"Scapy capture error: {e}")

            self.capture_thread = threading.Thread(target=capture_thread)
            self.capture_thread.daemon = True
            self.capture_thread.start()

        except Exception as e:
            print(f"Error starting Scapy capture: {e}")
            self.running = False

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        print("Stopping Scapy packet capture")

    def get_packet(self):
        """Get the latest packet data"""
        if self.packets:
            return self.packets[-1]
        return None

    def get_comprehensive_statistics(self):
        """Get comprehensive network statistics"""
        # Convert defaultdicts to regular dicts and sort top items
        stats = {
            'total_bandwidth_mb': self.statistics['total_bandwidth_mb'],
            'current_bandwidth_mbps': self.statistics['current_bandwidth_mbps'],
            'peak_bandwidth_mb': self.statistics['peak_bandwidth_mb'],
            'total_connections': self.statistics['total_connections'],
            'active_connections': self.statistics['active_connections'],
            'top_talkers': dict(sorted(self.statistics['top_talkers'].items(),
                                     key=lambda x: x[1], reverse=True)[:10]),
            'protocol_distribution': dict(self.statistics['protocol_distribution']),
            'top_ports': dict(sorted(self.statistics['top_ports'].items(),
                                   key=lambda x: x[1], reverse=True)[:10]),
            'connection_distribution': dict(sorted(self.statistics['connection_distribution'].items(),
                                                 key=lambda x: x[1], reverse=True)[:10]),
            'geographic_traffic': dict(self.statistics['geographic_traffic']),
            'application_usage': dict(sorted(self.statistics['application_usage'].items(),
                                           key=lambda x: x[1], reverse=True)[:10]),
            'bandwidth_timeline': list(self.statistics['bandwidth_timeline']),
            'network_health_score': self.statistics['network_health_score']
        }

        return stats

# Global analyzer instance
scapy_analyzer = ScapyPacketAnalyzer()
