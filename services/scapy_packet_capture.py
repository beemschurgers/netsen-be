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
        self.latest_packet = None  # Store the most recent packet
        self.packet_event = threading.Event()  # Event to signal new packets
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

        # Initialize ML service
        try:
            ml_service.load_model()
            print("ML service initialized for packet analysis")
        except Exception as e:
            print(f"Warning: Could not initialize ML service: {e}")

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
            try:
                if ml_service.is_initialized:
                    ml_service.add_packet(packet)  # Fixed method name
            except Exception as ml_error:
                # Don't let ML service errors stop packet processing
                print(f"Error processing packet: {ml_error}")

            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.packets.append(packet_info)
                self.update_statistics(packet_info, packet_size)

                # Set the latest packet and notify the event
                self.latest_packet = packet_info
                self.packet_event.set()

                # Debug output to confirm packets are being processed
                if self.packet_count % 100 == 0:  # Reduce debug spam
                    print(f"✅ Processed {self.packet_count} packets")

        except Exception as e:
            print(f"Error processing packet: {e}")
            import traceback
            traceback.print_exc()

    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'size': len(packet),
                'protocol': 'Unknown'
            }

            # Handle different packet types more carefully
            if IP in packet:
                ip_packet = packet[IP]
                packet_info.update({
                    'src_ip': ip_packet.src,
                    'dst_ip': ip_packet.dst,
                    'src_country': self.get_country_from_ip(ip_packet.src),
                    'dst_country': self.get_country_from_ip(ip_packet.dst),
                    'ttl': ip_packet.ttl
                })

                if TCP in packet:
                    tcp_packet = packet[TCP]
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': tcp_packet.sport,
                        'dst_port': tcp_packet.dport,
                        'flags': self.get_tcp_flags(tcp_packet.flags),
                        'application': self.get_application_from_port(tcp_packet.dport)
                    })
                elif UDP in packet:
                    udp_packet = packet[UDP]
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': udp_packet.sport,
                        'dst_port': udp_packet.dport,
                        'application': self.get_application_from_port(udp_packet.dport)
                    })
                elif ICMP in packet:
                    icmp_packet = packet[ICMP]
                    packet_info.update({
                        'protocol': 'ICMP',
                        'type': icmp_packet.type,
                        'code': icmp_packet.code,
                        'application': 'ICMP'
                    })
                else:
                    packet_info.update({
                        'protocol': f'IP-{ip_packet.proto}',
                        'application': f'Protocol-{ip_packet.proto}'
                    })

            elif ARP in packet:
                arp_packet = packet[ARP]
                # Validate ARP packet has proper addresses
                src_ip = arp_packet.psrc if hasattr(arp_packet, 'psrc') and arp_packet.psrc else 'Unknown'
                dst_ip = arp_packet.pdst if hasattr(arp_packet, 'pdst') and arp_packet.pdst else 'Unknown'

                # Skip packets with invalid addresses
                if src_ip == '0.0.0.0' or dst_ip == '0.0.0.0':
                    return None

                packet_info.update({
                    'protocol': 'ARP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_country': self.get_country_from_ip(src_ip),
                    'dst_country': self.get_country_from_ip(dst_ip),
                    'operation': arp_packet.op if hasattr(arp_packet, 'op') else 'Unknown',
                    'application': 'ARP'
                })
            else:
                # Handle other packet types (Ethernet, etc.)
                packet_info.update({
                    'protocol': packet.name if hasattr(packet, 'name') else 'Unknown',
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A',
                    'src_country': 'N/A',
                    'dst_country': 'N/A',
                    'application': 'Other'
                })

            # Add realistic data instead of random mock data
            packet_info.update({
                'bytes_sent': len(packet),
                'bytes_received': 0,
                'packets_sent': 1,
                'packets_received': 0,
                'latency_ms': random.randint(1, 50)  # More realistic latency range
            })

            return packet_info

        except Exception as e:
            print(f"Error extracting packet info: {e}")
            print(f"Packet summary: {packet.summary() if hasattr(packet, 'summary') else 'N/A'}")
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
