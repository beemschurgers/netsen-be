from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from datetime import datetime
from collections import defaultdict, deque
from .packet_capture import packet_analyzer

class NetworkAnalytics:
    def __init__(self):
        self.traffic_history = deque(maxlen=1000)
        self.bandwidth_usage = defaultdict(int)  # IP -> bytes
        self.protocol_distribution = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.connection_counts = defaultdict(int)
        self.geographic_traffic = defaultdict(int)
        self.application_usage = defaultdict(int)
        self.bandwidth_timeline = deque(maxlen=50)
        self.peak_usage = 0

        # Enhanced analytics data
        self.flow_analysis = defaultdict(lambda: {"bytes": 0, "packets": 0, "duration": 0, "last_seen": None})
        self.tcp_flags_distribution = defaultdict(int)
        self.packet_size_distribution = defaultdict(int)
        self.retransmission_count = defaultdict(int)
        self.session_data = defaultdict(lambda: {"start_time": None, "end_time": None, "bytes_total": 0})
        self.dns_queries = defaultdict(int)
        self.http_methods = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.threat_indicators = defaultdict(int)
        self.qos_metrics = defaultdict(lambda: {"latency": [], "jitter": [], "packet_loss": 0})
        self.network_conversations = defaultdict(lambda: {"in": 0, "out": 0, "total_bytes": 0})
        self.hourly_patterns = defaultdict(lambda: defaultdict(int))
        self.interface_statistics = defaultdict(lambda: {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0})
        self.error_statistics = defaultdict(int)
        self.fragmentation_stats = defaultdict(int)

    def add_traffic_data(self, data):
        self.traffic_history.append(data)

        # Update bandwidth usage
        self.bandwidth_usage[data["src_ip"]] += data["bytes_sent"]
        self.bandwidth_usage[data["dst_ip"]] += data["bytes_received"]

        # Update protocol distribution
        self.protocol_distribution[data["protocol"]] += data["bytes_sent"] + data["bytes_received"]

        # Update port activity
        self.port_activity[data["dst_port"]] += 1

        # Update connection counts
        self.connection_counts[data["src_ip"]] += 1

        # Geographic data
        self.geographic_traffic[data["src_country"]] += data["bytes_sent"]
        self.geographic_traffic[data["dst_country"]] += data["bytes_received"]

        # Application usage
        self.application_usage[data["application"]] += data["bytes_sent"] + data["bytes_received"]

        # Timeline data
        total_bytes = data["bytes_sent"] + data["bytes_received"]
        self.bandwidth_timeline.append({
            "timestamp": data["timestamp"],
            "bandwidth_mbps": total_bytes / (1024 * 1024),  # Convert to MB
            "connections": 1
        })

        # Update peak usage
        self.peak_usage = max(self.peak_usage, total_bytes)

        # Enhanced flow analysis
        flow_key = f"{data['src_ip']}:{data['src_port']}->{data['dst_ip']}:{data['dst_port']}"
        flow = self.flow_analysis[flow_key]
        flow["bytes"] += data["bytes_sent"] + data["bytes_received"]
        flow["packets"] += data["packets_sent"] + data["packets_received"]
        flow["last_seen"] = data["timestamp"]

        # TCP flags analysis
        for flag in data.get("flags", []):
            self.tcp_flags_distribution[flag] += 1

        # Packet size distribution
        packet_size = data["bytes_sent"]
        if packet_size < 64:
            self.packet_size_distribution["tiny (0-64)"] += 1
        elif packet_size < 256:
            self.packet_size_distribution["small (64-256)"] += 1
        elif packet_size < 1024:
            self.packet_size_distribution["medium (256-1024)"] += 1
        elif packet_size < 1518:
            self.packet_size_distribution["large (1024-1518)"] += 1
        else:
            self.packet_size_distribution["jumbo (>1518)"] += 1

        # Network conversations (bidirectional flows)
        conv_key = f"{min(data['src_ip'], data['dst_ip'])}<->{max(data['src_ip'], data['dst_ip'])}"
        conv = self.network_conversations[conv_key]
        conv["total_bytes"] += data["bytes_sent"] + data["bytes_received"]
        if data["src_ip"] < data["dst_ip"]:
            conv["out"] += data["bytes_sent"]
            conv["in"] += data["bytes_received"]
        else:
            conv["in"] += data["bytes_sent"]
            conv["out"] += data["bytes_received"]

        # Hourly traffic patterns
        current_hour = datetime.now().hour
        self.hourly_patterns[current_hour]["bytes"] += data["bytes_sent"] + data["bytes_received"]
        self.hourly_patterns[current_hour]["connections"] += 1

        # DNS query tracking
        if data["dst_port"] == 53 or data["src_port"] == 53:
            self.dns_queries[data["dst_ip"] if data["dst_port"] == 53 else data["src_ip"]] += 1

        # HTTP method tracking (simplified)
        if data["dst_port"] == 80 or data["dst_port"] == 443:
            self.http_methods["GET"] += 1  # Simplified - would need payload inspection

        # Security threat indicators
        self._analyze_security_threats(data)

        # Interface statistics
        interface = data.get("interface", "unknown")
        self.interface_statistics[interface]["tx_bytes"] += data["bytes_sent"]
        self.interface_statistics[interface]["rx_bytes"] += data["bytes_received"]
        self.interface_statistics[interface]["tx_packets"] += data["packets_sent"]
        self.interface_statistics[interface]["rx_packets"] += data["packets_received"]

    def _analyze_security_threats(self, data):
        """Analyze traffic for potential security threats"""
        # Port scanning detection
        if data["dst_port"] in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]:
            if self.connection_counts[data["src_ip"]] > 50:  # Many connections from same IP
                self.threat_indicators["potential_port_scan"] += 1

        # Suspicious ports
        suspicious_ports = [1337, 31337, 12345, 54321, 9999]
        if data["dst_port"] in suspicious_ports or data["src_port"] in suspicious_ports:
            self.threat_indicators["suspicious_ports"] += 1

        # Large packet anomalies
        if data["bytes_sent"] > 9000:  # Jumbo frames or potential attack
            self.threat_indicators["oversized_packets"] += 1

        # High frequency connections
        if self.connection_counts[data["src_ip"]] > 100:
            self.threat_indicators["high_frequency_connections"] += 1

    def get_statistics(self):
        total_bandwidth = sum(self.bandwidth_usage.values())
        total_connections = sum(self.connection_counts.values())

        # Calculate current bandwidth utilization
        recent_traffic = [t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=5)]
        current_bandwidth = sum(t["bytes_sent"] + t["bytes_received"] for t in recent_traffic) / (1024 * 1024)  # MB

        # Enhanced statistics
        total_flows = len(self.flow_analysis)
        active_flows = len([f for f in self.flow_analysis.values() if self._is_recent_flow(f["last_seen"])])

        # Top conversations
        top_conversations = dict(sorted(
            self.network_conversations.items(),
            key=lambda x: x[1]["total_bytes"],
            reverse=True
        )[:10])

        # Protocol efficiency
        protocol_efficiency = {}
        for proto, bytes_count in self.protocol_distribution.items():
            packets = sum(1 for t in self.traffic_history if t["protocol"] == proto)
            if packets > 0:
                protocol_efficiency[proto] = bytes_count / packets

        # Network utilization by hour
        current_hour = datetime.now().hour
        hourly_utilization = dict(self.hourly_patterns)

        return {
            "total_bandwidth_mb": sum(self.bandwidth_usage.values()) / (1024 * 1024),
            "current_bandwidth_mbps": self._calculate_current_bandwidth(),
            "peak_bandwidth_mb": self.peak_usage / (1024 * 1024),
            "total_connections": sum(self.connection_counts.values()),
            "active_connections": len([t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=5)]),
            "top_talkers": dict(sorted(self.bandwidth_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            "protocol_distribution": dict(self.protocol_distribution),
            "top_ports": dict(sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:10]),
            "connection_distribution": dict(sorted(self.connection_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "geographic_traffic": dict(self.geographic_traffic),
            "application_usage": dict(sorted(self.application_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            "bandwidth_timeline": list(self.bandwidth_timeline),
            "network_health_score": self._calculate_network_health(),

            # Enhanced analytics
            "flow_analysis": {
                "total_flows": total_flows,
                "active_flows": active_flows,
                "top_flows": dict(sorted(
                    [(k, v["bytes"]) for k, v in self.flow_analysis.items()],
                    key=lambda x: x[1], reverse=True
                )[:10]),
                "flow_duration_avg": self._calculate_avg_flow_duration()
            },
            "tcp_flags_distribution": dict(self.tcp_flags_distribution),
            "packet_size_distribution": dict(self.packet_size_distribution),
            "top_conversations": top_conversations,
            "protocol_efficiency": dict(sorted(protocol_efficiency.items(), key=lambda x: x[1], reverse=True)[:5]),
            "dns_activity": {
                "top_dns_servers": dict(sorted(self.dns_queries.items(), key=lambda x: x[1], reverse=True)[:5]),
                "total_queries": sum(self.dns_queries.values())
            },
            "http_analysis": {
                "methods": dict(self.http_methods),
                "user_agents": dict(sorted(self.user_agents.items(), key=lambda x: x[1], reverse=True)[:5])
            },
            "security_analysis": {
                "threat_indicators": dict(self.threat_indicators),
                "suspicious_ips": self._get_suspicious_ips(),
                "security_score": self._calculate_security_score()
            },
            "network_performance": {
                "average_packet_size": self._calculate_avg_packet_size(),
                "network_efficiency": self._calculate_network_efficiency(),
                "congestion_indicators": self._get_congestion_indicators()
            },
            "hourly_patterns": hourly_utilization,
            "interface_statistics": dict(self.interface_statistics),
            "network_topology": {
                "unique_sources": len(set(t["src_ip"] for t in self.traffic_history)),
                "unique_destinations": len(set(t["dst_ip"] for t in self.traffic_history)),
                "network_diameter": self._estimate_network_diameter()
            },
            "quality_of_service": {
                "retransmissions": dict(self.retransmission_count),
                "error_rates": self._calculate_error_rates(),
                "fragmentation_stats": dict(self.fragmentation_stats)
            }
        }

    def _calculate_current_bandwidth(self):
        """Calculate current bandwidth utilization"""
        recent_traffic = [t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=1)]
        if not recent_traffic:
            return 0
        total_bytes = sum(t["bytes_sent"] + t["bytes_received"] for t in recent_traffic)
        return (total_bytes / (1024 * 1024)) / 1  # MB per minute

    def _is_recent_flow(self, timestamp_str):
        """Check if a flow is recent (within last 5 minutes)"""
        return self._is_recent(timestamp_str, minutes=5)

    def _calculate_avg_flow_duration(self):
        """Calculate average flow duration"""
        durations = [f["duration"] for f in self.flow_analysis.values() if f["duration"] > 0]
        return sum(durations) / len(durations) if durations else 0

    def _get_suspicious_ips(self):
        """Identify potentially suspicious IP addresses"""
        suspicious = {}
        for ip, count in self.connection_counts.items():
            if count > 100:  # High connection count
                suspicious[ip] = {"reason": "high_connection_count", "count": count}
        return suspicious

    def _calculate_security_score(self):
        """Calculate overall security score"""
        score = 100
        total_threats = sum(self.threat_indicators.values())
        total_connections = sum(self.connection_counts.values())

        if total_connections > 0:
            threat_ratio = total_threats / total_connections
            score -= min(50, threat_ratio * 100)

        return max(0, score)

    def _calculate_avg_packet_size(self):
        """Calculate average packet size"""
        if not self.traffic_history:
            return 0
        total_bytes = sum(t["bytes_sent"] for t in self.traffic_history)
        total_packets = sum(t["packets_sent"] for t in self.traffic_history)
        return total_bytes / total_packets if total_packets > 0 else 0

    def _calculate_network_efficiency(self):
        """Calculate network efficiency based on retransmissions and errors"""
        total_packets = sum(t["packets_sent"] + t["packets_received"] for t in self.traffic_history)
        total_retransmissions = sum(self.retransmission_count.values())

        if total_packets == 0:
            return 100

        efficiency = ((total_packets - total_retransmissions) / total_packets) * 100
        return max(0, efficiency)

    def _get_congestion_indicators(self):
        """Get network congestion indicators"""
        recent_traffic = [t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=5)]

        if not recent_traffic:
            return {"status": "normal", "indicators": []}

        # Check for signs of congestion
        avg_packet_size = sum(t["bytes_sent"] for t in recent_traffic) / len(recent_traffic)
        connection_density = len(set(t["src_ip"] for t in recent_traffic))

        indicators = []
        status = "normal"

        if avg_packet_size < 100:  # Many small packets
            indicators.append("small_packet_flood")
            status = "warning"

        if connection_density > 50:  # Many different sources
            indicators.append("high_connection_density")
            status = "warning"

        return {"status": status, "indicators": indicators}

    def _calculate_error_rates(self):
        """Calculate various error rates"""
        total_packets = sum(t["packets_sent"] + t["packets_received"] for t in self.traffic_history)

        if total_packets == 0:
            return {"packet_loss": 0, "retransmission_rate": 0}

        total_retransmissions = sum(self.retransmission_count.values())
        total_errors = sum(self.error_statistics.values())

        return {
            "packet_loss": (total_errors / total_packets) * 100,
            "retransmission_rate": (total_retransmissions / total_packets) * 100
        }

    def _estimate_network_diameter(self):
        """Estimate network diameter based on unique IP ranges"""
        unique_networks = set()
        for traffic in self.traffic_history:
            src_network = ".".join(traffic["src_ip"].split(".")[:3]) + ".0"
            dst_network = ".".join(traffic["dst_ip"].split(".")[:3]) + ".0"
            unique_networks.add(src_network)
            unique_networks.add(dst_network)

        return len(unique_networks)

    def _is_recent(self, timestamp_str, minutes=5):
        try:
            traffic_time = datetime.strptime(timestamp_str, "%H:%M:%S").time()
            current_time = datetime.now().time()

            traffic_seconds = traffic_time.hour * 3600 + traffic_time.minute * 60 + traffic_time.second
            current_seconds = current_time.hour * 3600 + current_time.minute * 60 + current_time.second

            return abs(current_seconds - traffic_seconds) <= minutes * 60
        except:
            return False

    def _calculate_network_health(self):
        if not self.traffic_history:
            return 100

        # Calculate health based on bandwidth utilization and connection patterns
        recent_traffic = [t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=10)]

        if not recent_traffic:
            return 100

        # Check for unusual patterns
        avg_bandwidth = sum(t["bytes_sent"] + t["bytes_received"] for t in recent_traffic) / len(recent_traffic)
        connection_diversity = len(set(t["src_ip"] for t in recent_traffic))

        # Score based on normal patterns (this is simplified)
        health_score = 100

        # Penalize for very high bandwidth usage
        if avg_bandwidth > 10 * 1024 * 1024:  # 10MB average
            health_score -= 20

        # Penalize for low connection diversity (possible DDoS)
        if connection_diversity < 5:
            health_score -= 30

        return max(0, health_score)

    def process_packet_data(self, packet_data):
        """Process real packet data from Scapy capture"""
        if not packet_data.get("src") or not packet_data.get("dst"):
            return None

        # Create traffic data from real packet
        traffic_data = {
            "timestamp": packet_data["timestamp"],
            "src_ip": packet_data["src"],
            "dst_ip": packet_data["dst"],
            "src_country": self._get_country_from_ip(packet_data["src"]),
            "dst_country": self._get_country_from_ip(packet_data["dst"]),
            "protocol": packet_data["protocol"],
            "src_port": packet_data.get("src_port", 0),
            "dst_port": packet_data.get("dst_port", 0),
            "bytes_sent": packet_data["size"],
            "bytes_received": 0,  # We only see one direction in packet capture
            "packets_sent": 1,
            "packets_received": 0,
            "application": packet_data.get("application", "Unknown"),
            "flags": packet_data.get("flags", []),
            "ttl": packet_data.get("ttl", 64),
            "latency_ms": 0  # Would need round-trip measurement
        }

        self.add_traffic_data(traffic_data)
        return traffic_data

    def _get_country_from_ip(self, ip):
        """Simple IP to country mapping"""
        if not ip:
            return "Unknown"

        octets = ip.split('.')
        first_octet = int(octets[0])

        if first_octet in [192, 10, 172]:
            return "Local"
        elif first_octet < 50:
            return "USA"
        elif first_octet < 100:
            return "Europe"
        elif first_octet < 150:
            return "Asia"
        else:
            return "Other"

# Global analytics instance
network_analytics = NetworkAnalytics()

async def top_talkers_websocket(websocket: WebSocket):
    await websocket.accept()

    # Start packet capture if not already running
    if not packet_analyzer.is_capturing:
        packet_analyzer.start_capture()

    try:
        await websocket.send_json({
            "status": "Top Talkers monitoring started with real packet capture",
            "message": "Analyzing live network traffic patterns"
        })

        while True:
            # Get packet data from the analyzer
            packet_data = packet_analyzer.get_next_packet(timeout=0.5)

            if packet_data:
                # Process packet for traffic analysis
                traffic_data = network_analytics.process_packet_data(packet_data)

                if traffic_data:
                    # Send traffic data with statistics
                    response = {
                        "traffic": traffic_data,
                        "statistics": network_analytics.get_statistics()
                    }
                    await websocket.send_json(response)
            else:
                # Send periodic statistics update
                stats_update = {
                    "type": "stats_update",
                    "statistics": network_analytics.get_statistics()
                }
                await websocket.send_json(stats_update)

            await asyncio.sleep(0.2)  # Process packets every 200ms

    except WebSocketDisconnect:
        print("Top Talkers WebSocket disconnected.")
    except Exception as e:
        print(f"Top Talkers error: {e}")
