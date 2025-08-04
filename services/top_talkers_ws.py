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

    def get_statistics(self):
        total_bandwidth = sum(self.bandwidth_usage.values())
        total_connections = sum(self.connection_counts.values())

        # Calculate current bandwidth utilization
        recent_traffic = [t for t in self.traffic_history if self._is_recent(t["timestamp"], minutes=5)]
        current_bandwidth = sum(t["bytes_sent"] + t["bytes_received"] for t in recent_traffic) / (1024 * 1024)  # MB

        return {
            "total_bandwidth_mb": total_bandwidth / (1024 * 1024),
            "current_bandwidth_mbps": current_bandwidth / 5 if recent_traffic else 0,  # Average over 5 minutes
            "peak_bandwidth_mb": self.peak_usage / (1024 * 1024),
            "total_connections": total_connections,
            "active_connections": len(recent_traffic),
            "top_talkers": dict(sorted(self.bandwidth_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            "protocol_distribution": dict(self.protocol_distribution),
            "top_ports": dict(sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:10]),
            "connection_distribution": dict(sorted(self.connection_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "geographic_traffic": dict(self.geographic_traffic),
            "application_usage": dict(sorted(self.application_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            "bandwidth_timeline": list(self.bandwidth_timeline),
            "network_health_score": self._calculate_network_health()
        }

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
