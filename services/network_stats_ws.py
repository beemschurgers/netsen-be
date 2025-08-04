# services/network_stats_ws.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from datetime import datetime
from collections import defaultdict, deque
from .packet_capture import packet_analyzer

class NetworkStatistics:
    def __init__(self):
        self.packet_stats = deque(maxlen=1000)
        self.protocol_breakdown = defaultdict(int)
        self.port_statistics = defaultdict(int)
        self.bandwidth_utilization = deque(maxlen=100)
        self.latency_measurements = deque(maxlen=50)
        self.error_counts = defaultdict(int)
        self.quality_metrics = deque(maxlen=50)
        self.network_health_history = deque(maxlen=24)  # 24 hours of data

    def add_network_data(self, data):
        self.packet_stats.append(data)

        # Update protocol breakdown
        self.protocol_breakdown[data["protocol"]] += data["packet_count"]

        # Port statistics
        self.port_statistics[data["destination_port"]] += 1

        # Bandwidth tracking
        self.bandwidth_utilization.append({
            "timestamp": data["timestamp"],
            "utilization_percent": data["bandwidth_utilization"],
            "throughput_mbps": data["throughput_mbps"]
        })

        # Latency tracking
        self.latency_measurements.append({
            "timestamp": data["timestamp"],
            "avg_latency": data["avg_latency"],
            "max_latency": data["max_latency"],
            "min_latency": data["min_latency"]
        })

        # Error tracking
        if data["packet_loss"] > 0:
            self.error_counts["packet_loss"] += data["packet_loss"]
        if data["retransmissions"] > 0:
            self.error_counts["retransmissions"] += data["retransmissions"]

        # Quality metrics
        self.quality_metrics.append({
            "timestamp": data["timestamp"],
            "jitter": data["jitter"],
            "packet_loss_rate": data["packet_loss_rate"],
            "throughput_efficiency": data["throughput_efficiency"]
        })

        # Network health score
        health_score = self._calculate_current_health(data)
        self.network_health_history.append({
            "timestamp": data["timestamp"],
            "health_score": health_score
        })

    def get_statistics(self):
        if not self.packet_stats:
            return self._empty_stats()

        recent_data = list(self.packet_stats)[-10:]  # Last 10 measurements

        # Calculate aggregated metrics
        total_packets = sum(d["packet_count"] for d in recent_data)
        avg_bandwidth = sum(d["bandwidth_utilization"] for d in recent_data) / len(recent_data)
        avg_latency = sum(d["avg_latency"] for d in recent_data) / len(recent_data)
        total_throughput = sum(d["throughput_mbps"] for d in recent_data) / len(recent_data)

        # Network efficiency
        avg_efficiency = sum(d["throughput_efficiency"] for d in recent_data) / len(recent_data)

        return {
            "network_overview": {
                "total_packets_per_second": total_packets / 10,  # Average over 10 samples
                "bandwidth_utilization_percent": avg_bandwidth,
                "average_latency_ms": avg_latency,
                "current_throughput_mbps": total_throughput,
                "network_efficiency_percent": avg_efficiency
            },
            "protocol_distribution": dict(self.protocol_breakdown),
            "top_ports": dict(sorted(self.port_statistics.items(), key=lambda x: x[1], reverse=True)[:10]),
            "bandwidth_timeline": list(self.bandwidth_utilization),
            "latency_metrics": {
                "current_avg": avg_latency,
                "timeline": list(self.latency_measurements)
            },
            "error_statistics": dict(self.error_counts),
            "quality_metrics": {
                "current_jitter": recent_data[-1]["jitter"] if recent_data else 0,
                "packet_loss_rate": recent_data[-1]["packet_loss_rate"] if recent_data else 0,
                "timeline": list(self.quality_metrics)
            },
            "network_health": {
                "current_score": self.network_health_history[-1]["health_score"] if self.network_health_history else 100,
                "trend": self._calculate_health_trend(),
                "history": list(self.network_health_history)
            },
            "performance_alerts": self._generate_performance_alerts(recent_data),
            "network_capacity": self._analyze_capacity(recent_data),
            "traffic_patterns": self._analyze_traffic_patterns()
        }

    def _calculate_current_health(self, data):
        health_score = 100

        # Penalize for high latency
        if data["avg_latency"] > 100:
            health_score -= min(30, (data["avg_latency"] - 100) / 10)

        # Penalize for packet loss
        health_score -= min(40, data["packet_loss_rate"] * 2)

        # Penalize for high bandwidth utilization
        if data["bandwidth_utilization"] > 80:
            health_score -= min(20, (data["bandwidth_utilization"] - 80) / 2)

        # Penalize for low efficiency
        if data["throughput_efficiency"] < 70:
            health_score -= min(15, (70 - data["throughput_efficiency"]) / 5)

        return max(0, health_score)

    def _calculate_health_trend(self):
        if len(self.network_health_history) < 5:
            return "stable"

        recent_scores = [h["health_score"] for h in list(self.network_health_history)[-5:]]
        trend = (recent_scores[-1] - recent_scores[0]) / 4  # Average change per sample

        if trend > 2:
            return "improving"
        elif trend < -2:
            return "degrading"
        else:
            return "stable"

    def _generate_performance_alerts(self, recent_data):
        alerts = []
        if not recent_data:
            return alerts

        latest = recent_data[-1]

        if latest["bandwidth_utilization"] > 85:
            alerts.append(f"High bandwidth utilization: {latest['bandwidth_utilization']:.1f}%")

        if latest["avg_latency"] > 150:
            alerts.append(f"High latency detected: {latest['avg_latency']:.1f}ms")

        if latest["packet_loss_rate"] > 1:
            alerts.append(f"Packet loss detected: {latest['packet_loss_rate']:.2f}%")

        if latest["throughput_efficiency"] < 60:
            alerts.append(f"Low network efficiency: {latest['throughput_efficiency']:.1f}%")

        return alerts

    def _analyze_capacity(self, recent_data):
        if not recent_data:
            return {"status": "unknown", "utilization": 0}

        avg_utilization = sum(d["bandwidth_utilization"] for d in recent_data) / len(recent_data)

        if avg_utilization > 90:
            status = "critical"
        elif avg_utilization > 75:
            status = "warning"
        elif avg_utilization > 50:
            status = "normal"
        else:
            status = "low"

        return {
            "status": status,
            "utilization": avg_utilization,
            "available_capacity": 100 - avg_utilization
        }

    def _analyze_traffic_patterns(self):
        if len(self.packet_stats) < 10:
            return {"pattern": "insufficient_data"}

        recent_packets = [d["packet_count"] for d in list(self.packet_stats)[-10:]]
        avg_packets = sum(recent_packets) / len(recent_packets)
        variance = sum((x - avg_packets) ** 2 for x in recent_packets) / len(recent_packets)

        if variance > avg_packets * 0.5:
            pattern = "irregular"
        elif max(recent_packets) - min(recent_packets) > avg_packets * 0.3:
            pattern = "variable"
        else:
            pattern = "steady"

        return {
            "pattern": pattern,
            "average_pps": avg_packets,
            "variance": variance
        }

    def _empty_stats(self):
        return {
            "network_overview": {
                "total_packets_per_second": 0,
                "bandwidth_utilization_percent": 0,
                "average_latency_ms": 0,
                "current_throughput_mbps": 0,
                "network_efficiency_percent": 100
            },
            "protocol_distribution": {},
            "top_ports": {},
            "bandwidth_timeline": [],
            "latency_metrics": {"current_avg": 0, "timeline": []},
            "error_statistics": {},
            "quality_metrics": {"current_jitter": 0, "packet_loss_rate": 0, "timeline": []},
            "network_health": {"current_score": 100, "trend": "stable", "history": []},
            "performance_alerts": [],
            "network_capacity": {"status": "normal", "utilization": 0},
            "traffic_patterns": {"pattern": "steady"}
        }

    def process_packet_data(self, packet_data):
        """Process real packet data from Scapy capture"""
        if not packet_data:
            return None

        # Extract network statistics from real packet
        network_data = {
            "timestamp": packet_data["timestamp"],
            "packet_count": 1,
            "protocol": packet_data["protocol"],
            "destination_port": packet_data.get("dst_port", 0),
            "source_port": packet_data.get("src_port", 0),
            "packet_size": packet_data["size"],
            "src_ip": packet_data.get("src"),
            "dst_ip": packet_data.get("dst"),
            "flags": packet_data.get("flags", []),
            "ttl": packet_data.get("ttl", 64),
            # Calculated metrics (simplified for demo)
            "bandwidth_utilization": min(95, (packet_data["size"] / 1500) * 100),  # Based on MTU
            "throughput_mbps": (packet_data["size"] * 8) / (1024 * 1024),  # Convert to Mbps
            "avg_latency": 1.0,  # Would need RTT measurement
            "max_latency": 10.0,
            "min_latency": 0.1,
            "jitter": 0.5,
            "packet_loss": 0,  # Would need sequence analysis
            "packet_loss_rate": 0.0,
            "retransmissions": 0,  # Would detect from TCP analysis
            "throughput_efficiency": 85.0,  # Simplified calculation
            "connection_count": 1,
            "concurrent_sessions": 1
        }

        self.add_network_data(network_data)
        return network_data

# Global statistics instance
network_stats = NetworkStatistics()

async def network_stats_websocket(websocket: WebSocket):
    await websocket.accept()
    
    # Start packet capture if not already running
    if not packet_analyzer.is_capturing:
        packet_analyzer.start_capture()
    
    try:
        await websocket.send_json({
            "status": "Network statistics monitoring started with real packet capture",
            "message": "Analyzing live network performance metrics"
        })
        
        while True:
            # Get packet data from the analyzer
            packet_data = packet_analyzer.get_next_packet(timeout=0.5)
            
            if packet_data:
                # Process packet for network statistics
                network_data = network_stats.process_packet_data(packet_data)
                
                if network_data:
                    # Send network data with statistics
                    response = {
                        "current_data": network_data,
                        "statistics": network_stats.get_statistics()
                    }
                    await websocket.send_json(response)
            else:
                # Send periodic statistics update
                stats_update = {
                    "type": "stats_update",
                    "statistics": network_stats.get_statistics()
                }
                await websocket.send_json(stats_update)
            
            await asyncio.sleep(0.3)  # Process packets every 300ms
            
    except WebSocketDisconnect:
        print("Network Stats WebSocket disconnected.")
    except Exception as e:
        print(f"Network stats error: {e}")
