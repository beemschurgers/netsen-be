# services/network_stats_ws.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from datetime import datetime
from collections import defaultdict, deque
from .pyshark_packet_analyzer import pyshark_analyzer

class NetworkStatistics:
    def __init__(self):
        self.packet_stats = deque(maxlen=1000)
        self.protocol_breakdown = defaultdict(int)
        self.port_statistics = defaultdict(int)
        self.bandwidth_utilization = deque(maxlen=100)
        self.latency_measurements = deque(maxlen=50)
        self.error_counts = defaultdict(int)
        self.quality_metrics = deque(maxlen=50)
        self.network_health_history = deque(maxlen=24)

    def get_enhanced_statistics(self):
        """Get enhanced statistics from pyshark analyzer"""
        return pyshark_analyzer.get_comprehensive_statistics()

async def network_stats_websocket(websocket: WebSocket):
    """Enhanced network statistics WebSocket using pyshark data"""
    await websocket.accept()
    print("Network statistics WebSocket connected")

    try:
        # Start packet capture if not already running
        if not pyshark_analyzer.is_capturing:
            await pyshark_analyzer.start_capture()

        stats_tracker = NetworkStatistics()

        while True:
            # Get enhanced statistics from pyshark analyzer
            enhanced_stats = stats_tracker.get_enhanced_statistics()

            # Get recent packet for traffic info
            recent_packet = pyshark_analyzer.get_packet()

            response = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "statistics": enhanced_stats,
                "recent_traffic": recent_packet,
                "network_health": {
                    "overall_score": enhanced_stats.get("network_health_score", 100),
                    "bandwidth_utilization": enhanced_stats.get("current_bandwidth_mbps", 0),
                    "total_connections": enhanced_stats.get("total_connections", 0),
                    "packet_loss_rate": enhanced_stats.get("packet_loss_rate", 0),
                    "retransmission_rate": enhanced_stats.get("retransmission_rate", 0)
                },
                "security_overview": {
                    "alerts_count": len(enhanced_stats.get("security_alerts", [])),
                    "suspicious_ips": len([ip for ip in enhanced_stats.get("top_talkers", {}).keys()
                                         if not ip.startswith(('192.168.', '10.', '172.'))]),
                    "encrypted_traffic_ratio": enhanced_stats.get("application_usage", {}).get("HTTPS", 0) /
                                             max(sum(enhanced_stats.get("application_usage", {}).values()), 1) * 100
                }
            }

            await websocket.send_json(response)
            await asyncio.sleep(2)  # Update every 2 seconds

    except WebSocketDisconnect:
        print("Network statistics WebSocket disconnected")
    except Exception as e:
        print(f"Network statistics error: {e}")
        try:
            await websocket.send_json({
                "error": f"Network statistics error: {str(e)}",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            })
        except:
            pass
