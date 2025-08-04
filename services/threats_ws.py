# routes/threats_ws.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json
from datetime import datetime
from collections import defaultdict, deque
from .packet_capture import packet_analyzer

class ThreatAnalytics:
    def __init__(self):
        self.threat_history = deque(maxlen=1000)
        self.severity_counts = defaultdict(int)
        self.category_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.hourly_threats = defaultdict(int)
        self.top_sources = defaultdict(int)
        self.top_targets = defaultdict(int)
        self.geographic_data = defaultdict(int)
        self.threat_timeline = deque(maxlen=100)
        
    def process_packet_data(self, packet_data):
        """Process packet data from Scapy capture"""
        if not packet_data.get("is_threat", False):
            return None
        
        # Map threat types to categories and severity
        threat_mapping = {
            "Port Scan": {"severity": "Medium", "category": "Reconnaissance"},
            "DDoS": {"severity": "High", "category": "Availability"},
            "ICMP Flood": {"severity": "Medium", "category": "Availability"},
            "Network Scan": {"severity": "Low", "category": "Reconnaissance"},
            "Suspicious Traffic": {"severity": "Medium", "category": "Network"},
            "Network Reconnaissance": {"severity": "Medium", "category": "Reconnaissance"}
        }
        
        threat_info = threat_mapping.get(packet_data["threat_type"], {
            "severity": "Medium", 
            "category": "Unknown"
        })
        
        # Enhanced threat data using real packet information
        threat = {
            "time": packet_data["timestamp"],
            "src": packet_data["src"],
            "dst": packet_data["dst"],
            "type": packet_data["threat_type"],
            "severity": threat_info["severity"],
            "category": threat_info["category"],
            "protocol": packet_data["protocol"],
            "src_port": packet_data.get("src_port"),
            "dst_port": packet_data.get("dst_port"),
            "src_country": self._get_country_from_ip(packet_data["src"]),
            "bytes_transferred": packet_data["size"],
            "flags": packet_data.get("flags", []),
            "ttl": packet_data.get("ttl"),
            "confidence": packet_data.get("confidence", 85),
            "blocked": False,  # Would integrate with firewall in real scenario
            "application": packet_data.get("application", "Unknown")
        }
        
        self.add_threat(threat)
        return threat
    
    def _get_country_from_ip(self, ip):
        """Simple IP to country mapping (would use GeoIP in production)"""
        if not ip:
            return "Unknown"
        
        # Simple heuristic based on IP ranges (not accurate, just for demo)
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
        
    def add_threat(self, threat):
        self.threat_history.append(threat)
        self.severity_counts[threat["severity"]] += 1
        self.category_counts[threat["category"]] += 1
        self.protocol_counts[threat["protocol"]] += 1

        # Track hourly patterns
        hour = datetime.now().hour
        self.hourly_threats[hour] += 1

        # Track top sources and targets
        self.top_sources[threat["src"]] += 1
        self.top_targets[threat["dst"]] += 1

        # Mock geographic data
        self.geographic_data[threat.get("src_country", "Unknown")] += 1

        # Timeline data
        self.threat_timeline.append({
            "timestamp": threat["time"],
            "count": 1,
            "severity": threat["severity"]
        })

    def get_statistics(self):
        total_threats = len(self.threat_history)
        
        # Calculate threat trends
        recent_threats = [t for t in self.threat_history if self._is_recent(t["time"], minutes=10)]
        
        return {
            "total_threats": total_threats,
            "recent_threats_10min": len(recent_threats),
            "threats_per_minute": len(recent_threats) / 10 if recent_threats else 0,
            "severity_distribution": dict(self.severity_counts),
            "category_distribution": dict(self.category_counts),
            "protocol_distribution": dict(self.protocol_counts),
            "hourly_pattern": dict(self.hourly_threats),
            "top_sources": dict(sorted(self.top_sources.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_targets": dict(sorted(self.top_targets.items(), key=lambda x: x[1], reverse=True)[:10]),
            "geographic_distribution": dict(self.geographic_data),
            "threat_timeline": list(self.threat_timeline),
            "risk_score": self._calculate_risk_score()
        }

    def _is_recent(self, time_str, minutes=10):
        threat_time = datetime.strptime(time_str, "%H:%M:%S").time()
        current_time = datetime.now().time()

        # Simple time comparison (ignoring date for this example)
        threat_seconds = threat_time.hour * 3600 + threat_time.minute * 60 + threat_time.second
        current_seconds = current_time.hour * 3600 + current_time.minute * 60 + current_time.second

        return abs(current_seconds - threat_seconds) <= minutes * 60

    def _calculate_risk_score(self):
        if not self.threat_history:
            return 0

        # Calculate risk based on recent activity and severity
        recent_threats = [t for t in self.threat_history if self._is_recent(t["time"], minutes=30)]

        severity_weights = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        risk_score = sum(severity_weights.get(t["severity"], 1) for t in recent_threats)

        # Normalize to 0-100 scale
        return min(100, (risk_score / len(recent_threats) if recent_threats else 0) * 25)

# Global analytics instance
analytics = ThreatAnalytics()

async def threats_websocket(websocket: WebSocket):
    await websocket.accept()
    
    # Start packet capture if not already running
    if not packet_analyzer.is_capturing:
        packet_analyzer.start_capture()
    
    try:
        await websocket.send_json({
            "status": "Threat detection started with real packet capture",
            "message": "Analyzing live network traffic for threats"
        })
        
        while True:
            # Get packet data from the analyzer
            packet_data = packet_analyzer.get_next_packet(timeout=0.5)
            
            if packet_data:
                # Process packet for threat analysis
                threat = analytics.process_packet_data(packet_data)
                
                if threat:
                    # Send threat data with statistics
                    response = {
                        "threat": threat,
                        "statistics": analytics.get_statistics()
                    }
                    await websocket.send_json(response)
            else:
                # Send periodic statistics update even if no new threats
                stats_update = {
                    "type": "stats_update", 
                    "statistics": analytics.get_statistics()
                }
                await websocket.send_json(stats_update)
            
            await asyncio.sleep(0.1)  # Small delay to prevent overwhelming
            
    except WebSocketDisconnect:
        print("Threats WebSocket disconnected.")
    except Exception as e:
        print(f"Threat detection error: {e}")
    finally:
        # Keep packet analyzer running for other services
        pass
