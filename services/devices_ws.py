from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import random
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

class DeviceMonitoring:
    def __init__(self):
        self.devices = {}  # device_id -> device_info
        self.device_history = deque(maxlen=500)
        self.network_segments = defaultdict(list)
        self.device_types = defaultdict(int)
        self.os_distribution = defaultdict(int)
        self.vulnerability_counts = defaultdict(int)
        self.uptime_stats = defaultdict(list)
        self.performance_metrics = deque(maxlen=100)
        
    def add_device_data(self, device_data):
        device_id = device_data["device_id"]
        self.devices[device_id] = device_data
        self.device_history.append(device_data)
        
        # Update statistics
        self.network_segments[device_data["subnet"]].append(device_id)
        self.device_types[device_data["device_type"]] += 1
        self.os_distribution[device_data["os"]] += 1
        self.vulnerability_counts[device_data["risk_level"]] += 1
        self.uptime_stats[device_id].append(device_data["uptime_hours"])
        
        # Performance tracking
        self.performance_metrics.append({
            "timestamp": device_data["timestamp"],
            "total_devices": len(self.devices),
            "online_devices": sum(1 for d in self.devices.values() if d["status"] == "online"),
            "avg_cpu_usage": sum(d["cpu_usage"] for d in self.devices.values()) / len(self.devices),
            "avg_memory_usage": sum(d["memory_usage"] for d in self.devices.values()) / len(self.devices)
        })
        
    def get_statistics(self):
        online_devices = [d for d in self.devices.values() if d["status"] == "online"]
        offline_devices = [d for d in self.devices.values() if d["status"] == "offline"]
        
        # Calculate network health metrics
        total_cpu = sum(d["cpu_usage"] for d in online_devices) / len(online_devices) if online_devices else 0
        total_memory = sum(d["memory_usage"] for d in online_devices) / len(online_devices) if online_devices else 0
        
        # Security posture
        high_risk_devices = len([d for d in self.devices.values() if d["risk_level"] == "High"])
        critical_devices = len([d for d in self.devices.values() if d["risk_level"] == "Critical"])
        
        return {
            "total_devices": len(self.devices),
            "online_devices": len(online_devices),
            "offline_devices": len(offline_devices),
            "device_uptime_percentage": (len(online_devices) / len(self.devices) * 100) if self.devices else 0,
            "average_cpu_usage": total_cpu,
            "average_memory_usage": total_memory,
            "network_segments": {k: len(v) for k, v in self.network_segments.items()},
            "device_types": dict(self.device_types),
            "os_distribution": dict(self.os_distribution),
            "risk_distribution": dict(self.vulnerability_counts),
            "high_risk_devices": high_risk_devices,
            "critical_devices": critical_devices,
            "performance_timeline": list(self.performance_metrics),
            "security_score": self._calculate_security_score(),
            "performance_score": self._calculate_performance_score(),
            "top_cpu_consumers": self._get_top_resource_consumers("cpu_usage"),
            "top_memory_consumers": self._get_top_resource_consumers("memory_usage"),
            "recent_alerts": self._get_recent_alerts()
        }
    
    def _calculate_security_score(self):
        if not self.devices:
            return 100
        
        total_devices = len(self.devices)
        high_risk = self.vulnerability_counts.get("High", 0)
        critical_risk = self.vulnerability_counts.get("Critical", 0)
        
        # Calculate score based on risk distribution
        score = 100 - (high_risk / total_devices * 30) - (critical_risk / total_devices * 50)
        return max(0, score)
    
    def _calculate_performance_score(self):
        online_devices = [d for d in self.devices.values() if d["status"] == "online"]
        if not online_devices:
            return 100
        
        avg_cpu = sum(d["cpu_usage"] for d in online_devices) / len(online_devices)
        avg_memory = sum(d["memory_usage"] for d in online_devices) / len(online_devices)
        
        # Score based on resource utilization
        cpu_score = max(0, 100 - avg_cpu)
        memory_score = max(0, 100 - avg_memory)
        
        return (cpu_score + memory_score) / 2
    
    def _get_top_resource_consumers(self, metric):
        return dict(sorted(
            [(d["hostname"], d[metric]) for d in self.devices.values() if d["status"] == "online"],
            key=lambda x: x[1], reverse=True
        )[:5])
    
    def _get_recent_alerts(self):
        alerts = []
        for device in self.devices.values():
            if device["cpu_usage"] > 80:
                alerts.append(f"High CPU usage on {device['hostname']}: {device['cpu_usage']}%")
            if device["memory_usage"] > 85:
                alerts.append(f"High memory usage on {device['hostname']}: {device['memory_usage']}%")
            if device["risk_level"] in ["High", "Critical"]:
                alerts.append(f"Security risk on {device['hostname']}: {device['risk_level']} risk level")
        return alerts[:10]  # Return top 10 alerts

def random_hostname():
    prefixes = ["WS", "SRV", "DB", "WEB", "APP", "DC", "LB", "FW"]
    return f"{random.choice(prefixes)}-{random.randint(100, 999)}"

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_subnet():
    return f"192.168.{random.randint(1, 50)}.0/24"

def random_mac():
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def random_os():
    os_list = ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022", 
               "Ubuntu 20.04", "Ubuntu 22.04", "CentOS 7", "RHEL 8", "macOS Monterey", "macOS Ventura"]
    return random.choice(os_list)

def random_device_type():
    types = ["Workstation", "Server", "Router", "Switch", "Firewall", "Printer", "IoT Device", "Mobile", "Laptop"]
    return random.choice(types)

# Global device monitoring instance
device_monitor = DeviceMonitoring()

async def device_ws(websocket: WebSocket):
    await websocket.accept()
    device_counter = 1
    
    try:
        while True:
            # Generate device data
            device_data = {
                "device_id": f"DEV-{device_counter:04d}",
                "hostname": random_hostname(),
                "ip_address": random_ip(),
                "mac_address": random_mac(),
                "subnet": random_subnet(),
                "device_type": random_device_type(),
                "os": random_os(),
                "status": random.choice(["online", "online", "online", "offline"]),  # 75% online
                "cpu_usage": random.randint(5, 95),
                "memory_usage": random.randint(20, 90),
                "disk_usage": random.randint(30, 85),
                "network_utilization": random.randint(1, 100),
                "uptime_hours": random.randint(1, 8760),  # Up to 1 year
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "risk_level": random.choice(["Low", "Medium", "High", "Critical"]),
                "open_ports": random.randint(1, 50),
                "running_services": random.randint(10, 100),
                "patch_level": random.choice(["Up to date", "Minor updates needed", "Critical updates needed"]),
                "antivirus_status": random.choice(["Protected", "Outdated", "Not installed"]),
                "firewall_status": random.choice(["Enabled", "Disabled", "Partially configured"]),
                "location": random.choice(["Building A", "Building B", "Data Center", "Remote", "Branch Office"])
            }
            
            # Add to monitoring
            device_monitor.add_device_data(device_data)
            
            # Send device data and statistics
            response = {
                "device": device_data,
                "statistics": device_monitor.get_statistics()
            }
            
            await websocket.send_json(response)
            device_counter += 1
            
            # Simulate different update frequencies
            await asyncio.sleep(random.uniform(2, 5))  # every 2-5 seconds
            
    except WebSocketDisconnect:
        print("Device WebSocket disconnected.")
    except Exception as e:
        print(f"Unexpected error in device monitoring: {e}")
