# services/system_performance_ws.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import random
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

class SystemPerformanceMonitor:
    def __init__(self):
        self.performance_history = deque(maxlen=200)
        self.cpu_timeline = deque(maxlen=100)
        self.memory_timeline = deque(maxlen=100)
        self.disk_timeline = deque(maxlen=100)
        self.network_io_timeline = deque(maxlen=100)
        self.process_stats = defaultdict(list)
        self.service_health = defaultdict(list)
        self.resource_alerts = deque(maxlen=50)
        self.system_events = deque(maxlen=100)
        
    def add_performance_data(self, data):
        self.performance_history.append(data)
        
        # Timeline data for charts
        timestamp = data["timestamp"]
        self.cpu_timeline.append({
            "timestamp": timestamp,
            "usage": data["cpu_usage"],
            "load_1min": data["load_average"]["1min"],
            "load_5min": data["load_average"]["5min"],
            "load_15min": data["load_average"]["15min"]
        })
        
        self.memory_timeline.append({
            "timestamp": timestamp,
            "usage_percent": data["memory"]["usage_percent"],
            "available_gb": data["memory"]["available_gb"],
            "cached_gb": data["memory"]["cached_gb"]
        })
        
        self.disk_timeline.append({
            "timestamp": timestamp,
            "usage_percent": data["disk"]["usage_percent"],
            "read_iops": data["disk"]["read_iops"],
            "write_iops": data["disk"]["write_iops"],
            "queue_length": data["disk"]["queue_length"]
        })
        
        self.network_io_timeline.append({
            "timestamp": timestamp,
            "bytes_in": data["network"]["bytes_in"],
            "bytes_out": data["network"]["bytes_out"],
            "packets_in": data["network"]["packets_in"],
            "packets_out": data["network"]["packets_out"]
        })
        
        # Process tracking
        for process in data["top_processes"]:
            self.process_stats[process["name"]].append({
                "timestamp": timestamp,
                "cpu_percent": process["cpu_percent"],
                "memory_mb": process["memory_mb"]
            })
        
        # Service health tracking
        for service in data["services"]:
            self.service_health[service["name"]].append({
                "timestamp": timestamp,
                "status": service["status"],
                "response_time": service.get("response_time", 0)
            })
        
        # Generate alerts
        self._check_and_generate_alerts(data)
        
        # System events
        if data["cpu_usage"] > 90:
            self.system_events.append({
                "timestamp": timestamp,
                "type": "warning",
                "message": f"High CPU usage: {data['cpu_usage']:.1f}%"
            })
        
        if data["memory"]["usage_percent"] > 85:
            self.system_events.append({
                "timestamp": timestamp,
                "type": "warning",
                "message": f"High memory usage: {data['memory']['usage_percent']:.1f}%"
            })
    
    def get_statistics(self):
        if not self.performance_history:
            return self._empty_stats()
        
        recent_data = list(self.performance_history)[-10:]
        latest = recent_data[-1]
        
        # Calculate trends
        cpu_trend = self._calculate_trend([d["cpu_usage"] for d in recent_data])
        memory_trend = self._calculate_trend([d["memory"]["usage_percent"] for d in recent_data])
        
        # System health score
        health_score = self._calculate_system_health(latest)
        
        return {
            "current_metrics": {
                "cpu_usage": latest["cpu_usage"],
                "memory_usage_percent": latest["memory"]["usage_percent"],
                "disk_usage_percent": latest["disk"]["usage_percent"],
                "network_throughput_mbps": (latest["network"]["bytes_in"] + latest["network"]["bytes_out"]) / (1024 * 1024),
                "load_average": latest["load_average"],
                "uptime_hours": latest["uptime_hours"]
            },
            "trends": {
                "cpu_trend": cpu_trend,
                "memory_trend": memory_trend,
                "disk_trend": self._calculate_trend([d["disk"]["usage_percent"] for d in recent_data])
            },
            "timelines": {
                "cpu": list(self.cpu_timeline),
                "memory": list(self.memory_timeline),
                "disk": list(self.disk_timeline),
                "network_io": list(self.network_io_timeline)
            },
            "top_processes": latest["top_processes"],
            "service_status": latest["services"],
            "system_health": {
                "overall_score": health_score,
                "status": self._get_health_status(health_score),
                "alerts": list(self.resource_alerts)[-10:]  # Last 10 alerts
            },
            "capacity_planning": {
                "cpu_headroom": 100 - latest["cpu_usage"],
                "memory_headroom": 100 - latest["memory"]["usage_percent"],
                "disk_headroom": 100 - latest["disk"]["usage_percent"],
                "estimated_capacity_days": self._estimate_capacity_timeline()
            },
            "performance_insights": self._generate_performance_insights(recent_data),
            "system_events": list(self.system_events)[-20:],  # Last 20 events
            "resource_efficiency": self._calculate_resource_efficiency(latest)
        }
    
    def _calculate_trend(self, values):
        if len(values) < 3:
            return "stable"
        
        recent_avg = sum(values[-3:]) / 3
        older_avg = sum(values[:-3]) / max(1, len(values) - 3)
        
        diff = recent_avg - older_avg
        
        if diff > 5:
            return "increasing"
        elif diff < -5:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_system_health(self, data):
        health_score = 100
        
        # CPU health
        if data["cpu_usage"] > 90:
            health_score -= 30
        elif data["cpu_usage"] > 70:
            health_score -= 15
        
        # Memory health
        if data["memory"]["usage_percent"] > 90:
            health_score -= 25
        elif data["memory"]["usage_percent"] > 80:
            health_score -= 10
        
        # Disk health
        if data["disk"]["usage_percent"] > 95:
            health_score -= 20
        elif data["disk"]["usage_percent"] > 85:
            health_score -= 10
        
        # Load average health
        if data["load_average"]["1min"] > 4:
            health_score -= 15
        
        # Service health
        failed_services = len([s for s in data["services"] if s["status"] != "running"])
        health_score -= failed_services * 5
        
        return max(0, health_score)
    
    def _get_health_status(self, score):
        if score >= 80:
            return "excellent"
        elif score >= 60:
            return "good"
        elif score >= 40:
            return "warning"
        else:
            return "critical"
    
    def _check_and_generate_alerts(self, data):
        timestamp = data["timestamp"]
        
        if data["cpu_usage"] > 85:
            self.resource_alerts.append({
                "timestamp": timestamp,
                "type": "cpu",
                "severity": "high" if data["cpu_usage"] > 95 else "medium",
                "message": f"High CPU usage: {data['cpu_usage']:.1f}%"
            })
        
        if data["memory"]["usage_percent"] > 85:
            self.resource_alerts.append({
                "timestamp": timestamp,
                "type": "memory",
                "severity": "high" if data["memory"]["usage_percent"] > 95 else "medium",
                "message": f"High memory usage: {data['memory']['usage_percent']:.1f}%"
            })
        
        if data["disk"]["usage_percent"] > 90:
            self.resource_alerts.append({
                "timestamp": timestamp,
                "type": "disk",
                "severity": "high",
                "message": f"High disk usage: {data['disk']['usage_percent']:.1f}%"
            })
    
    def _estimate_capacity_timeline(self):
        # Simplified capacity estimation
        if len(self.performance_history) < 10:
            return "insufficient_data"
        
        recent_growth = self._calculate_trend([d["memory"]["usage_percent"] for d in list(self.performance_history)[-10:]])
        
        if recent_growth == "increasing":
            return "30-60 days"
        elif recent_growth == "stable":
            return "90+ days"
        else:
            return "90+ days"
    
    def _generate_performance_insights(self, recent_data):
        insights = []
        
        avg_cpu = sum(d["cpu_usage"] for d in recent_data) / len(recent_data)
        avg_memory = sum(d["memory"]["usage_percent"] for d in recent_data) / len(recent_data)
        
        if avg_cpu > 70:
            insights.append("CPU utilization is consistently high. Consider load balancing or scaling.")
        
        if avg_memory > 80:
            insights.append("Memory usage is high. Monitor for memory leaks or consider adding RAM.")
        
        # Check for I/O bottlenecks
        avg_queue = sum(d["disk"]["queue_length"] for d in recent_data) / len(recent_data)
        if avg_queue > 5:
            insights.append("Disk I/O queue is elevated. Storage performance may be a bottleneck.")
        
        return insights
    
    def _calculate_resource_efficiency(self, data):
        # Calculate how efficiently resources are being used
        cpu_efficiency = min(100, (data["cpu_usage"] / 70) * 100) if data["cpu_usage"] < 70 else 100
        memory_efficiency = min(100, (data["memory"]["usage_percent"] / 80) * 100) if data["memory"]["usage_percent"] < 80 else 100
        
        overall_efficiency = (cpu_efficiency + memory_efficiency) / 2
        
        return {
            "cpu_efficiency": cpu_efficiency,
            "memory_efficiency": memory_efficiency,
            "overall_efficiency": overall_efficiency,
            "optimization_score": min(100, overall_efficiency + (100 - data["cpu_usage"]) * 0.2)
        }
    
    def _empty_stats(self):
        return {
            "current_metrics": {
                "cpu_usage": 0,
                "memory_usage_percent": 0,
                "disk_usage_percent": 0,
                "network_throughput_mbps": 0,
                "load_average": {"1min": 0, "5min": 0, "15min": 0},
                "uptime_hours": 0
            },
            "trends": {"cpu_trend": "stable", "memory_trend": "stable", "disk_trend": "stable"},
            "timelines": {"cpu": [], "memory": [], "disk": [], "network_io": []},
            "top_processes": [],
            "service_status": [],
            "system_health": {"overall_score": 100, "status": "excellent", "alerts": []},
            "capacity_planning": {"cpu_headroom": 100, "memory_headroom": 100, "disk_headroom": 100},
            "performance_insights": [],
            "system_events": [],
            "resource_efficiency": {"overall_efficiency": 100}
        }

def generate_mock_processes():
    processes = [
        {"name": "nginx", "cpu_percent": random.uniform(0.1, 15), "memory_mb": random.randint(50, 200)},
        {"name": "postgres", "cpu_percent": random.uniform(0.5, 25), "memory_mb": random.randint(100, 500)},
        {"name": "python", "cpu_percent": random.uniform(1, 30), "memory_mb": random.randint(80, 300)},
        {"name": "redis", "cpu_percent": random.uniform(0.2, 10), "memory_mb": random.randint(30, 150)},
        {"name": "node", "cpu_percent": random.uniform(0.5, 20), "memory_mb": random.randint(60, 250)}
    ]
    return sorted(processes, key=lambda x: x["cpu_percent"], reverse=True)[:5]

def generate_mock_services():
    services = [
        {"name": "web-server", "status": random.choice(["running", "running", "running", "stopped"]), "response_time": random.uniform(50, 200)},
        {"name": "database", "status": random.choice(["running", "running", "running", "error"]), "response_time": random.uniform(20, 100)},
        {"name": "cache", "status": random.choice(["running", "running", "starting"]), "response_time": random.uniform(5, 50)},
        {"name": "load-balancer", "status": "running", "response_time": random.uniform(10, 30)},
        {"name": "monitoring", "status": "running", "response_time": random.uniform(100, 300)}
    ]
    return services

# Global performance monitor instance
performance_monitor = SystemPerformanceMonitor()

async def system_performance_websocket(websocket: WebSocket):
    await websocket.accept()
    
    try:
        while True:
            # Generate system performance data
            performance_data = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "cpu_usage": random.uniform(10, 95),
                "load_average": {
                    "1min": random.uniform(0.1, 8.0),
                    "5min": random.uniform(0.1, 6.0),
                    "15min": random.uniform(0.1, 4.0)
                },
                "memory": {
                    "total_gb": 32,
                    "used_gb": random.uniform(8, 28),
                    "available_gb": random.uniform(4, 24),
                    "cached_gb": random.uniform(2, 8),
                    "usage_percent": random.uniform(25, 90)
                },
                "disk": {
                    "total_gb": 1000,
                    "used_gb": random.uniform(300, 800),
                    "usage_percent": random.uniform(30, 85),
                    "read_iops": random.randint(50, 2000),
                    "write_iops": random.randint(20, 1500),
                    "queue_length": random.uniform(0.1, 10)
                },
                "network": {
                    "bytes_in": random.randint(1048576, 104857600),  # 1MB to 100MB
                    "bytes_out": random.randint(1048576, 104857600),
                    "packets_in": random.randint(1000, 50000),
                    "packets_out": random.randint(1000, 50000)
                },
                "uptime_hours": random.randint(1, 8760),
                "top_processes": generate_mock_processes(),
                "services": generate_mock_services(),
                "temperature_celsius": random.uniform(35, 75),
                "fan_speed_rpm": random.randint(1500, 4000)
            }
            
            # Add to monitoring
            performance_monitor.add_performance_data(performance_data)
            
            # Send data and statistics
            response = {
                "current_data": performance_data,
                "statistics": performance_monitor.get_statistics()
            }
            
            await websocket.send_json(response)
            await asyncio.sleep(random.uniform(2, 4))  # every 2-4 seconds
            
    except WebSocketDisconnect:
        print("System Performance WebSocket disconnected.")
    except Exception as e:
        print(f"Unexpected error in system performance monitoring: {e}")
