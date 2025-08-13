from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from datetime import datetime
from collections import defaultdict, deque
import json
import threading
import time
import subprocess
import socket
import os
from scapy.all import ARP, Ether, srp
import netifaces
import psutil

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
        self.is_scanning = False
        self.scan_thread = None
        self.last_scan_time = None
        
    def start_network_scan(self):
        """Start continuous network scanning in a separate thread"""
        if self.is_scanning:
            return
        
        self.is_scanning = True
        self.scan_thread = threading.Thread(target=self._continuous_scan, daemon=True)
        self.scan_thread.start()
    
    def stop_network_scan(self):
        """Stop network scanning"""
        self.is_scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=2)
    
    def _continuous_scan(self):
        """Continuously scan the network for devices"""
        while self.is_scanning:
            try:
                self._scan_network()
                self.last_scan_time = datetime.now()
                # Scan every 30 seconds
                time.sleep(30)
            except Exception as e:
                print(f"Network scan error: {e}")
                time.sleep(10)  # Wait before retrying
    
    def _scan_network(self):
        """Scan the local network for devices using ARP"""
        try:
            # Get network interfaces and their IP ranges
            interfaces = self._get_network_interfaces()
            
            for interface_info in interfaces:
                network = interface_info['network']
                interface = interface_info['interface']
                
                print(f"Scanning network {network} on interface {interface}")
                
                # Create ARP request
                arp_request = ARP(pdst=network)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                
                # Send ARP request and receive response
                try:
                    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
                    
                    for element in answered_list:
                        ip = element[1].psrc
                        mac = element[1].hwsrc
                        
                        # Create device data
                        device_data = self._create_device_data(ip, mac, interface_info)
                        self.add_device_data(device_data)
                        
                except Exception as e:
                    print(f"ARP scan error on {interface}: {e}")
                    # Fall back to ping sweep for this network
                    self._ping_sweep(network, interface_info)
                    
        except Exception as e:
            print(f"Network scanning error: {e}")
            # Generate fallback data with local system only
            self._generate_fallback_data()
    
    def _get_network_interfaces(self):
        """Get available network interfaces and their IP ranges"""
        interfaces = []
        
        try:
            # Get all network interfaces
            for interface_name in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface_name)
                    
                    # Check for IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            
                            if ip and netmask and not ip.startswith('127.'):
                                # Calculate network range
                                network = self._calculate_network_range(ip, netmask)
                                if network:
                                    interfaces.append({
                                        'interface': interface_name,
                                        'ip': ip,
                                        'netmask': netmask,
                                        'network': network
                                    })
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Interface detection error: {e}")
            # Fallback to common network ranges
            interfaces = [
                {'interface': 'default', 'ip': '192.168.1.1', 'netmask': '255.255.255.0', 'network': '192.168.1.0/24'},
                {'interface': 'default', 'ip': '10.0.0.1', 'netmask': '255.255.255.0', 'network': '10.0.0.0/24'}
            ]
        
        return interfaces
    
    def _calculate_network_range(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        try:
            import ipaddress
            
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            # Fallback calculation
            if netmask == "255.255.255.0":
                base = ".".join(ip.split(".")[:-1])
                return f"{base}.0/24"
            return None
    
    def _ping_sweep(self, network, interface_info):
        """Fallback ping sweep when ARP fails"""
        try:
            import ipaddress
            
            net = ipaddress.IPv4Network(network, strict=False)
            
            # Ping a subset of IPs (first 50 to avoid long delays)
            count = 0
            for ip in net.hosts():
                if count >= 50:  # Limit to avoid long scanning times
                    break
                    
                if self._ping_host(str(ip)):
                    # Try to get MAC address
                    mac = self._get_mac_address(str(ip))
                    device_data = self._create_device_data(str(ip), mac, interface_info)
                    self.add_device_data(device_data)
                
                count += 1
                
        except Exception as e:
            print(f"Ping sweep error: {e}")
    
    def _ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            # Use ping command
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=2)
            else:  # Unix/Linux/macOS
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_mac_address(self, ip):
        """Try to get MAC address for an IP"""
        try:
            # Try ARP table lookup first
            if os.name == 'nt':  # Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                return parts[1].replace('-', ':')
            else:  # Unix/Linux/macOS
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2]
            
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def _create_device_data(self, ip, mac, interface_info):
        """Create device data from discovered information"""
        device_id = f"DEV-{ip.replace('.', '-')}"
        
        # Try to get hostname
        hostname = self._get_hostname(ip)
        
        # Determine device type based on patterns
        device_type = self._determine_device_type(ip, mac, hostname)
        
        # Try to determine OS
        os_guess = self._guess_os(ip, hostname)
        
        # Get current performance metrics if it's the local machine
        cpu_usage, memory_usage, disk_usage = self._get_performance_metrics(ip)
        
        # Calculate uptime for local machine, unknown for others
        uptime_hours = self._get_uptime_hours(ip)
        
        return {
            "device_id": device_id,
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": mac,
            "subnet": interface_info.get('network', 'Unknown'),
            "device_type": device_type,
            "os": os_guess,
            "status": "online",  # If we found it, it's online
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "disk_usage": disk_usage,
            "network_utilization": 0,  # Would need SNMP or other protocol to get real data
            "uptime_hours": uptime_hours,
            "last_seen": datetime.now().strftime("%H:%M:%S"),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "risk_level": self._assess_risk_level(ip, device_type),
            "open_ports": self._scan_common_ports(ip),
            "running_services": 0,  # Would need system access to determine
            "patch_level": "Unknown",
            "antivirus_status": "Unknown", 
            "firewall_status": "Unknown",
            "location": "Network Discovered",
            "interface": interface_info.get('interface', 'Unknown'),
            "discovery_method": "Network Scan"
        }
    
    def _get_hostname(self, ip):
        """Try to resolve hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return f"device-{ip.split('.')[-1]}"
    
    def _determine_device_type(self, ip, mac, hostname):
        """Determine device type based on available information"""
        hostname_lower = hostname.lower()
        
        # Check hostname patterns
        if any(x in hostname_lower for x in ['router', 'rt', 'gw', 'gateway']):
            return "Router"
        elif any(x in hostname_lower for x in ['switch', 'sw']):
            return "Switch"
        elif any(x in hostname_lower for x in ['ap', 'wifi', 'wireless']):
            return "Access Point"
        elif any(x in hostname_lower for x in ['srv', 'server']):
            return "Server"
        elif any(x in hostname_lower for x in ['printer', 'print']):
            return "Printer"
        elif any(x in hostname_lower for x in ['phone', 'mobile', 'android', 'iphone']):
            return "Mobile Device"
        elif any(x in hostname_lower for x in ['iot', 'sensor', 'smart']):
            return "IoT Device"
        
        # Check MAC address patterns (OUI)
        if mac and len(mac) >= 8:
            oui = mac[:8].upper().replace(':', '')
            # Common manufacturer patterns
            if oui.startswith(('00:1B:63', '00:25:9C')):  # Cisco
                return "Network Device"
            elif oui.startswith(('00:50:56', '00:0C:29')):  # VMware
                return "Virtual Machine"
        
        # Check if it's likely a gateway/router (usually .1 or .254)
        last_octet = int(ip.split('.')[-1])
        if last_octet in [1, 254]:
            return "Router"
        
        return "Workstation"
    
    def _guess_os(self, ip, hostname):
        """Try to guess OS based on hostname and other factors"""
        hostname_lower = hostname.lower()
        
        if any(x in hostname_lower for x in ['win', 'windows', 'pc']):
            return "Windows"
        elif any(x in hostname_lower for x in ['ubuntu', 'linux', 'debian']):
            return "Linux"
        elif any(x in hostname_lower for x in ['mac', 'apple']):
            return "macOS"
        elif any(x in hostname_lower for x in ['android']):
            return "Android"
        elif any(x in hostname_lower for x in ['ios', 'iphone', 'ipad']):
            return "iOS"
        
        return "Unknown"
    
    def _get_performance_metrics(self, ip):
        """Get performance metrics if it's the local machine"""
        try:
            # Check if this is the local machine
            local_ips = [addr['addr'] for interface in netifaces.interfaces() 
                        for addr in netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])]
            
            if ip in local_ips:
                # Get actual system metrics
                cpu_usage = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                return cpu_usage, memory.percent, disk.percent
            else:
                # Cannot get performance metrics for remote devices without additional protocols
                return 0, 0, 0
                
        except Exception:
            return 0, 0, 0
    
    def _get_uptime_hours(self, ip):
        """Get uptime if it's the local machine"""
        try:
            # Check if this is the local machine
            local_ips = [addr['addr'] for interface in netifaces.interfaces() 
                        for addr in netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])]
            
            if ip in local_ips:
                return int(time.time() - psutil.boot_time()) // 3600
            else:
                return 0  # Unknown for remote devices
                
        except Exception:
            return 0
    
    def _assess_risk_level(self, ip, device_type):
        """Assess security risk level based on device characteristics"""
        # Default to low risk
        risk = "Low"
        
        # Higher risk for certain device types
        if device_type in ["IoT Device", "Unknown", "Mobile Device"]:
            risk = "Medium"
        elif device_type in ["Server", "Router", "Switch"]:
            # Infrastructure devices might need updates
            open_ports = self._scan_common_ports(ip)
            if open_ports > 5:
                risk = "Medium"
        
        return risk
    
    def _scan_common_ports(self, ip):
        """Scan common ports on a device"""
        common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = 0
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports += 1
                sock.close()
            except Exception:
                continue
        
        return open_ports
    
    def _generate_fallback_data(self):
        """Generate some fallback data when scanning fails"""
        # Add localhost as a device
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            device_data = {
                "device_id": "DEV-LOCAL",
                "hostname": socket.gethostname(),
                "ip_address": local_ip,
                "mac_address": "Local",
                "subnet": "127.0.0.0/8",
                "device_type": "Workstation",
                "os": "Local System",
                "status": "online",
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "network_utilization": 5,
                "uptime_hours": int(time.time() - psutil.boot_time()) // 3600,
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "risk_level": "Low",
                "open_ports": 5,
                "running_services": len(psutil.pids()),
                "patch_level": "Unknown",
                "antivirus_status": "Unknown",
                "firewall_status": "Unknown",
                "location": "Local",
                "interface": "local",
                "discovery_method": "Local System"
            }
            self.add_device_data(device_data)
        except Exception as e:
            print(f"Fallback data generation error: {e}")

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

# Global device monitoring instance
device_monitor = DeviceMonitoring()

async def device_ws(websocket: WebSocket):
    await websocket.accept()
    
    # Start network scanning
    device_monitor.start_network_scan()
    
    try:
        await websocket.send_json({
            "status": "Device discovery started",
            "message": "Scanning network for devices..."
        })
        
        while True:
            # Send current device data and statistics
            response = {
                "devices": list(device_monitor.devices.values()),
                "statistics": device_monitor.get_statistics(),
                "scan_info": {
                    "last_scan": device_monitor.last_scan_time.strftime("%H:%M:%S") if device_monitor.last_scan_time else "Not started",
                    "total_discovered": len(device_monitor.devices),
                    "scanning": device_monitor.is_scanning
                }
            }
            
            await websocket.send_json(response)
            
            # Send updates every 5 seconds
            await asyncio.sleep(5)
            
    except WebSocketDisconnect:
        print("Device WebSocket disconnected.")
        device_monitor.stop_network_scan()
    except Exception as e:
        print(f"Unexpected error in device monitoring: {e}")
        device_monitor.stop_network_scan()
