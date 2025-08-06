import threading
import pickle
import numpy as np
import pandas as pd
from collections import defaultdict, deque
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import os
import queue


class MLModelService:
    def __init__(self, interface=None, batch_size=10, capture_duration=None):
        self.frst_model = None
        self.is_initialized = False
        
        # Capture settings
        self.interface = interface
        self.batch_size = batch_size
        self.capture_duration = capture_duration
        
        # Feature columns for ML model
        self.columns = [
            "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
            "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "rst_count",
            "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", 
            "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance"
        ]
        
        # Flow tracking (essential for the system architecture)
        self.tcpflows = defaultdict(list)
        self.udpflows = defaultdict(list)
        
        # Counters
        self.src_packet_count = defaultdict(int)
        self.dst_packet_count = defaultdict(int)
        self.src_ip_byte = defaultdict(int)
        self.dst_ip_byte = defaultdict(int)
        
        # Protocol counters for window
        self.window_protocols = defaultdict(int)
        self.window_flags = defaultdict(int)
        
        # Timing
        self.last_packet_time = 0
        self.start_time = time.time()
        
        # Batch processing
        self.packet_queue = queue.Queue()
        self.batch_data = []
        
        # Control flags
        self.running = False
        self.packet_count = 0
        
        # Statistics
        self.packet_sizes = deque(maxlen=1000)  # Keep last 1000 packet sizes for stats

    def load_model(self):
        """Load the ML model"""
        try:
            model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'random_forest_model.pkl')

            with open(model_path, 'rb') as f:
                self.frst_model = pickle.load(f)

            self.is_initialized = True
            print("ML Model loaded successfully!")
            return True
        except Exception as e:
            print(f"Error loading ML model: {e}")
            return False

    def get_protocol_name(self, protocol_val):
        """Convert protocol number to name"""
        protocol_map = {
            0: "IP",
            6: "TCP", 
            17: "UDP",
            2: "IGMP",
            1: "ICMP"
        }
        return protocol_map.get(protocol_val, "Unknown")

    def extract_tcp_flags(self, tcp_packet):
        """Extract TCP flags as binary values"""
        if not tcp_packet:
            return [0] * 8
            
        flags = tcp_packet.flags
        return [
            int(flags & 0x01 != 0),  # FIN
            int(flags & 0x02 != 0),  # SYN  
            int(flags & 0x04 != 0),  # RST
            int(flags & 0x08 != 0),  # PSH
            int(flags & 0x10 != 0),  # ACK
            int(flags & 0x20 != 0),  # URG
            int(flags & 0x40 != 0),  # ECE
            int(flags & 0x80 != 0),  # CWR
        ]

    def identify_application_protocol(self, src_port, dst_port):
        """Identify application protocol based on ports"""
        protocols = {
            'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0, 'SMTP': 0,
            'SSH': 0, 'IRC': 0, 'DHCP': 0
        }
        
        # Check common ports
        if src_port == 80 or dst_port == 80:
            protocols['HTTP'] = 1
        if src_port == 443 or dst_port == 443:
            protocols['HTTPS'] = 1
        if src_port == 53 or dst_port == 53:
            protocols['DNS'] = 1
        if src_port == 23 or dst_port == 23:
            protocols['Telnet'] = 1
        if src_port == 25 or dst_port == 25:
            protocols['SMTP'] = 1
        if src_port == 22 or dst_port == 22:
            protocols['SSH'] = 1
        if src_port == 21 or dst_port == 21:
            protocols['IRC'] = 1
        if (src_port == 67 and dst_port == 68) or (src_port == 68 and dst_port == 67):
            protocols['DHCP'] = 1
            
        return protocols

    def get_flow_key(self, src_ip, src_port, dst_ip, dst_port):
        """Create consistent flow key (bidirectional)"""
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return (flow[0], flow[1])

    def calculate_flow_stats(self, flows, flow_key):
        """Calculate flow statistics"""
        if not flows.get(flow_key):
            return 0, 0, 0, 0, 0, 0, 0, 0, 0
            
        packets = flows[flow_key]
        if not packets:
            return 0, 0, 0, 0, 0, 0, 0, 0, 0
            
        # Calculate statistics
        total_bytes = sum(p['byte_count'] for p in packets)
        timestamps = [p['ts'] for p in packets]
        
        if len(timestamps) > 1:
            duration = max(timestamps) - min(timestamps)
            idle_time = timestamps[-1] - timestamps[-2] if len(timestamps) > 1 else 0
        else:
            duration = 0
            idle_time = 0
            
        max_duration = max(timestamps) if timestamps else 0
        min_duration = min(timestamps) if timestamps else 0
        sum_duration = sum(timestamps)
        avg_duration = sum_duration / len(timestamps) if timestamps else 0
        std_duration = np.std(timestamps) if len(timestamps) > 1 else 0
        active_time = duration
        
        return (total_bytes, duration, max_duration, min_duration, 
                sum_duration, avg_duration, std_duration, idle_time, active_time)

    def process_packet(self, packet):
        """Process a single packet and extract features"""
        try:
            # Basic packet info
            packet_size = len(packet)
            self.packet_sizes.append(packet_size)
            
            # Get current time for IAT calculation
            current_time = time.time()
            
            # Initialize feature values
            features = {
                'ts': current_time,  # Keep ts for internal calculations
                'Header_Length': 0,
                'Protocol Type': 0,
                'Time_To_Live': 0,
                'Rate': 0,
                'fin_flag_number': 0, 'syn_flag_number': 0, 'rst_flag_number': 0,
                'psh_flag_number': 0, 'ack_flag_number': 0, 'ece_flag_number': 0, 'cwr_flag_number': 0,
                'ack_count': 0, 'syn_count': 0, 'fin_count': 0, 'rst_count': 0,
                'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0, 'SMTP': 0, 'SSH': 0, 'IRC': 0,
                'TCP': 0, 'UDP': 0, 'DHCP': 0, 'ARP': 0, 'ICMP': 0, 'IGMP': 0, 'IPv': 0, 'LLC': 0,
                'Tot sum': 0, 'Min': 0, 'Max': 0, 'AVG': 0, 'Std': 0,
                'Tot size': packet_size, 'IAT': 0, 'Number': 1, 'Variance': 0
            }
            
            # Calculate IAT
            if self.last_packet_time > 0:
                features['IAT'] = current_time - self.last_packet_time
            self.last_packet_time = current_time
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                features['IPv'] = 1
                features['Protocol Type'] = ip_layer.proto
                features['Time_To_Live'] = ip_layer.ttl
                features['Header_Length'] = ip_layer.ihl * 4  # IP header length
                
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Update IP counters for flow analysis
                self.src_ip_byte[src_ip] += packet_size
                self.dst_ip_byte[dst_ip] += packet_size
                self.src_packet_count[src_ip] += 1
                self.dst_packet_count[dst_ip] += 1
                
                # Process TCP
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    features['TCP'] = 1
                    features['Header_Length'] += tcp_layer.dataofs * 4
                    
                    # Extract TCP flags
                    tcp_flags = self.extract_tcp_flags(tcp_layer)
                    features['fin_flag_number'] = tcp_flags[0]
                    features['syn_flag_number'] = tcp_flags[1]
                    features['rst_flag_number'] = tcp_flags[2]
                    features['psh_flag_number'] = tcp_flags[3]
                    features['ack_flag_number'] = tcp_flags[4]
                    features['ece_flag_number'] = tcp_flags[6]
                    features['cwr_flag_number'] = tcp_flags[7]
                    
                    # Update flag counters for current packet
                    if tcp_flags[4]: features['ack_count'] = 1
                    if tcp_flags[1]: features['syn_count'] = 1
                    if tcp_flags[0]: features['fin_count'] = 1
                    if tcp_flags[2]: features['rst_count'] = 1
                    
                    # Flow tracking
                    flow_key = self.get_flow_key(src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport)
                    flow_data = {
                        'byte_count': packet_size,
                        'header_len': features['Header_Length'],
                        'ts': features['ts']  # Use ts from features for flow tracking
                    }
                    self.tcpflows[flow_key].append(flow_data)
                    
                    # Application protocol identification
                    app_protocols = self.identify_application_protocol(tcp_layer.sport, tcp_layer.dport)
                    features.update(app_protocols)
                    
                # Process UDP
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    features['UDP'] = 1
                    features['Header_Length'] += 8  # UDP header is fixed 8 bytes
                    
                    # Flow tracking
                    flow_key = self.get_flow_key(src_ip, udp_layer.sport, dst_ip, udp_layer.dport)
                    flow_data = {
                        'byte_count': packet_size,
                        'header_len': features['Header_Length'],
                        'ts': features['ts']  # Use ts from features for flow tracking
                    }
                    self.udpflows[flow_key].append(flow_data)
                    
                    # Application protocol identification
                    app_protocols = self.identify_application_protocol(udp_layer.sport, udp_layer.dport)
                    features.update(app_protocols)
                    
                # Process ICMP
                elif ICMP in packet:
                    features['ICMP'] = 1
                    
                # Process IGMP
                elif packet.haslayer('IGMP'):
                    features['IGMP'] = 1
                    
            # Process ARP
            elif ARP in packet:
                features['ARP'] = 1
                features['Header_Length'] = 28  # ARP header size
                
            # Calculate packet size statistics
            if self.packet_sizes:
                features['Tot sum'] = sum(self.packet_sizes)
                features['Min'] = min(self.packet_sizes)
                features['Max'] = max(self.packet_sizes)
                features['AVG'] = np.mean(self.packet_sizes)
                features['Std'] = np.std(self.packet_sizes) if len(self.packet_sizes) > 1 else 0
                features['Variance'] = np.var(self.packet_sizes) if len(self.packet_sizes) > 1 else 0
            
            return features
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            return None

    def process_packet_with_ml(self, packet):
        """Process each captured packet and make prediction"""
        if not self.is_initialized:
            print("ML model not initialized")
            return None

        try:
            # Extract features using the existing process_packet method
            features = self.process_packet(packet)
            if features is None:
                print("Failed to extract features from packet")
                return None

            # Create feature vector for ML model
            feature_vector = []
            for col in self.columns:
                if col in features:
                    feature_vector.append(features[col])
                else:
                    feature_vector.append(0)  # Default value for missing columns

            # Reshape for model input
            features_array = np.array(feature_vector, dtype='float32').reshape(1, -1)

            # Make prediction
            pred = self.frst_model.predict(features_array)[0]
            label = str(pred)

            # Get timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Prepare packet info
            packet_info = {
                "timestamp": timestamp,
                "size": len(packet),
                "protocol": packet.name,
                "predicted_label": label,
                "is_threat": label != 'BENIGN',
                "threat_type": label if label != 'BENIGN' else None
            }

            # Add IP layer info if available
            if IP in packet:
                packet_info["src"] = packet[IP].src
                packet_info["dst"] = packet[IP].dst
                if TCP in packet:
                    packet_info["protocol_detail"] = f"TCP ({packet[TCP].sport} -> {packet[TCP].dport})"
                elif UDP in packet:
                    packet_info["protocol_detail"] = f"UDP ({packet[UDP].sport} -> {packet[UDP].dport})"
                elif ICMP in packet:
                    packet_info["protocol_detail"] = "ICMP"
            else:
                packet_info["src"] = ""
                packet_info["dst"] = ""
                packet_info["protocol_detail"] = packet.name

            return packet_info

        except Exception as e:
            print(f"Error processing packet with ML: {e}")
            return None

    def packet_handler(self, packet):
        """Callback function for each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Process packet and extract features
        features = self.process_packet(packet)
        if features:
            self.packet_queue.put(features)
            
        # Print progress
        if self.packet_count % 100 == 0:
            print(f"Captured {self.packet_count} packets...")

    def batch_processor(self):
        """Process packets in batches and make predictions"""
        batch_data = []
        
        while self.running:
            try:
                # Get packet with timeout
                features = self.packet_queue.get(timeout=1)
                batch_data.append(features)
                
                # Process batch when full
                if len(batch_data) >= self.batch_size:
                    self.process_batch_with_ml(batch_data)
                    batch_data = []
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in batch processor: {e}")
        
        # Process remaining packets
        if batch_data:
            self.process_batch_with_ml(batch_data)

    def process_batch_with_ml(self, batch_data):
        """Process a batch of features and make prediction"""
        if not self.is_initialized:
            return None

        try:
            # Create DataFrame
            df = pd.DataFrame(batch_data)
            
            # Calculate aggregated features
            if len(df) > 0:
                # Aggregate features
                aggregated = {
                    'Header_Length': df['Header_Length'].mean(),
                    'Protocol Type': df['Protocol Type'].mode().iloc[0] if len(df['Protocol Type'].mode()) > 0 else 0,
                    'Time_To_Live': df['Time_To_Live'].mean(),
                    'Rate': len(df) / (df['ts'].max() - df['ts'].min()) if df['ts'].max() != df['ts'].min() else 0,
                    'fin_flag_number': df['fin_flag_number'].sum() / len(df),
                    'syn_flag_number': df['syn_flag_number'].sum() / len(df),
                    'rst_flag_number': df['rst_flag_number'].sum() / len(df),
                    'psh_flag_number': df['psh_flag_number'].sum() / len(df),
                    'ack_flag_number': df['ack_flag_number'].sum() / len(df),
                    'ece_flag_number': df['ece_flag_number'].sum() / len(df),
                    'cwr_flag_number': df['cwr_flag_number'].sum() / len(df),
                    'ack_count': df['ack_count'].sum(),
                    'syn_count': df['syn_count'].sum(),
                    'fin_count': df['fin_count'].sum(),
                    'rst_count': df['rst_count'].sum(),
                    'HTTP': df['HTTP'].sum() / len(df),
                    'HTTPS': df['HTTPS'].sum() / len(df),
                    'DNS': df['DNS'].sum() / len(df),
                    'Telnet': df['Telnet'].sum() / len(df),
                    'SMTP': df['SMTP'].sum() / len(df),
                    'SSH': df['SSH'].sum() / len(df),
                    'IRC': df['IRC'].sum() / len(df),
                    'TCP': df['TCP'].sum() / len(df),
                    'UDP': df['UDP'].sum() / len(df),
                    'DHCP': df['DHCP'].sum() / len(df),
                    'ARP': df['ARP'].sum() / len(df),
                    'ICMP': df['ICMP'].sum() / len(df),
                    'IGMP': df['IGMP'].sum() / len(df),
                    'IPv': df['IPv'].sum() / len(df),
                    'LLC': df['LLC'].sum() / len(df),
                    'Tot sum': df['Tot size'].sum(),
                    'Min': df['Tot size'].min(),
                    'Max': df['Tot size'].max(),
                    'AVG': df['Tot size'].mean(),
                    'Std': df['Tot size'].std(),
                    'Tot size': df['Tot size'].sum(),
                    'IAT': df['IAT'].mean(),
                    'Number': len(df),
                    'Variance': df['Tot size'].var()
                }
                
                # Convert to feature vector for ML model
                feature_vector = []
                for col in self.columns:
                    if col in aggregated:
                        feature_vector.append(aggregated[col])
                    else:
                        feature_vector.append(0)  # Default value for missing columns
                
                # Reshape for model input
                features = np.array(feature_vector, dtype='float32').reshape(1, -1)
                
                # Make prediction
                pred = self.frst_model.predict(features)[0]
                label = str(pred)
                
                # Get timestamp
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Prepare batch info
                batch_info = {
                    "timestamp": timestamp,
                    "packet_count": len(df),
                    "total_bytes": aggregated['Tot size'],
                    "predicted_label": label,
                    "is_threat": label != 'BENIGN',
                    "threat_type": label if label != 'BENIGN' else None
                }
                
                # Print threat detection
                if batch_info["is_threat"]:
                    print(f"🚨 THREAT DETECTED: {batch_info['threat_type']}")
                    print(f"   Packets: {batch_info['packet_count']}, Bytes: {batch_info['total_bytes']}")
                    print(f"   Time: {batch_info['timestamp']}")
                    print("-" * 50)
                
                print(f"Processed batch of {len(df)} packets - Prediction: {label}")
                
                return batch_info
                
        except Exception as e:
            print(f"Error processing batch with ML: {e}")
            return None

    def start_capture(self):
        """Start live packet capture with flow tracking"""
        print(f"Starting live capture on interface: {self.interface or 'default'}")
        print(f"Batch size: {self.batch_size}")
        print("Press Ctrl+C to stop capture")
        
        # Start batch processor thread
        self.running = True
        batch_thread = threading.Thread(target=self.batch_processor)
        batch_thread.daemon = True
        batch_thread.start()
        
        try:
            # Start capture
            if self.capture_duration:
                print(f"Capturing for {self.capture_duration} seconds...")
                sniff(iface=self.interface, prn=self.packet_handler, 
                      store=0, timeout=self.capture_duration)
            else:
                print("Capturing indefinitely...")
                sniff(iface=self.interface, prn=self.packet_handler, store=0)
                
        except KeyboardInterrupt:
            print("\nStopping capture...")
        finally:
            self.running = False
            print(f"Capture stopped. Total packets captured: {self.packet_count}")
            print(f"TCP flows tracked: {len(self.tcpflows)}")
            print(f"UDP flows tracked: {len(self.udpflows)}")


# Global instance
ml_service = MLModelService()