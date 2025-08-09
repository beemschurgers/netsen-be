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
        # ML Models
        self.frst_model = None
        self.threat_detection_model = None
        self.is_initialized = False
        
        # Capture settings
        self.interface = interface
        self.batch_size = batch_size
        self.capture_duration = capture_duration
        
        # Feature columns for ML models
        self.columns = [
            "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
            "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "rst_count",
            "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", 
            "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance"
        ]
        
        # Columns for threat detection model (removing specified features)
        self.threat_detection_columns = [
            "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
            "ack_count", "HTTP", "HTTPS", "DNS", "TCP", "UDP", "DHCP", "ICMP", "IPv",
            "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "Variance"
        ]
        
        # Flow tracking
        self.tcpflows = defaultdict(list)
        self.udpflows = defaultdict(list)
        
        # Counters
        self.src_packet_count = defaultdict(int)
        self.dst_packet_count = defaultdict(int)
        self.src_ip_byte = defaultdict(int)
        self.dst_ip_byte = defaultdict(int)
        self.packet_sizes = deque(maxlen=1000)
        
        # Timing and control
        self.last_packet_time = 0
        self.start_time = time.time()
        self.running = False
        self.packet_count = 0
        
        # Batch processing
        self.packet_queue = queue.Queue()
        
        # Recent results storage for WebSocket access
        self.recent_results = []
        self.max_recent_results = 100  # Keep last 100 results

    def load_model(self):
        """Load the ML models"""
        try:
            # Load threat detection model
            threat_model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'threat_detection_model.pkl')
            if os.path.exists(threat_model_path):
                with open(threat_model_path, 'rb') as f:
                    self.threat_detection_model = pickle.load(f)
            else:
                return False

            # Load main classification model
            model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'random_forest_model.pkl')
            with open(model_path, 'rb') as f:
                self.frst_model = pickle.load(f)

            self.is_initialized = True
            print("All ML Models loaded successfully!")
            return True
        except Exception as e:
            print(f"Error loading ML models: {e}")
            return False

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
                    features['flow_key'] = str(flow_key)
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
                    features['flow_key'] = str(flow_key)
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

    def packet_handler(self, packet):
        """Callback function for each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Process packet and extract features
        features = self.process_packet(packet)
        if features:
            self.packet_queue.put(features)
            

    def batch_processor(self):
        """Process packets in per-flow batches and make predictions"""
        flow_batches = {}

        while self.running:
            try:
                features = self.packet_queue.get(timeout=1)
                flow_key = features.get('flow_key', 'NO_FLOW')

                if flow_key not in flow_batches:
                    flow_batches[flow_key] = []

                flow_batches[flow_key].append(features)

                if len(flow_batches[flow_key]) >= self.batch_size:
                    self.process_batch_with_ml(flow_batches[flow_key])
                    flow_batches[flow_key] = []

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in batch processor: {e}")

        for batch in flow_batches.values():
            if batch:
                self.process_batch_with_ml(batch)

    def process_batch_with_ml(self, batch_data):
        """Process a batch of features and make prediction using two-stage approach"""
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
                
                # Build a single full DataFrame aligned to main model columns
                full_df = pd.DataFrame([aggregated], columns=self.columns).fillna(0)

                # Stage 1: Threat Detection Model using reduced column view
                threat_df = full_df.reindex(columns=self.threat_detection_columns, fill_value=0)
                threat_pred = self.threat_detection_model.predict(threat_df.to_numpy())[0]
                is_threat = bool(threat_pred)  # Assuming binary classification (0=benign, 1=threat)

                # Stage 2: Main Classification Model (only if threat detected)
                main_df = None
                if is_threat:
                    main_df = full_df
                    pred = self.frst_model.predict(full_df.to_numpy())[0]
                    label = str(pred)
                else:
                    label = 'BENIGN'
                
                # Get timestamp
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Prepare batch info
                flow_key_value = None
                if 'flow_key' in df.columns:
                    try:
                        flow_key_value = df['flow_key'].mode().iloc[0]
                    except Exception:
                        flow_key_value = df['flow_key'].iloc[0]

                batch_info = {
                    "timestamp": timestamp,
                    "flow_key": flow_key_value,
                    "packet_count": len(df),
                    "total_bytes": aggregated['Tot size'],
                    "predicted_label": label,
                    "is_threat": is_threat,
                    "threat_type": label if is_threat else None,
                    "threat_dataframe": threat_df.to_dict('records')[0] if is_threat else None,
                    "main_dataframe": main_df.to_dict('records')[0] if main_df is not None else None
                }
                
                # Store recent result for WebSocket access
                self.recent_results.append(batch_info)
                if len(self.recent_results) > self.max_recent_results:
                    self.recent_results.pop(0)  # Remove oldest result
                
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

    def get_recent_results(self, limit=10):
        """Get recent threat detection results for WebSocket access"""
        return self.recent_results[-limit:] if self.recent_results else []


# Global instance
ml_service = MLModelService()