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
from concurrent.futures import ThreadPoolExecutor


class MLModelService:
    def __init__(self, interface=None, batch_size=100, capture_duration=None):
        # ML Models
        self.stage1_model = None
        self.stage2_model = None
        self.is_initialized = False
        
        # Capture settings
        self.interface = interface
        self.batch_size = batch_size
        self.capture_duration = capture_duration
        self.max_batch_wait_seconds = 3
        
        # Feature columns for ML models (reduced to match model expectations)
        self.columns = [
            "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
            "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "rst_count",
            "HTTP", "HTTPS", "DNS", "Telnet", "SMTP"
        ]
        
        # Flow tracking
        self.tcpflows = defaultdict(list)
        self.udpflows = defaultdict(list)
        
        # Counters
        self.src_packet_count = defaultdict(int)
        self.dst_packet_count = defaultdict(int)
        self.src_ip_byte = defaultdict(int)
        self.dst_ip_byte = defaultdict(int)
        self.packet_sizes = deque(maxlen=10000)
        
        # Timing and control
        self.last_packet_time = 0
        self.start_time = time.time()
        self.running = False
        self.packet_count = 0
        
        # Batch processing
        self.packet_queue = queue.Queue()
        
        # Recent results storage for WebSocket access
        self.recent_results = []

        # Initialize models on creation
        self.load_model()

    def load_model(self):
        """Load the ML models with better error handling"""
        try:
            import warnings
            warnings.filterwarnings('ignore')

            print("Attempting to load ML models...")
            models_loaded = 0

            # Try to load stage1 model
            stage1_model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'stage1_model.pkl')
            print(f"Looking for stage1 model at: {stage1_model_path}")

            if os.path.exists(stage1_model_path):
                try:
                    with open(stage1_model_path, 'rb') as f:
                        self.stage1_model = pickle.load(f)
                    print("Stage1 model loaded successfully!")
                    models_loaded += 1
                except Exception as e:
                    print(f"Error loading stage1 model: {e}")
                    self.stage1_model = None
            else:
                print(f"Stage1 model file not found")

            # Try to load stage2 model
            stage2_model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'stage2_model.pkl')
            print(f"Looking for stage2 model at: {stage2_model_path}")

            if os.path.exists(stage2_model_path):
                try:
                    with open(stage2_model_path, 'rb') as f:
                        self.stage2_model = pickle.load(f)
                    print("Stage2 model loaded successfully!")
                    models_loaded += 1
                except Exception as e:
                    print(f"Error loading stage2 model: {e}")
                    self.stage2_model = None
            else:
                print(f"Stage2 model file not found")

            # Set initialization status based on whether any models loaded
            self.is_initialized = models_loaded > 0

            if self.is_initialized:
                print(f"ML service initialized with {models_loaded} model(s)")
            else:
                print("No ML models could be loaded. Service will run without ML analysis.")

            return self.is_initialized

        except Exception as e:
            print(f"Critical error loading ML models: {e}")
            self.is_initialized = False
            self.stage1_model = None
            self.stage2_model = None
            return False

    def extract_tcp_flags(self, tcp_packet):
        """Extract TCP flags from packet"""
        if not tcp_packet:
            return [0] * 8
            
        try:
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
        except:
            return [0] * 8

    def identify_application_protocol(self, src_port, dst_port):
        """Identify application protocol based on ports"""
        protocols = {
            'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0, 'SMTP': 0
        }
        
        # Check common ports
        if src_port == 80 or dst_port == 80:
            protocols['HTTP'] = 1
        elif src_port == 443 or dst_port == 443:
            protocols['HTTPS'] = 1
        elif src_port == 53 or dst_port == 53:
            protocols['DNS'] = 1
        elif src_port == 23 or dst_port == 23:
            protocols['Telnet'] = 1
        elif src_port == 25 or dst_port == 25:
            protocols['SMTP'] = 1

        return list(protocols.values())

    def extract_features(self, packet):
        """Extract features from a packet for ML analysis"""
        try:
            features = {}

            if IP in packet:
                ip = packet[IP]
                features['Header_Length'] = ip.ihl * 4
                features['Protocol Type'] = ip.proto
                features['Time_To_Live'] = ip.ttl

                # Calculate rate (simplified)
                current_time = time.time()
                features['Rate'] = 1.0 / max(current_time - self.last_packet_time, 0.001)
                self.last_packet_time = current_time

                src_port = dst_port = 0

                # Extract TCP features
                if TCP in packet:
                    tcp = packet[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport

                    # TCP flags
                    tcp_flags = self.extract_tcp_flags(tcp)
                    features.update({
                        'fin_flag_number': tcp_flags[0],
                        'syn_flag_number': tcp_flags[1],
                        'rst_flag_number': tcp_flags[2],
                        'psh_flag_number': tcp_flags[3],
                        'ack_flag_number': tcp_flags[4],
                        'ece_flag_number': tcp_flags[6],
                        'cwr_flag_number': tcp_flags[7]
                    })

                    # Flow counts
                    flow_key = f"{ip.src}-{ip.dst}-{tcp.sport}-{tcp.dport}"
                    self.tcpflows[flow_key].append(packet)

                else:
                    # Default TCP flag values
                    features.update({
                        'fin_flag_number': 0, 'syn_flag_number': 0, 'rst_flag_number': 0,
                        'psh_flag_number': 0, 'ack_flag_number': 0, 'ece_flag_number': 0,
                        'cwr_flag_number': 0
                    })

                if UDP in packet:
                    udp = packet[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport

                # Count flags and connections
                features.update({
                    'ack_count': sum(1 for f in self.tcpflows.values() if any(TCP in p and p[TCP].flags & 0x10 for p in f)),
                    'syn_count': sum(1 for f in self.tcpflows.values() if any(TCP in p and p[TCP].flags & 0x02 for p in f)),
                    'fin_count': sum(1 for f in self.tcpflows.values() if any(TCP in p and p[TCP].flags & 0x01 for p in f)),
                    'rst_count': sum(1 for f in self.tcpflows.values() if any(TCP in p and p[TCP].flags & 0x04 for p in f))
                })

                # Application protocol identification
                app_protocols = self.identify_application_protocol(src_port, dst_port)
                features.update({
                    'HTTP': app_protocols[0],
                    'HTTPS': app_protocols[1],
                    'DNS': app_protocols[2],
                    'Telnet': app_protocols[3],
                    'SMTP': app_protocols[4]
                })

            else:
                # Default values for non-IP packets
                features = {col: 0 for col in self.columns}

            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return {col: 0 for col in self.columns}

    def predict_with_models(self, features_df):
        """Make predictions using loaded models"""
        results = []

        if not self.is_initialized:
            # Return default values when no models are loaded
            for _ in range(len(features_df)):
                results.append({
                    'stage1_prediction': 'Normal',
                    'stage2_prediction': 'Normal',
                    'confidence': 0.5,
                    'threat_level': 'Low'
                })
            return results

        try:
            # Ensure features match expected number
            if len(features_df.columns) != len(self.columns):
                print(f"Feature mismatch: got {len(features_df.columns)}, expected {len(self.columns)}")
                # Pad or trim features to match expected size
                for col in self.columns:
                    if col not in features_df.columns:
                        features_df[col] = 0
                features_df = features_df[self.columns]

            for idx in range(len(features_df)):
                row_data = features_df.iloc[idx:idx+1]
                result = {
                    'stage1_prediction': 'Normal',
                    'stage2_prediction': 'Normal',
                    'confidence': 0.5,
                    'threat_level': 'Low'
                }

                # Stage 1 prediction
                if self.stage1_model is not None:
                    try:
                        stage1_pred = self.stage1_model.predict(row_data)[0]
                        stage1_prob = self.stage1_model.predict_proba(row_data)[0].max()
                        result['stage1_prediction'] = 'Anomaly' if stage1_pred == 1 else 'Normal'
                        result['confidence'] = float(stage1_prob)
                    except Exception as e:
                        print(f"Stage 1 prediction error: {e}")

                # Stage 2 prediction
                if self.stage2_model is not None:
                    try:
                        stage2_pred = self.stage2_model.predict(row_data)[0]
                        result['stage2_prediction'] = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'][int(stage2_pred)]

                        # Determine threat level
                        if stage2_pred in [1, 2]:  # DoS, Probe
                            result['threat_level'] = 'High'
                        elif stage2_pred in [3, 4]:  # R2L, U2R
                            result['threat_level'] = 'Critical'
                        else:
                            result['threat_level'] = 'Low'
                    except Exception as e:
                        print(f"Stage 2 prediction error: {e}")

                results.append(result)

        except Exception as e:
            print(f"Error during prediction: {e}")
            # Return default results on error
            for _ in range(len(features_df)):
                results.append({
                    'stage1_prediction': 'Normal',
                    'stage2_prediction': 'Normal',
                    'confidence': 0.5,
                    'threat_level': 'Low'
                })

        return results

    def process_packets_batch(self, packets):
        """Process a batch of packets"""
        if not packets:
            return []

        try:
            # Extract features from all packets
            features_list = []
            for packet in packets:
                features = self.extract_features(packet)
                features_list.append(features)

            if not features_list:
                return []

            # Create DataFrame
            features_df = pd.DataFrame(features_list)

            # Make predictions
            predictions = self.predict_with_models(features_df)

            # Store recent results
            self.recent_results.extend(predictions[-10:])  # Keep last 10 results
            self.recent_results = self.recent_results[-50:]  # Limit to 50 results

            return predictions

        except Exception as e:
            print(f"Error processing batch with ML: {e}")
            return []

    def add_packet(self, packet):
        """Add packet to processing queue"""
        try:
            self.packet_queue.put(packet, timeout=1)
            self.packet_count += 1
        except queue.Full:
            pass  # Drop packet if queue is full

    def get_recent_results(self):
        """Get recent ML analysis results"""
        return list(self.recent_results)

    def start_batch_processing(self):
        """Start batch processing in background thread"""
        self.running = True

        def batch_processor():
            batch = []
            last_process_time = time.time()

            while self.running:
                try:
                    # Try to get packet with timeout
                    try:
                        packet = self.packet_queue.get(timeout=1)
                        batch.append(packet)
                    except queue.Empty:
                        pass

                    current_time = time.time()

                    # Process batch if conditions are met
                    if (len(batch) >= self.batch_size or
                        (batch and current_time - last_process_time > self.max_batch_wait_seconds)):

                        if batch:
                            self.process_packets_batch(batch)
                            batch = []
                            last_process_time = current_time

                except Exception as e:
                    print(f"Error in batch processor: {e}")
                    batch = []  # Clear batch on error

        # Start background thread
        threading.Thread(target=batch_processor, daemon=True).start()
        print("ML batch processing started")

    def stop(self):
        """Stop the ML service"""
        self.running = False
        print("ML service stopped")


# Global ML service instance
ml_service = MLModelService()
ml_service.start_batch_processing()
