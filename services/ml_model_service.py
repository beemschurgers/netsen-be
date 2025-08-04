import threading
import asyncio
import pickle
import numpy as np
import pandas as pd
from collections import defaultdict
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import os


class MLModelService:
    def __init__(self):
        self.frst_model = None
        self.frst_encoder = None
        self.packet_stats = defaultdict(int)
        self.last_packet_time = None
        self.is_initialized = False

    def load_model(self):
        """Load the ML model and encoder"""
        try:
            model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'random_forest_model.pkl')
            encoder_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'label_encoder.pkl')

            with open(model_path, 'rb') as f:
                self.frst_model = pickle.load(f)

            with open(encoder_path, 'rb') as f:
                self.frst_encoder = pickle.load(f)

            self.is_initialized = True
            print("ML Model loaded successfully!")
            return True
        except Exception as e:
            print(f"Error loading ML model: {e}")
            return False

    def extract_features_from_packet(self, packet):
        """
        Extract features from a Scapy packet to match the model's expected input format.
        Returns a feature vector that matches the columns in Merged_dropped.txt (excluding 'Label' for prediction).
        """
        features = {}

        # Columns as per Merged_dropped.txt
        feature_columns = [
            'Protocol Type', 'Time_To_Live', 'Rate',
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
            'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
            'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC',
            'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC',
            'Tot sum', 'Min', 'Max', 'AVG', 'IAT', 'Number', 'Variance', 'Label'
        ]

        for col in feature_columns:
            features[col] = 0

        # Basic packet information
        features['Tot sum'] = self.packet_stats['total_size'] + len(packet)

        # Protocol type (convert to numeric)
        if packet.haslayer(IP):
            features['Protocol Type'] = packet[IP].proto
            features['Time_To_Live'] = packet[IP].ttl
            features['IPv'] = 1
        elif packet.haslayer(ARP):
            features['Protocol Type'] = 2054  # ARP protocol number
            features['ARP'] = 1
        else:
            features['Protocol Type'] = 0

        # TCP flags and counts
        if packet.haslayer(TCP):
            features['TCP'] = 1
            tcp = packet[TCP]
            features['fin_flag_number'] = 1 if tcp.flags & 0x01 else 0  # FIN
            features['syn_flag_number'] = 1 if tcp.flags & 0x02 else 0  # SYN
            features['rst_flag_number'] = 1 if tcp.flags & 0x04 else 0  # RST
            features['psh_flag_number'] = 1 if tcp.flags & 0x08 else 0  # PSH
            features['ack_flag_number'] = 1 if tcp.flags & 0x10 else 0  # ACK
            features['ece_flag_number'] = 1 if tcp.flags & 0x40 else 0  # ECE
            features['cwr_flag_number'] = 1 if tcp.flags & 0x80 else 0  # CWR
            # Port-based protocol detection
            if tcp.sport == 80 or tcp.dport == 80:
                features['HTTP'] = 1
            if tcp.sport == 443 or tcp.dport == 443:
                features['HTTPS'] = 1
            if tcp.sport == 22 or tcp.dport == 22:
                features['SSH'] = 1
            if tcp.sport == 23 or tcp.dport == 23:
                features['Telnet'] = 1
            if tcp.sport == 25 or tcp.dport == 25:
                features['SMTP'] = 1
            if tcp.sport == 6667 or tcp.dport == 6667:
                features['IRC'] = 1
        elif packet.haslayer(UDP):
            features['UDP'] = 1
            udp = packet[UDP]
            if udp.sport == 53 or udp.dport == 53:
                features['DNS'] = 1
            if udp.sport == 67 or udp.dport == 67 or udp.sport == 68 or udp.dport == 68:
                features['DHCP'] = 1
        elif packet.haslayer(ICMP):
            features['ICMP'] = 1
        # IGMP and LLC are not handled by scapy by default, set to 0
        features['IGMP'] = 0
        features['LLC'] = 0

        # Update packet statistics
        self.packet_stats['total_packets'] += 1
        self.packet_stats['total_size'] += len(packet)

        # Calculate IAT (Inter-Arrival Time)
        current_time = time.time()
        if self.last_packet_time is not None:
            features['IAT'] = current_time - self.last_packet_time
        else:
            features['IAT'] = 0
        self.last_packet_time = current_time

        # Calculate rate (packets per second - simplified)
        features['Rate'] = self.packet_stats['total_packets'] / max(current_time - (current_time - 1), 1)

        # Calculate statistics
        features['Number'] = self.packet_stats['total_packets']
        features['Min'] = min(len(packet), self.packet_stats.get('min_size', float('inf')))
        features['Max'] = max(len(packet), self.packet_stats.get('max_size', 0))

        # Update min/max tracking
        self.packet_stats['min_size'] = (features['Min'])
        self.packet_stats['max_size'] = (features['Max'])

        # Calculate average
        if self.packet_stats['total_packets'] > 0:
            features['AVG'] = self.packet_stats['total_size'] / self.packet_stats['total_packets']
        else:
            features['AVG'] = 0

        # Simplified variance calculation
        features['Variance'] = (features['Max'] - features['Min']) ** 2 / 4 if features['Max'] > features['Min'] else 0

        # 'Label' is a placeholder for prediction, set to 0 or empty string
        features['Label'] = 0

        # Convert to feature vector in the correct order (excluding 'Label' for prediction)
        feature_vector = []
        for col in feature_columns[:-1]:  # Exclude 'Label' for prediction
            feature_vector.append(features[col])

        return np.array(feature_vector, dtype='float32')

    def process_packet_with_ml(self, packet):
        """
        Process each captured packet and make prediction
        """
        if not self.is_initialized:
            return None

        try:
            # Extract features
            features = self.extract_features_from_packet(packet)

            # Reshape for model input
            features = features.reshape(1, -1)

            # Make prediction
            pred = self.frst_model.predict(features)[0]
            if isinstance(pred, (int, float)):
                label = self.frst_encoder.inverse_transform([int(pred)])[0]
            else:
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
            if packet.haslayer(IP):
                packet_info["src"] = packet[IP].src
                packet_info["dst"] = packet[IP].dst
                if packet.haslayer(TCP):
                    packet_info["protocol_detail"] = f"TCP ({packet[TCP].sport} -> {packet[TCP].dport})"
                elif packet.haslayer(UDP):
                    packet_info["protocol_detail"] = f"UDP ({packet[UDP].sport} -> {packet[UDP].dport})"
                elif packet.haslayer(ICMP):
                    packet_info["protocol_detail"] = "ICMP"
            else:
                packet_info["src"] = ""
                packet_info["dst"] = ""
                packet_info["protocol_detail"] = packet.name

            return packet_info

        except Exception as e:
            print(f"Error processing packet with ML: {e}")
            return None


# Global instance
ml_service = MLModelService()
