import os
import pandas as pd
from datetime import datetime
from scapy.all import wrpcap


class ThreatLogger:
    def __init__(self, output_dir="logs"):
        self.output_dir = output_dir
        
        # Create output directories
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "csv"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "pcap"), exist_ok=True)
    
    def log_threat_dataframe(self, batch_info, full_df):
        """Log threat batch DataFrame to CSV and packets to PCAP"""
        try:
            # Add only flow_key and Stage 2 prediction to DataFrame
            df_with_metadata = full_df.copy()
            df_with_metadata['flow_key'] = batch_info['flow_key']
            df_with_metadata['predicted_label'] = batch_info['predicted_label']
            
            # Generate filename
            today = datetime.now().strftime("%Y%m%d")
            csv_file = os.path.join(self.output_dir, "csv", f"threat_{today}.csv")
            pcap_file = os.path.join(self.output_dir, "pcap", f"threat_{today}.pcap")
            
            # Append to CSV (create headers if file doesn't exist)
            if not os.path.exists(csv_file):
                df_with_metadata.to_csv(csv_file, index=False)
            else:
                df_with_metadata.to_csv(csv_file, mode='a', header=False, index=False)
            
            # Extract packets from flow buffers and clear them
            from services.ml_model_service import ml_service
            
            flow_key_tuple = eval(batch_info['flow_key']) if isinstance(batch_info['flow_key'], str) else batch_info['flow_key']
            packets = []
            
            # Check TCP flows
            if flow_key_tuple in ml_service.tcpflows:
                flow_data = ml_service.tcpflows[flow_key_tuple]
                packets = [item['raw_packet'] for item in flow_data if 'raw_packet' in item]
                # Clear the flow buffer after extracting packets
                ml_service.tcpflows[flow_key_tuple] = []
            
            # Check UDP flows
            elif flow_key_tuple in ml_service.udpflows:
                flow_data = ml_service.udpflows[flow_key_tuple]
                packets = [item['raw_packet'] for item in flow_data if 'raw_packet' in item]
                # Clear the flow buffer after extracting packets
                ml_service.udpflows[flow_key_tuple] = []
            
            if packets:
                # Append packets to single daily PCAP file
                wrpcap(pcap_file, packets, append=True)
                
        except Exception as e:
            pass


# Global instance
threat_logger = ThreatLogger()
