# ML Model Integration for Network Threat Detection

This document describes the integration of the ML model functions from the `model/` folder into the backend services.

## Overview

The ML model integration provides real-time network threat detection using a Random Forest classifier trained on network packet features. The model can classify network traffic as benign or identify various types of threats.

## Files Added/Modified

### New Files
- `services/ml_model_service.py` - Core ML model service with feature extraction and prediction
- `services/threat_detection_ws.py` - WebSocket service for real-time threat detection
- `routes/api_routes.py` - REST API endpoints for model management
- `templates/threat_detection.html` - Web interface for threat detection

### Modified Files
- `routes/websocket_routes.py` - Added threat detection WebSocket endpoint
- `routes/html_routes.py` - Added threat detection page route
- `main.py` - Added API routes
- `requirement.txt` - Added ML dependencies

## Features

### 1. Real-time Threat Detection
- WebSocket endpoint: `/ws/threat-detection`
- Analyzes packets in real-time using the ML model
- Provides detailed packet information and threat classification
- Maintains session statistics

### 2. REST API Endpoints
- `GET /api/model/status` - Check model loading status
- `POST /api/model/reload` - Reload the ML model
- `GET /api/model/stats` - Get current model statistics

### 3. Web Interface
- Access at `/threat-detection`
- Real-time packet analysis display
- Threat statistics dashboard
- Color-coded threat indicators

## Model Files Required

The following files must be present in the `model/` directory:
- `random_forest_model.pkl` - The trained Random Forest model
- `label_encoder.pkl` - Label encoder for threat type classification

## Dependencies Added

- `numpy` - For numerical operations
- `pandas` - For data manipulation
- `scikit-learn` - For ML model compatibility

## Usage

### Starting the Backend
```bash
pip install -r requirement.txt
python main.py
```

### Accessing Threat Detection
1. Open a web browser
2. Navigate to `http://localhost:8000/threat-detection`
3. Click "Start Threat Detection" to begin real-time analysis

### API Usage
```bash
# Check model status
curl http://localhost:8000/api/model/status

# Reload model
curl -X POST http://localhost:8000/api/model/reload

# Get statistics
curl http://localhost:8000/api/model/stats
```

## WebSocket Data Format

The threat detection WebSocket sends JSON messages with the following structure:

```json
{
  "timestamp": "2024-01-01 12:00:00",
  "size": 1500,
  "protocol": "IP",
  "src": "192.168.1.1",
  "dst": "192.168.1.2",
  "protocol_detail": "TCP (80 -> 443)",
  "predicted_label": "BENIGN",
  "is_threat": false,
  "threat_type": null,
  "session_stats": {
    "total_packets": 100,
    "threats_detected": 5,
    "benign_packets": 95,
    "threat_types": {
      "DoS": 3,
      "DDoS": 2
    }
  }
}
```

## Threat Types

The model can classify network traffic into various categories:
- `BENIGN` - Normal network traffic
- `DoS` - Denial of Service attacks
- `DDoS` - Distributed Denial of Service attacks
- `PortScan` - Port scanning activities
- `BruteForce` - Brute force attacks
- And other threat types based on the training data

## Security Considerations

1. **Administrator Privileges**: Packet capture requires administrator/root privileges
2. **Model Security**: Ensure model files are from trusted sources
3. **Network Access**: The system captures all network traffic on the interface
4. **Data Privacy**: Be aware of privacy implications when capturing network data

## Troubleshooting

### Model Loading Issues
- Ensure model files exist in the `model/` directory
- Check file permissions
- Verify model file integrity

### Permission Issues
- Run the application with administrator privileges
- On Windows, run as Administrator
- On Linux/Mac, use `sudo`

### WebSocket Connection Issues
- Check if the backend is running on port 8000
- Verify firewall settings
- Ensure WebSocket support in the browser

## Performance Notes

- The ML model processes packets in real-time
- Large packet volumes may impact performance
- Consider rate limiting for high-traffic networks
- Monitor memory usage during extended capture sessions 