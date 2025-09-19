# services/packet_capture.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json
from datetime import datetime
from .scapy_packet_capture import scapy_analyzer

# Global packet analyzer instance
packet_analyzer = scapy_analyzer

async def packet_capture_websocket(websocket: WebSocket):
    """Scapy-based packet capture WebSocket with proper async handling"""
    await websocket.accept()
    print("Packet capture WebSocket connected")
    
    # Send initial status message about capture method
    try:
        await websocket.send_json({
            "status": "connected",
            "capture_method": packet_analyzer.capture_method,
            "message": f"Using {packet_analyzer.capture_method} packet capture method"
        })
    except:
        pass
    
    try:
        # Start packet capture
        await packet_analyzer.start_capture(interface=None)
        
        # Give capture some time to start
        await asyncio.sleep(1)

        while True:
            try:
                # Wait for new packets with timeout
                packet_data = None

                # Check if we have any packets
                if packet_analyzer.packets:
                    packet_data = packet_analyzer.get_packet()

                # Get comprehensive statistics (always available)
                statistics = packet_analyzer.get_comprehensive_statistics()

                # Create response with both packet and statistics
                response = {
                    "traffic": packet_data,
                    "statistics": statistics
                }

                await websocket.send_json(response)

                # Wait before next update - this prevents overwhelming the client
                await asyncio.sleep(1)  # Send updates every second

            except asyncio.TimeoutError:
                # Send statistics even if no new packets
                statistics = packet_analyzer.get_comprehensive_statistics()
                response = {
                    "traffic": None,
                    "statistics": statistics
                }
                await websocket.send_json(response)
                await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("Packet capture WebSocket disconnected")
        packet_analyzer.stop_capture()
    except Exception as e:
        print(f"Packet capture error: {e}")
        packet_analyzer.stop_capture()
        try:
            await websocket.send_json({
                "error": f"Packet capture error: {str(e)}",
                "traffic": None,
                "statistics": packet_analyzer.get_comprehensive_statistics()
            })
        except:
            pass
