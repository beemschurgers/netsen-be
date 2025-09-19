from fastapi import APIRouter, WebSocket
from services.scapy_packet_capture import scapy_analyzer
from services.threats_ws import threats_websocket
from services.devices_ws import device_ws
from services.network_stats_ws import network_stats_websocket
from services.system_performance_ws import system_performance_websocket
import asyncio

from services.threat_detection_ws import threat_detection_websocket as threat_detection_handler

router = APIRouter()

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    """Direct scapy packet capture WebSocket endpoint"""
    await websocket.accept()
    print("Scapy packet capture WebSocket connected")

    # Send initial status message
    try:
        await websocket.send_json({
            "status": "connected",
            "capture_method": "scapy",
            "message": "Using direct scapy packet capture"
        })
    except Exception as e:
        print(f"Error sending initial message: {e}")

    try:
        # Start packet capture using scapy analyzer
        print("Starting scapy capture...")
        await scapy_analyzer.start_capture(interface=None)
        print("Scapy capture started")

        # Give capture some time to start
        await asyncio.sleep(2)

        while True:
            try:
                # Get packet data from scapy analyzer
                packet_data = scapy_analyzer.get_packet()

                # Get comprehensive statistics
                statistics = scapy_analyzer.get_comprehensive_statistics()

                # Debug logging
                if packet_data:
                    print(f"Sending packet data: {packet_data.get('protocol', 'Unknown')} from {packet_data.get('src_ip', 'N/A')}")
                else:
                    print("No packet data available, sending statistics only")

                # Create response with both packet and statistics
                response = {
                    "traffic": packet_data,
                    "statistics": statistics
                }

                await websocket.send_json(response)

                # Wait before next update
                await asyncio.sleep(1)

            except asyncio.TimeoutError:
                print("Timeout - sending statistics only")
                # Send statistics even if no new packets
                statistics = scapy_analyzer.get_comprehensive_statistics()
                response = {
                    "traffic": None,
                    "statistics": statistics
                }
                await websocket.send_json(response)
                await asyncio.sleep(1)

    except Exception as e:
        print(f"Scapy packet capture error: {e}")
        scapy_analyzer.stop_capture()
        try:
            await websocket.send_json({
                "error": f"Packet capture error: {str(e)}",
                "traffic": None,
                "statistics": scapy_analyzer.get_comprehensive_statistics()
            })
        except Exception as send_error:
            print(f"Error sending error message: {send_error}")
    finally:
        scapy_analyzer.stop_capture()
        print("Scapy packet capture WebSocket disconnected")


@router.websocket("/ws/devices")
async def devices_endpoint(websocket: WebSocket):
    await device_ws(websocket)


@router.websocket("/ws/network-stats")
async def network_stats_endpoint(websocket: WebSocket):
    await network_stats_websocket(websocket)


@router.websocket("/ws/threats")
async def threats_endpoint(websocket: WebSocket):
    await threats_websocket(websocket)

@router.websocket("/ws/threat-detection")
async def threat_detection_websocket(websocket: WebSocket):
    await threat_detection_handler(websocket)

@router.websocket("/ws/system-performance")
async def system_performance_endpoint(websocket: WebSocket):
    await system_performance_websocket(websocket)
