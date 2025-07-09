from fastapi import APIRouter, WebSocket
from services.packet_capture import start_packet_capture
from services.top_talkers_ws import top_talkers_websocket
from services.devices_ws import device_ws
from services.threat_detection_ws import threat_detection_websocket

router = APIRouter()

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await start_packet_capture(websocket)


@router.websocket("/ws/top-talkers")
async def top_talkers_endpoint(websocket: WebSocket):
    await top_talkers_websocket(websocket)


@router.websocket("/ws/devices")
async def devices_endpoint(websocket: WebSocket):
    await device_ws(websocket)


@router.websocket("/ws/threat-detection")
async def threat_detection_endpoint(websocket: WebSocket):
    await threat_detection_websocket(websocket)



