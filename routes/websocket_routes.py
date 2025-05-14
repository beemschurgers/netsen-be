from fastapi import APIRouter, WebSocket
from services.packet_capture import start_packet_capture

router = APIRouter()

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await start_packet_capture(websocket)