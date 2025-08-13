from fastapi import APIRouter, WebSocket
from services.packet_capture import packet_capture_websocket
from services.threats_ws import threats_websocket
from services.devices_ws import device_ws
from services.network_stats_ws import network_stats_websocket
from services.system_performance_ws import system_performance_websocket

router = APIRouter()

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await packet_capture_websocket(websocket)


@router.websocket("/ws/devices")
async def devices_endpoint(websocket: WebSocket):
    await device_ws(websocket)


@router.websocket("/ws/network-stats")
async def network_stats_endpoint(websocket: WebSocket):
    await network_stats_websocket(websocket)


@router.websocket("/ws/threats")
async def threats_endpoint(websocket: WebSocket):
    await threats_websocket(websocket)


@router.websocket("/ws/system-performance")
async def system_performance_endpoint(websocket: WebSocket):
    await system_performance_websocket(websocket)
