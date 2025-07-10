# routes/threats_ws.py
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import random
from datetime import datetime

MOCK_THREATS = ["Port Scan", "DDoS", "MITM", "ARP Spoofing", "Data Exfiltration"]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

async def threats_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            threat = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src": random_ip(),
                "dst": random_ip(),
                "type": random.choice(MOCK_THREATS),
            }
            await websocket.send_json([threat])  # sends 1 at a time in a list
            await asyncio.sleep(random.uniform(2, 6))  # every 2–6 sec
    except WebSocketDisconnect:
        print("Threats WebSocket disconnected.")
