from fastapi import APIRouter, WebSocket
from scapy.all import ARP, Ether, srp
import asyncio
from datetime import datetime

def scan_devices(ip_range="192.168.2.2"):
    devices = []

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": None,  # Optional: use socket.gethostbyaddr
            "lastSeen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    return devices

async def device_ws(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            devices = scan_devices()
            await websocket.send_json(devices)
            await asyncio.sleep(10)  # rescan every 10 seconds
    except Exception as e:
        print("Device WS error:", e)
        await websocket.close()
