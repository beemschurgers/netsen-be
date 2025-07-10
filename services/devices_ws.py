from fastapi import WebSocket, WebSocketDisconnect
from scapy.all import ARP, Ether, srp
from datetime import datetime
import asyncio
import socket
import ipaddress
import logging

# 📋 Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')

# 🔍 Get primary IP (used to access the internet)
def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        logging.info(f"Primary IP detected: {ip}")
    finally:
        s.close()
    return ip

# 🔍 Get subnet from IP (e.g., 192.168.1.1/24)
def get_local_subnet():
    local_ip = get_primary_ip()
    network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
    logging.info(f"Local subnet calculated: {network}")
    return str(network)

# 📡 Scan devices in local subnet
def scan_devices():
    ip_range = get_local_subnet()
    logging.info(f"Scanning devices on subnet: {ip_range}")

    devices = []

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        device = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": None,  # optional: resolve via socket.gethostbyaddr
            "lastSeen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        logging.info(f"Device found: {device}")
        devices.append(device)

    logging.info(f"Total devices found: {len(devices)}")
    return devices

# 🔌 WebSocket handler
async def device_ws(websocket: WebSocket):
    await websocket.accept()
    logging.info("[Device WS] WebSocket connection accepted.")
    try:
        while True:
            logging.info("[Device WS] Scanning and sending device list...")
            devices = scan_devices()
            await websocket.send_json(devices)
            logging.info("[Device WS] Device list sent.")
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        logging.warning("[Device WS] Client disconnected.")
    except Exception as e:
        logging.error(f"[Device WS] Unexpected error: {e}")
    finally:
        if websocket.client_state.name == "CONNECTED":
            logging.info("[Device WS] Closing WebSocket connection.")
            await websocket.close()
