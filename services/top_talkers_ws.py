from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP
from collections import defaultdict
import asyncio
import threading
import json

async def top_talkers_websocket(websocket):
    await websocket.accept()
    loop = asyncio.get_running_loop()
    ip_counter = defaultdict(int)
    stop_event = threading.Event()

    def sniff_packets():
        def packet_callback(pkt):
            if IP in pkt:
                ip_counter[pkt[IP].src] += 1
        sniff(store=False, prn=packet_callback, stop_filter=lambda x: stop_event.is_set())

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

    try:
        while True:
            # Get top 5 IPs
            top = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            data = [{"ip": ip, "count": count} for ip, count in top]
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(2)  # adjust frequency
    except:
        stop_event.set()
        sniff_thread.join()
        await websocket.close()
