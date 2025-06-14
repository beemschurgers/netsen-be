import threading
import asyncio
from scapy.all import sniff, IP

async def start_packet_capture(websocket):
    await websocket.accept()
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()

    def capture_packets(loop):
        def packet_callback(packet):
            if stop_event.is_set():
                return True
            summary = {
                "time": str(packet.time),
                "protocol": packet.name,
                "src": packet[IP].src if IP in packet else "",
                "dst": packet[IP].dst if IP in packet else "",
                "length": len(packet)
            }
            asyncio.run_coroutine_threadsafe(websocket.send_json(summary), loop)
        try:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
        except Exception as e:
            asyncio.run_coroutine_threadsafe(websocket.send_text(f"Error starting capture: {e}"), loop)
        finally:
            asyncio.run_coroutine_threadsafe(websocket.close(), loop)

    thread = threading.Thread(target=capture_packets, args=(loop,))
    thread.start()

    try:
        while thread.is_alive():
            await asyncio.sleep(0.1)
    finally:
        stop_event.set()
        thread.join()