import threading
import asyncio
from scapy.all import sniff, IP, ARP, Ether
from services.ml_model_service import ml_service

async def threat_detection_websocket(websocket):
    """WebSocket endpoint for real-time threat detection using ML model"""
    await websocket.accept()
    
    # Load the ML model if not already loaded
    if not ml_service.is_initialized:
        success = ml_service.load_model()
        if not success:
            await websocket.send_json({
                "error": "Failed to load ML model. Please check if model files exist."
            })
            await websocket.close()
            return
    
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()
    
    # Statistics for the session
    session_stats = {
        "total_packets": 0,
        "threats_detected": 0,
        "benign_packets": 0,
        "threat_types": {}
    }

    def capture_and_analyze(loop):
        def packet_callback(packet):
            if stop_event.is_set():
                return True
            
            # Process packet with ML model
            ml_result = ml_service.process_packet_with_ml(packet)
            
            if ml_result:
                # Update session statistics
                session_stats["total_packets"] += 1
                
                if ml_result["is_threat"]:
                    session_stats["threats_detected"] += 1
                    threat_type = ml_result["threat_type"]
                    session_stats["threat_types"][threat_type] = session_stats["threat_types"].get(threat_type, 0) + 1
                else:
                    session_stats["benign_packets"] += 1
                
                # Add session stats to the result
                ml_result["session_stats"] = session_stats
                
                # Send the result through WebSocket
                asyncio.run_coroutine_threadsafe(websocket.send_json(ml_result), loop)
        
        try:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
        except Exception as e:
            error_msg = f"Error during threat detection capture: {e}"
            print(error_msg)
            asyncio.run_coroutine_threadsafe(websocket.send_json({"error": error_msg}), loop)
        finally:
            asyncio.run_coroutine_threadsafe(websocket.close(), loop)

    # Start the capture thread
    thread = threading.Thread(target=capture_and_analyze, args=(loop,))
    thread.start()

    try:
        # Send initial status
        await websocket.send_json({
            "status": "Threat detection started",
            "model_loaded": ml_service.is_initialized,
            "message": "Real-time ML-based threat detection is now active"
        })
        
        # Keep the WebSocket connection alive
        while thread.is_alive():
            await asyncio.sleep(0.1)
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        stop_event.set()
        thread.join() 