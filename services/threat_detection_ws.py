import threading
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from scapy.all import sniff, IP, ARP, Ether
from services.ml_model_service import ml_service
from datetime import datetime

async def threat_detection_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time threat detection using ML model"""
    await websocket.accept()
    print("Threat detection WebSocket connected")
    
    # Load the ML model if not already loaded
    if not ml_service.is_initialized:
        print("Loading ML model...")
        success = ml_service.load_model()
        if not success:
            error_msg = "Failed to load ML model. Please check if model files exist."
            print(error_msg)
            await websocket.send_json({"error": error_msg})
            return
        else:
            print("ML model loaded successfully")
    
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
            
            try:
                print(f"Processing packet: {packet.name} ({len(packet)} bytes)")
                # Process packet with ML model
                ml_result = ml_service.process_packet_with_ml(packet)
                
                if ml_result:
                    # Update session statistics
                    session_stats["total_packets"] += 1
                    
                    if ml_result["is_threat"]:
                        session_stats["threats_detected"] += 1
                        threat_type = ml_result["threat_type"]
                        session_stats["threat_types"][threat_type] = session_stats["threat_types"].get(threat_type, 0) + 1
                        print(f"🚨 THREAT DETECTED: {threat_type}")
                    else:
                        session_stats["benign_packets"] += 1
                    
                    # Add session stats to the result
                    ml_result["session_stats"] = session_stats.copy()
                    
                    # Send the result through WebSocket
                    asyncio.run_coroutine_threadsafe(websocket.send_json(ml_result), loop)
                else:
                    print("Failed to process packet with ML")
                    
            except Exception as e:
                print(f"Error processing packet: {e}")
        
        try:
            print("Starting packet capture...")
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
        except PermissionError:
            error_msg = "Permission denied. Please run the application as administrator for packet capture."
            print(error_msg)
            asyncio.run_coroutine_threadsafe(websocket.send_json({"error": error_msg}), loop)
        except OSError as e:
            if "Permission denied" in str(e):
                error_msg = "Permission denied. Please run the application as administrator for packet capture."
            else:
                error_msg = f"OS Error in packet capture: {str(e)}"
            print(error_msg)
            asyncio.run_coroutine_threadsafe(websocket.send_json({"error": error_msg}), loop)
        except Exception as e:
            error_msg = f"Error during threat detection capture: {e}"
            print(error_msg)
            asyncio.run_coroutine_threadsafe(websocket.send_json({"error": error_msg}), loop)

    # Start the capture thread
    thread = threading.Thread(target=capture_and_analyze, args=(loop,))
    thread.daemon = True
    thread.start()

    # Send initial status
    await websocket.send_json({
        "status": "Connected - Threat detection active",
        "model_loaded": ml_service.is_initialized,
        "message": "Real-time ML-based threat detection is now active",
        "session_stats": session_stats
    })
    
    # Send a test packet to verify connection
    test_packet = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "size": 0,
        "protocol": "TEST",
        "predicted_label": "BENIGN",
        "is_threat": False,
        "threat_type": None,
        "src": "",
        "dst": "",
        "protocol_detail": "Test connection",
        "session_stats": session_stats.copy()
    }
    await websocket.send_json(test_packet)

    try:
        # Keep the WebSocket connection alive and handle incoming messages
        while True:
            try:
                # Wait for any message from client (ping/pong or disconnect)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # No message received, continue
                pass
            except WebSocketDisconnect:
                print("Threat detection WebSocket disconnected")
                break
            
            # Small delay to prevent high CPU usage
            await asyncio.sleep(0.1)
            
    except WebSocketDisconnect:
        print("Threat detection WebSocket disconnected")
    except Exception as e:
        print(f"Error in threat detection WebSocket: {e}")
        await websocket.send_json({"error": f"WebSocket error: {str(e)}"})
    finally:
        stop_event.set()
        print("Threat detection stopped") 