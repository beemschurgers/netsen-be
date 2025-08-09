import threading
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from services.ml_model_service import ml_service
from datetime import datetime
import time


async def threat_detection_websocket(websocket: WebSocket):
    """WebSocket endpoint streaming per-flow batch results from MLModelService to the frontend."""
    await websocket.accept()

    # Ensure models are loaded
    if not ml_service.is_initialized:
        success = ml_service.load_model()
        if not success:
            error_msg = "Failed to load ML model. Please check if model files exist."
            print(error_msg)
            await websocket.send_json({"error": error_msg})
            return
        else:
            pass

    # Start capture if not already running (start_capture manages its own batch thread)
    if not ml_service.running:
        try:
            capture_thread = threading.Thread(target=ml_service.start_capture)
            capture_thread.daemon = True
            capture_thread.start()
        except Exception as e:
            error_msg = f"Failed to start packet capture: {str(e)}"
            print(error_msg)
            await websocket.send_json({"error": error_msg})
            return

    stop_event = threading.Event()
    loop = asyncio.get_running_loop()

    # Per-connection session statistics
    session_stats = {
        "total_packets": 0,
        "threats_detected": 0,
        "benign_packets": 0,
        "threat_types": {},
        "stage1_predictions": 0,
        "stage2_predictions": 0,
    }

    def monitor_ml_service(loop_ref: asyncio.AbstractEventLoop) -> None:
        """Monitor ml_service.recent_results and forward new items to the client."""
        def send(payload):
            asyncio.run_coroutine_threadsafe(websocket.send_json(payload), loop_ref)

        last_packet_count = ml_service.packet_count
        last_result_count = len(ml_service.recent_results) if hasattr(ml_service, "recent_results") else 0

        while not stop_event.is_set():
            try:
                current_packet_count = ml_service.packet_count
                current_result_count = len(ml_service.recent_results) if hasattr(ml_service, "recent_results") else 0

                # Packet count delta
                if current_packet_count > last_packet_count:
                    session_stats["total_packets"] += (current_packet_count - last_packet_count)
                    last_packet_count = current_packet_count

                # New results
                if current_result_count > last_result_count and hasattr(ml_service, "get_recent_results"):
                    try:
                        delta = current_result_count - last_result_count
                        new_results = ml_service.get_recent_results(delta)
                    except Exception as e:
                        print(f"Error getting recent results: {e}")
                        new_results = []

                    for result in new_results:
                        if result.get("is_threat"):
                            session_stats["threats_detected"] += 1
                            session_stats["stage1_predictions"] += 1
                            threat_type = result.get("threat_type")
                            if threat_type:
                                session_stats["threat_types"][threat_type] = session_stats["threat_types"].get(threat_type, 0) + 1
                            if result.get("main_dataframe"):
                                session_stats["stage2_predictions"] += 1
                                print(f"🔍 STAGE 2 - CLASSIFICATION: {threat_type} -> {result.get('predicted_label')}")
                        else:
                            session_stats["benign_packets"] += 1
                            session_stats["stage1_predictions"] += 1
                            print("✅ STAGE 1 - BENIGN DETECTED")

                        enhanced_result = {
                            "timestamp": result.get("timestamp"),
                            "flow_key": result.get("flow_key"),
                            "packet_count": result.get("packet_count"),
                            "total_bytes": result.get("total_bytes"),
                            "predicted_label": result.get("predicted_label"),
                            "is_threat": result.get("is_threat"),
                            "threat_type": result.get("threat_type"),
                            # Frontend-compatible fields
                            "size": result.get("total_bytes", 0),
                            "protocol": "TCP/UDP" if result.get("is_threat") else "BENIGN",
                            "src": "Unknown",
                            "dst": "Unknown",
                            "protocol_detail": (
                                f"Threat: {result.get('threat_type')}" if result.get("is_threat") else "Benign traffic"
                            ),
                            "stage1_result": {
                                "threat_detected": result.get("is_threat"),
                                "threat_dataframe": result.get("threat_dataframe"),
                            },
                            "stage2_result": {
                                "classification_performed": result.get("is_threat"),
                                "main_dataframe": result.get("main_dataframe"),
                                "final_label": result.get("predicted_label"),
                            },
                            "session_stats": session_stats.copy(),
                            "processing_stages": {
                                "stage1_completed": True,
                                "stage2_completed": result.get("is_threat", False),
                                "total_stages": 2 if result.get("is_threat") else 1,
                            },
                        }

                        send(enhanced_result)

                    last_result_count = current_result_count

                # Periodic status (every ~5s)
                if int(time.time()) % 5 == 0:
                    status_update = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "packet_count": current_packet_count,
                        "session_stats": session_stats.copy(),
                        "status": "monitoring",
                        "two_stage_info": {
                            "stage1_model": "Threat Detection Model",
                            "stage2_model": "Main Classification Model",
                            "stage1_predictions": session_stats["stage1_predictions"],
                            "stage2_predictions": session_stats["stage2_predictions"],
                        },
                    }
                    send(status_update)

                time.sleep(1)

            except Exception as e:
                print(f"Error in monitor_ml_service: {e}")
                time.sleep(1)

    # Start monitor thread
    monitor_thread = threading.Thread(target=monitor_ml_service, args=(loop,))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Initial status
    await websocket.send_json(
        {
            "status": "Connected - Two-stage threat detection active",
            "model_loaded": ml_service.is_initialized,
            "message": "Real-time ML-based threat detection with two-stage approach is now active",
            "session_stats": session_stats,
            "batch_size": ml_service.batch_size,
            "two_stage_approach": {
                "stage1": {
                    "name": "Threat Detection Model",
                    "purpose": "Binary classification (Threat vs Benign)",
                    "features": len(ml_service.threat_detection_columns),
                    "model_type": "Threat Detection",
                },
                "stage2": {
                    "name": "Main Classification Model",
                    "purpose": "Detailed threat classification (only if threat detected)",
                    "features": len(ml_service.columns),
                    "model_type": "Main Classification",
                },
            },
        }
    )

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                break

            await asyncio.sleep(0.1)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"Error in threat detection WebSocket: {e}")
        await websocket.send_json({"error": f"WebSocket error: {str(e)}"})
    finally:
        stop_event.set()
        print("Threat detection stopped")


