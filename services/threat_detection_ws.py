import threading
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from services.ml_model_service import ml_service
from datetime import datetime
import time
import json
import math
import numpy as np


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

    # Per-connection session statistics (flow-based)
    session_stats = {
        "total_flows": 0,
        "threat_flows": 0,
        "benign_flows": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "threat_types": {},
    }

    def to_jsonable(value):
        """Recursively convert numpy/pandas scalars, arrays, NaN/Inf to JSON-safe Python types."""
        # Numpy scalar
        if isinstance(value, np.generic):
            return value.item()
        # Numpy array
        if isinstance(value, np.ndarray):
            return [to_jsonable(v) for v in value.tolist()]
        # Basic containers
        if isinstance(value, dict):
            return {str(k): to_jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [to_jsonable(v) for v in value]
        # Floats: sanitize NaN/Inf
        if isinstance(value, float):
            if math.isfinite(value):
                return value
            return None
        return value

    def monitor_ml_service(loop_ref: asyncio.AbstractEventLoop) -> None:
        """Monitor ml_service.recent_results and forward new items to the client."""
        def send(payload):
            # Convert aggressively to builtin types to avoid numpy serialization issues
            safe_payload = to_jsonable(payload)
            try:
                text = json.dumps(safe_payload, ensure_ascii=False, allow_nan=False)
            except Exception as enc_err:
                print(f"Encoding error, dumping simplified payload: {enc_err}")
                try:
                    text = json.dumps(jsonable_encoder(safe_payload), ensure_ascii=False)
                except Exception as enc_err2:
                    print(f"Fallback encoding also failed: {enc_err2}")
                    return
            asyncio.run_coroutine_threadsafe(websocket.send_text(text), loop_ref)

        last_result_count = len(ml_service.recent_results) if hasattr(ml_service, "recent_results") else 0

        while not stop_event.is_set():
            try:
                current_result_count = len(ml_service.recent_results) if hasattr(ml_service, "recent_results") else 0

                # New results
                if current_result_count > last_result_count and hasattr(ml_service, "get_recent_results"):
                    try:
                        delta = int(current_result_count - last_result_count)
                        new_results = ml_service.get_recent_results(delta)
                    except Exception as e:
                        print(f"Error getting recent results: {e}")
                        new_results = []

                    for result in new_results:
                        # Update flow-based session statistics
                        session_stats["total_flows"] += 1
                        session_stats["total_packets"] += int(result.get("packet_count", 0))
                        session_stats["total_bytes"] += int(result.get("total_bytes", 0))

                        if result.get("is_threat"):
                            session_stats["threat_flows"] += 1
                            threat_type = result.get("threat_type")
                            if threat_type:
                                session_stats["threat_types"][threat_type] = session_stats["threat_types"].get(threat_type, 0) + 1
                        else:
                            session_stats["benign_flows"] += 1

                        enhanced_result = {
                            "timestamp": result.get("timestamp"),
                            "flow_key": result.get("flow_key"),
                            "packet_count": result.get("packet_count"),
                            "total_bytes": result.get("total_bytes"),
                            "predicted_label": result.get("predicted_label"),
                            "is_threat": result.get("is_threat"),
                            "threat_type": result.get("threat_type")
                        }
                        send(enhanced_result)

                    last_result_count = current_result_count

                # Periodic status (every ~5s)
                if int(time.time()) % 5 == 0:
                    status_update = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "session_stats": session_stats.copy(),
                        "status": "Monitoring"
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
            "status": "Connected",
            "model_loaded": ml_service.is_initialized,
            "message": "Real-time ML-based threat detection is now active",
            "session_stats": session_stats,
            "batch_size": ml_service.batch_size,
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
        
        