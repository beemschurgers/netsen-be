from fastapi import APIRouter, HTTPException
from services.ml_model_service import ml_service
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter()

class ModelStatus(BaseModel):
    is_loaded: bool
    status: str
    message: str

class ThreatStats(BaseModel):
    total_packets: int
    threats_detected: int
    benign_packets: int
    threat_types: Dict[str, int]

@router.get("/api/model/status", response_model=ModelStatus)
async def get_model_status():
    """Get the current status of the ML model"""
    try:
        if not ml_service.is_initialized:
            # Try to load the model
            success = ml_service.load_model()
            if success:
                return ModelStatus(
                    is_loaded=True,
                    status="loaded",
                    message="ML model loaded successfully"
                )
            else:
                return ModelStatus(
                    is_loaded=False,
                    status="error",
                    message="Failed to load ML model. Check if model files exist."
                )
        else:
            return ModelStatus(
                is_loaded=True,
                status="ready",
                message="ML model is ready for threat detection"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking model status: {str(e)}")

@router.post("/api/model/reload")
async def reload_model():
    """Reload the ML model"""
    try:
        success = ml_service.load_model()
        if success:
            return {"message": "Model reloaded successfully", "status": "success"}
        else:
            raise HTTPException(status_code=500, detail="Failed to reload model")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reloading model: {str(e)}")

@router.get("/api/model/stats")
async def get_model_stats():
    """Get current model statistics"""
    try:
        stats = {
            "total_packets": ml_service.packet_stats.get('total_packets', 0),
            "total_size": ml_service.packet_stats.get('total_size', 0),
            "min_size": ml_service.packet_stats.get('min_size', 0),
            "max_size": ml_service.packet_stats.get('max_size', 0),
            "is_initialized": ml_service.is_initialized
        }
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting model stats: {str(e)}")