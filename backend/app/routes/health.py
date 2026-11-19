"""
Health Check and System Readiness Endpoint
"""

from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sentinel.backend.app.database import check_db_connection
from sentinel.backend.app.config import get_settings

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get(
    "/health",
    summary="Application Health & Readiness Check",
    description="Verifies API responsiveness and database connectivity.",
    responses={
        200: {"description": "System operational and database connected"},
        503: {"description": "Database connectivity failure"}
    }
)
def get_health():
    """Perform health and readiness probe."""
    db_status = check_db_connection()
    is_db_up = db_status.get("status") == "connected"
    
    payload = {
        "status": "healthy" if is_db_up else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    status_code = status.HTTP_200_OK if is_db_up else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=status_code, content=payload)
