"""
Machine Learning API Endpoints for SENTINEL
Endpoints:
- GET /api/v1/ml/status: Subsystem operational status and service baselines
- POST /api/v1/ml/train: Explicit model training on baseline dataset
- GET /api/v1/ml/models: List serialized model artifacts and metadata
- GET /api/v1/ml/evaluation: Retrieve statistical evaluation benchmark report
- GET /api/v1/ml/anomalies: Query ML-detected behavioural anomaly incidents

SECURITY NOTICE: In Phase 3 development, ML administrative operations are restricted
to localhost invocation. Production deployment requires RBAC and administrator authentication.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel.backend.app.database import get_db
from sentinel.backend.app.ml.baseline_manager import baseline_manager
from sentinel.backend.app.ml.model_store import model_store
from sentinel.backend.app.ml.evaluator import evaluate_service_model
from sentinel.backend.app.models.incident import Incident

router = APIRouter(prefix="/api/v1/ml", tags=["Machine Learning Anomaly Detection"])


class TrainModelRequest(BaseModel):
    """Payload for explicit model baseline training."""
    service_identity: str = Field(..., min_length=2, max_length=100, examples=["srv-ledgerone-core"])
    num_samples: int = Field(default=60, ge=20, le=5000, description="Number of baseline training samples.")
    version: str = Field(default="1.0.0", max_length=20)
    contamination: Optional[float] = Field(default=0.05, ge=0.001, le=0.2)


@router.get(
    "/status",
    summary="ML Subsystem Readiness & Baselines",
    description="Inspect behavioural baseline readiness for each monitored service."
)
def get_ml_status():
    """Return model status overview across services."""
    return {
        "status": "operational",
        "feature_schema_version": "1.0.0",
        "service_baselines": baseline_manager.get_status_overview()
    }


@router.post(
    "/train",
    status_code=status.HTTP_200_OK,
    summary="Explicitly train Isolation Forest baseline model",
    description="Trigger an explicit training job for a service baseline. Requires minimum sample threshold."
)
def train_model(request: TrainModelRequest):
    """Trigger explicit model training for a service."""
    try:
        meta = baseline_manager.train_service_baseline(
            service_identity=request.service_identity,
            version=request.version,
            contamination=request.contamination
        )
        return {
            "status": "success",
            "message": f"Isolation Forest baseline successfully trained for '{request.service_identity}'",
            "model_metadata": meta
        }
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "InsufficientDataError", "message": str(ve)}
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "TrainingFailure", "message": str(exc)}
        )


@router.get(
    "/models",
    summary="List serialized models in model store",
    description="Retrieve manifests of all saved Isolation Forest models."
)
def list_models():
    """List serialized models and their calibration metadata."""
    return {
        "count": len(model_store.list_saved_models()),
        "models": model_store.list_saved_models()
    }


@router.get(
    "/evaluation",
    summary="Model evaluation benchmark report",
    description="Run time-aware benchmark testing and return Precision, Recall, F1, FPR, and scenario detection rates."
)
def get_model_evaluation(
    service_identity: str = Query("srv-ledgerone-core", description="Target service to evaluate")
):
    """Generate statistical evaluation report."""
    try:
        report = evaluate_service_model(service_identity=service_identity)
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "EvaluationFailure", "message": str(exc)}
        )


@router.get(
    "/anomalies",
    summary="List ML-detected behavioural anomalies",
    description="Query incidents generated specifically by the Isolation Forest detector."
)
def list_ml_anomalies(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieve paginated behavioural anomaly incidents."""
    query = (
        db.query(Incident)
        .filter(Incident.rule_id == "ML-ANOMALY-ISOFOR-001")
        .order_by(Incident.created_at.desc())
    )
    total = query.count()
    items = query.offset((page - 1) * limit).limit(limit).all()
    pages = (total + limit - 1) // limit if total > 0 else 0

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages,
        "items": items
    }
