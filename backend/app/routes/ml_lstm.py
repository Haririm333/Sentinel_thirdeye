"""
LSTM Sequential Anomaly Detection REST API Endpoints
Endpoints:
- GET /api/v1/ml/lstm/status: Inspect LSTM readiness and service baselines
- POST /api/v1/ml/lstm/train: Explicit model training on sequential baseline
- GET /api/v1/ml/lstm/models: List serialized PyTorch models and manifests
- GET /api/v1/ml/lstm/evaluation: Retrieve benchmark evaluation metrics and comparison
- GET /api/v1/ml/lstm/anomalies: Query ML-ANOMALY-LSTM-001 incidents

SECURITY NOTICE: In Phase 4 development, ML administrative operations are restricted
to localhost invocation. Production deployment requires RBAC and administrator authentication.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel.backend.app.database import get_db
from sentinel.backend.app.ml.lstm.baseline_manager import lstm_baseline_manager
from sentinel.backend.app.ml.lstm.model_store import lstm_model_store
from sentinel.backend.app.ml.lstm.evaluator import evaluate_lstm_model
from sentinel.backend.app.models.incident import Incident

router = APIRouter(prefix="/api/v1/ml/lstm", tags=["LSTM Sequential Anomaly Detection"])


class TrainLSTMModelRequest(BaseModel):
    """Payload for explicit LSTM Autoencoder baseline training."""
    service_identity: str = Field(..., min_length=2, max_length=100, examples=["srv-ledgerone-core"])
    version: str = Field(default="1.0.0", max_length=20)
    epochs: Optional[int] = Field(default=25, ge=5, le=100)
    batch_size: Optional[int] = Field(default=16, ge=1, le=128)
    learning_rate: Optional[float] = Field(default=0.005, ge=0.0001, le=0.1)


@router.get(
    "/status",
    summary="LSTM Subsystem Status & Baselines",
    description="Inspect sequential baseline readiness for each monitored service."
)
def get_lstm_status():
    """Return LSTM model status overview across services."""
    return {
        "status": "operational",
        "subsystem": "LSTM Autoencoder Sequential Anomaly Detector",
        "device": "cpu",
        "feature_schema_version": "1.0.0",
        "service_baselines": lstm_baseline_manager.get_status_overview()
    }


@router.post(
    "/train",
    status_code=status.HTTP_200_OK,
    summary="Explicitly train LSTM Autoencoder baseline",
    description="Trigger an explicit training job for an LSTM service baseline on CPU."
)
def train_lstm_model(request: TrainLSTMModelRequest):
    """Trigger explicit LSTM model training for a service."""
    try:
        meta = lstm_baseline_manager.train_service_baseline(
            service_identity=request.service_identity,
            version=request.version,
            epochs=request.epochs,
            batch_size=request.batch_size,
            learning_rate=request.learning_rate
        )
        return {
            "status": "success",
            "message": f"LSTM Autoencoder baseline successfully trained for '{request.service_identity}'",
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
    summary="List serialized LSTM models in store",
    description="Retrieve manifests of all saved PyTorch LSTM models."
)
def list_lstm_models():
    """List serialized LSTM models and their calibration metadata."""
    models = lstm_model_store.list_saved_models()
    return {
        "count": len(models),
        "models": models
    }


@router.get(
    "/evaluation",
    summary="LSTM Model Evaluation and Isolation Forest Comparison",
    description="Run sequential benchmark testing and compare metrics against Phase 3 Isolation Forest."
)
def get_lstm_evaluation(
    service_identity: str = Query("srv-ledgerone-core", description="Target service to evaluate")
):
    """Generate statistical sequential evaluation report."""
    try:
        report = evaluate_lstm_model(service_identity=service_identity)
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "EvaluationFailure", "message": str(exc)}
        )


@router.get(
    "/anomalies",
    summary="List LSTM-detected sequential anomalies",
    description="Query incidents generated specifically by the LSTM Autoencoder detector."
)
def list_lstm_anomalies(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieve paginated sequential anomaly incidents."""
    query = (
        db.query(Incident)
        .filter(Incident.rule_id == "ML-ANOMALY-LSTM-001")
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
