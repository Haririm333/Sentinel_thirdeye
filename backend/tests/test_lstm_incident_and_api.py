"""
Integration and API Tests for LSTM Sequential Anomaly Detection Subsystem
Tests:
- ML-ANOMALY-LSTM-001 incident generation and structured evidence verification
- Incident deduplication within correlation window
- Fault isolation: LSTM failure does not block API event persistence
- REST API:
  - GET /api/v1/ml/lstm/status
  - POST /api/v1/ml/lstm/train
  - GET /api/v1/ml/lstm/models
  - GET /api/v1/ml/lstm/evaluation
  - GET /api/v1/ml/lstm/anomalies
"""

import uuid
from datetime import datetime, timezone, timedelta
from fastapi import status
from sqlalchemy import select

from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.ml.lstm.config import lstm_settings
from sentinel.backend.app.ml.lstm.baseline_manager import lstm_baseline_manager


def test_lstm_anomaly_generates_incident_with_evidence(client, db_session, sample_valid_event):
    """
    Submitting a sequence of 20 anomalous events triggers an ML-ANOMALY-LSTM-001
    incident with structured evidence and top feature reconstruction errors.
    """
    service_id = "srv-ledgerone-core"
    lstm_baseline_manager.train_service_baseline(service_id, version="1.0.0")

    base_time = datetime(2026, 11, 20, 3, 30, 0, tzinfo=timezone.utc)
    
    # Submit 20 anomalous events (off-hours bulk exfiltration pattern)
    for i in range(20):
        ev = sample_valid_event.copy()
        ev["event_id"] = str(uuid.uuid4())
        ev["service_identity"] = service_id
        ev["timestamp"] = (base_time + timedelta(seconds=i * 2)).isoformat()
        ev["source_ip"] = "198.51.100.88"
        ev["endpoint"] = "/api/v1/vendors/export/dump"
        ev["action"] = "EXPORT_DATABASE_BATCH"
        ev["request_size_bytes"] = 3500
        ev["response_size_bytes"] = 25_000_000

        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    # Query incidents for ML-ANOMALY-LSTM-001
    stmt = select(Incident).where(
        Incident.rule_id == "ML-ANOMALY-LSTM-001",
        Incident.service_identity == service_id
    )
    incidents = db_session.execute(stmt).scalars().all()
    assert len(incidents) >= 1, "Expected ML-ANOMALY-LSTM-001 incident to be generated."

    target_incident = incidents[0]
    assert target_incident.rule_id == "ML-ANOMALY-LSTM-001"
    assert target_incident.rule_name == "LSTM Sequential Behavioural Anomaly"
    assert target_incident.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert target_incident.status == "OPEN"

    evidence = target_incident.evidence
    assert "model_id" in evidence
    assert "reconstruction_error" in evidence
    assert "calibrated_threshold" in evidence
    assert "top_deviations" in evidence
    assert len(evidence["top_deviations"]) > 0


def test_lstm_incident_deduplication(client, db_session, sample_valid_event):
    """
    Continuous sequential anomalies from the same service within the correlation
    window must update the existing incident rather than duplicating open incidents.
    """
    service_id = "srv-helpdeskr-agent"
    lstm_baseline_manager.train_service_baseline(service_id, version="1.0.0")

    base_time = datetime(2026, 11, 20, 3, 45, 0, tzinfo=timezone.utc)
    for i in range(22):
        ev = sample_valid_event.copy()
        ev["event_id"] = str(uuid.uuid4())
        ev["service_identity"] = service_id
        ev["timestamp"] = (base_time + timedelta(seconds=i * 2)).isoformat()
        ev["endpoint"] = "/api/v1/internal/admin/privileges"
        ev["action"] = "ESCALATE_ROLE_PERMISSIONS"
        ev["http_method"] = "DELETE"
        ev["response_size_bytes"] = 12_000_000

        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    stmt = select(Incident).where(
        Incident.rule_id == "ML-ANOMALY-LSTM-001",
        Incident.service_identity == service_id
    )
    incidents = db_session.execute(stmt).scalars().all()
    assert len(incidents) == 1, f"Expected exactly 1 correlated incident, got {len(incidents)}"


def test_lstm_failure_does_not_block_event_persistence(client, db_session, sample_valid_event, monkeypatch):
    """
    Simulated runtime error inside the LSTM detector must not prevent the
    API event from being committed to the database (fault isolation).
    """
    from sentinel.backend.app.ml.lstm.detector import lstm_detector

    def mock_fail(*args, **kwargs):
        raise RuntimeError("Simulated PyTorch GPU/CPU memory allocator fault")

    monkeypatch.setattr(lstm_detector, "evaluate_and_record_incident", mock_fail)

    ev = sample_valid_event.copy()
    ev_id = str(uuid.uuid4())
    ev["event_id"] = ev_id
    ev["service_identity"] = "srv-ledgerone-core"

    res = client.post("/api/v1/events", json=ev)
    assert res.status_code == status.HTTP_201_CREATED

    stmt = select(ApiEvent).where(ApiEvent.event_id == ev_id)
    persisted = db_session.execute(stmt).scalar_one_or_none()
    assert persisted is not None
    assert persisted.event_id == ev_id


def test_get_lstm_status_endpoint(client):
    """GET /api/v1/ml/lstm/status must return operational status, device, and baselines."""
    res = client.get("/api/v1/ml/lstm/status")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "operational"
    assert data["device"] == "cpu"
    assert "service_baselines" in data


def test_post_lstm_train_endpoint(client):
    """POST /api/v1/ml/lstm/train must train LSTM baseline and return metadata."""
    payload = {
        "service_identity": "srv-ledgerone-paygate",
        "epochs": 10,
        "batch_size": 16,
        "version": "1.0.0"
    }
    res = client.post("/api/v1/ml/lstm/train", json=payload)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "success"
    assert "LSTM Autoencoder baseline successfully trained" in data["message"]
    meta = data["model_metadata"]
    assert meta["service_identity"] == "srv-ledgerone-paygate"
    assert "calibrated_threshold" in meta


def test_post_lstm_train_validation_error(client):
    """POST /api/v1/ml/lstm/train with invalid parameters must return 422."""
    payload = {
        "service_identity": "srv-ledgerone-core",
        "epochs": 2  # Below ge=5
    }
    res = client.post("/api/v1/ml/lstm/train", json=payload)
    assert res.status_code == 422


def test_get_lstm_models_endpoint(client):
    """GET /api/v1/ml/lstm/models must list serialized PyTorch LSTM models."""
    res = client.get("/api/v1/ml/lstm/models")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert "count" in data
    assert "models" in data
    assert data["count"] >= 1


def test_get_lstm_evaluation_endpoint(client):
    """GET /api/v1/ml/lstm/evaluation must return metrics and Isolation Forest comparison."""
    res = client.get("/api/v1/ml/lstm/evaluation?service_identity=srv-ledgerone-core")
    assert res.status_code == status.HTTP_200_OK
    report = res.json()

    assert report["service_identity"] == "srv-ledgerone-core"
    assert "metrics" in report
    metrics = report["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "false_positive_rate" in metrics

    assert "confusion_matrix" in report
    assert "scenario_detection_rates" in report
    assert "performance_profile" in report
    assert report["performance_profile"]["device"] == "cpu"
    assert "model_comparison" in report
    assert "lstm_autoencoder" in report["model_comparison"]
    assert "isolation_forest" in report["model_comparison"]


def test_get_lstm_anomalies_endpoint(client):
    """GET /api/v1/ml/lstm/anomalies must return paginated ML-ANOMALY-LSTM-001 incidents."""
    res = client.get("/api/v1/ml/lstm/anomalies?page=1&limit=10")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert "total" in data
    assert "items" in data
