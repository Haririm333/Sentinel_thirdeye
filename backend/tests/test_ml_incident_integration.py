"""
Integration Tests for ML Anomaly Detector and SENTINEL Incident Engine
Verifies that behavioral anomalies create ML-ANOMALY-ISOFOR-001 incidents,
evidence manifests contain full audit telemetry, continuous anomalies are correlated/deduplicated,
and ML subsystem errors do not interrupt core event persistence.
"""

import uuid
from datetime import datetime, timezone, timedelta
from fastapi import status
from sqlalchemy import select

from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.ml.config import ml_settings
from sentinel.backend.app.ml.baseline_manager import baseline_manager


def test_ml_anomaly_generates_incident_with_evidence(client, db_session, sample_valid_event):
    """
    Submitting an anomalous burst of events (off-hours, huge payload, unauthorized IP)
    triggers ML-ANOMALY-ISOFOR-001 incident with detailed evidence.
    """
    service_id = "srv-ledgerone-core"
    
    # Ensure baseline model is loaded
    baseline_manager.train_service_baseline(service_id, version="1.0.0")

    # Generate 4 events in the window that exhibit extreme anomalous characteristics
    # (Deep night 03:30 AM, huge responses, non-standard IP)
    event_ids = []
    base_time = datetime(2026, 11, 20, 3, 30, 0, tzinfo=timezone.utc)
    
    for i in range(4):
        ev = sample_valid_event.copy()
        ev_id = str(uuid.uuid4())
        event_ids.append(ev_id)
        ev["event_id"] = ev_id
        ev["service_identity"] = service_id
        ev["timestamp"] = (base_time + timedelta(seconds=i * 20)).isoformat()
        ev["source_ip"] = "198.51.100.77"  # External unseen IP
        ev["endpoint"] = "/api/v1/vendors/export/full"
        ev["action"] = "EXPORT_ALL_VENDORS"
        ev["resource_type"] = "VENDOR"
        ev["resource_id"] = f"vnd_bulk_{i}"
        ev["request_size_bytes"] = 3500
        ev["response_size_bytes"] = 25_000_000  # 25 MB payload dump
        
        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    # Query incidents for ML anomaly
    stmt = select(Incident).where(
        Incident.rule_id == "ML-ANOMALY-ISOFOR-001",
        Incident.service_identity == service_id
    )
    incidents = db_session.execute(stmt).scalars().all()
    assert len(incidents) >= 1, "Expected ML-ANOMALY-ISOFOR-001 incident to be generated."

    target_incident = incidents[0]
    assert target_incident.rule_id == "ML-ANOMALY-ISOFOR-001"
    assert target_incident.rule_name == "Isolation Forest Behavioural Anomaly"
    assert target_incident.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert target_incident.risk_score >= 55
    assert target_incident.status == "OPEN"

    # Verify structured evidence
    evidence = target_incident.evidence
    assert "model_id" in evidence
    assert "anomaly_score" in evidence
    assert evidence["anomaly_score"] >= ml_settings.ANOMALY_THRESHOLD
    assert "top_deviations" in evidence
    assert len(evidence["top_deviations"]) > 0
    assert "feature_values" in evidence


def test_ml_incident_deduplication_within_correlation_window(client, db_session, sample_valid_event):
    """
    Subsequent anomalous events from the same service within the correlation window
    must update the existing incident rather than creating duplicate open incidents.
    """
    service_id = "srv-helpdeskr-agent"
    baseline_manager.train_service_baseline(service_id, version="1.0.0")

    base_time = datetime(2026, 11, 20, 3, 40, 0, tzinfo=timezone.utc)
    
    # Send 6 consecutive anomalous events
    for i in range(6):
        ev = sample_valid_event.copy()
        ev["event_id"] = str(uuid.uuid4())
        ev["service_identity"] = service_id
        ev["timestamp"] = (base_time + timedelta(seconds=i * 15)).isoformat()
        ev["source_ip"] = "203.0.113.99"
        ev["endpoint"] = "/api/v1/internal/debug/dump"
        ev["action"] = "DUMP_INTERNAL_STATE"
        ev["http_method"] = "DELETE"
        ev["response_size_bytes"] = 8_000_000

        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    # Verify that only 1 ML incident exists for this service in this window
    stmt = select(Incident).where(
        Incident.rule_id == "ML-ANOMALY-ISOFOR-001",
        Incident.service_identity == service_id
    )
    incidents = db_session.execute(stmt).scalars().all()
    assert len(incidents) == 1, f"Expected 1 correlated incident, got {len(incidents)}"

    incident = incidents[0]
    # Related events should include multiple event IDs
    assert len(incident.related_event_ids) >= 2


def test_ml_detector_failure_does_not_block_event_persistence(client, db_session, sample_valid_event, monkeypatch):
    """
    If the ML subsystem encounters a runtime error (corrupt model, unhandled exception),
    the API event must still be safely committed and persisted to PostgreSQL (fault isolation).
    """
    # Simulate an error in the anomaly detector
    def mock_evaluate_and_record(*args, **kwargs):
        raise RuntimeError("Simulated ML model memory corruption or runtime fault")

    from sentinel.backend.app.ml.detector import anomaly_detector
    monkeypatch.setattr(anomaly_detector, "evaluate_and_record_incident", mock_evaluate_and_record)

    event_payload = sample_valid_event.copy()
    event_payload["event_id"] = str(uuid.uuid4())
    event_payload["service_identity"] = "srv-ledgerone-core"

    # Post event
    res = client.post("/api/v1/events", json=event_payload)
    assert res.status_code == status.HTTP_201_CREATED

    # Verify event is safely in database
    stmt = select(ApiEvent).where(ApiEvent.event_id == event_payload["event_id"])
    persisted_event = db_session.execute(stmt).scalar_one_or_none()
    assert persisted_event is not None
    assert persisted_event.event_id == event_payload["event_id"]
