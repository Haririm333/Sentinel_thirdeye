"""
Tests for Incident Management API, Deduplication, Status Transitions, and Summaries
"""

import uuid
from unittest.mock import patch
from fastapi import status
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.security_audit import SecurityAuditEvent
from sentinel.backend.app.detection.base_rule import BaseDetectionRule


def test_incident_deduplication_and_correlation(client, db_session, sample_valid_event):
    """
    Submitting multiple events triggering the same rule within the correlation window
    must correlate into one incident with merged evidence rather than generating duplicate incidents.
    """
    service_id = "srv-tallybridge-audit-ro"

    # Event 1: Read-only service attempting write
    ev1 = sample_valid_event.copy()
    id1 = str(uuid.uuid4())
    ev1["event_id"] = id1
    ev1["service_identity"] = service_id
    ev1["source_ip"] = "10.0.2.10"
    ev1["endpoint"] = "/api/v1/vendors"
    ev1["http_method"] = "POST"

    res1 = client.post("/api/v1/events", json=ev1)
    assert res1.status_code == status.HTTP_201_CREATED

    # Initial incident count
    incidents_after_ev1 = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-PRIV-001",
        Incident.service_identity == service_id
    ).all()
    assert len(incidents_after_ev1) == 1
    inc1 = incidents_after_ev1[0]
    assert inc1.evidence["occurrence_count"] == 1
    assert id1 in inc1.related_event_ids

    # Event 2: Same rule & service within correlation window
    ev2 = sample_valid_event.copy()
    id2 = str(uuid.uuid4())
    ev2["event_id"] = id2
    ev2["service_identity"] = service_id
    ev2["source_ip"] = "10.0.2.10"
    ev2["endpoint"] = "/api/v1/vendors"
    ev2["http_method"] = "DELETE"  # Another write attempt

    res2 = client.post("/api/v1/events", json=ev2)
    assert res2.status_code == status.HTTP_201_CREATED

    # Verify incident was correlated and updated, NOT duplicated
    incidents_after_ev2 = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-PRIV-001",
        Incident.service_identity == service_id
    ).all()
    assert len(incidents_after_ev2) == 1, "Incident was duplicated instead of correlated!"
    inc_merged = incidents_after_ev2[0]
    assert inc_merged.incident_id == inc1.incident_id
    assert inc_merged.evidence["occurrence_count"] == 2
    assert id1 in inc_merged.related_event_ids
    assert id2 in inc_merged.related_event_ids


def test_list_incidents_api_and_filters(client, db_session, sample_valid_event):
    """Verify GET /api/v1/incidents pagination and multi-field filtering."""
    # Generate an incident via unapproved bank modification
    bank_event = sample_valid_event.copy()
    bank_event["event_id"] = str(uuid.uuid4())
    bank_event["service_identity"] = "srv-ledgerone-core"
    bank_event["source_ip"] = "10.0.1.15"
    bank_event["endpoint"] = "/api/v1/vendors/vnd_10482/bank-account"
    bank_event["http_method"] = "PATCH"
    bank_event["action"] = "MODIFY_VENDOR_BANK_ACCOUNT"
    bank_event["approval_reference"] = None

    client.post("/api/v1/events", json=bank_event)

    # 1. Query all incidents
    res = client.get("/api/v1/incidents?limit=10")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1

    # 2. Filter by severity
    res_crit = client.get("/api/v1/incidents?severity=CRITICAL")
    assert res_crit.status_code == status.HTTP_200_OK
    for item in res_crit.json()["items"]:
        assert item["severity"] == "CRITICAL"

    # 3. Filter by status
    res_open = client.get("/api/v1/incidents?status=OPEN")
    assert res_open.status_code == status.HTTP_200_OK
    for item in res_open.json()["items"]:
        assert item["status"] == "OPEN"


def test_get_incident_by_id(client, db_session, sample_valid_event):
    """Verify GET /api/v1/incidents/{incident_id}."""
    # Trigger an incident
    ev = sample_valid_event.copy()
    ev["event_id"] = str(uuid.uuid4())
    ev["service_identity"] = "srv-ledgerone-core"
    ev["source_ip"] = "198.51.100.99"  # Unexpected IP
    client.post("/api/v1/events", json=ev)

    incident = db_session.query(Incident).filter_by(service_identity="srv-ledgerone-core").first()
    assert incident is not None

    res = client.get(f"/api/v1/incidents/{incident.incident_id}")
    assert res.status_code == status.HTTP_200_OK
    retrieved = res.json()
    assert retrieved["incident_id"] == incident.incident_id
    assert retrieved["rule_id"] == incident.rule_id
    assert "scoring_breakdown" in retrieved["evidence"]


def test_get_nonexistent_incident_returns_404(client):
    """Verify 404 for unknown incident."""
    random_id = str(uuid.uuid4())
    res = client.get(f"/api/v1/incidents/{random_id}")
    assert res.status_code == status.HTTP_404_NOT_FOUND


def test_patch_incident_status_transitions(client, db_session, sample_valid_event):
    """Verify allowed and disallowed lifecycle transitions."""
    # Create incident
    ev = sample_valid_event.copy()
    ev["event_id"] = str(uuid.uuid4())
    ev["service_identity"] = "srv-ledgerone-core"
    ev["source_ip"] = "198.51.100.77"
    client.post("/api/v1/events", json=ev)

    incident = db_session.query(Incident).filter_by(service_identity="srv-ledgerone-core").first()
    assert incident is not None

    # 1. Valid: OPEN -> INVESTIGATING
    res1 = client.patch(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "INVESTIGATING", "notes": "SOC analyst triaging"}
    )
    assert res1.status_code == status.HTTP_200_OK
    assert res1.json()["status"] == "INVESTIGATING"

    # 2. Valid: INVESTIGATING -> RESOLVED
    res2 = client.patch(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "RESOLVED", "notes": "Confirmed benign network test"}
    )
    assert res2.status_code == status.HTTP_200_OK
    assert res2.json()["status"] == "RESOLVED"

    # 3. Invalid: RESOLVED -> FALSE_POSITIVE (Not permitted directly)
    res3 = client.patch(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "FALSE_POSITIVE"}
    )
    assert res3.status_code == status.HTTP_400_BAD_REQUEST
    assert "InvalidStatusTransitionError" in res3.json()["detail"]["error"]

    # 4. PUT also supported on /status endpoint for idempotent updates
    res_put = client.put(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "INVESTIGATING", "notes": "Re-opened for deeper inspection"}
    )
    assert res_put.status_code == status.HTTP_200_OK
    assert res_put.json()["status"] == "INVESTIGATING"

    # 5. Invalid status value rejected by schema validation
    res_invalid_val = client.patch(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "INVALID_STATE"}
    )
    assert res_invalid_val.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # 6. Verify PATCH directly to /api/v1/incidents/{incident_id} returns 405 Method Not Allowed
    res_405 = client.patch(
        f"/api/v1/incidents/{incident.incident_id}",
        json={"status": "RESOLVED"}
    )
    assert res_405.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_get_detection_rules_and_summary_apis(client):
    """Verify detection rules inspection and telemetry summary endpoints."""
    # 1. Rules list
    res_rules = client.get("/api/v1/detection/rules")
    assert res_rules.status_code == status.HTTP_200_OK
    rules = res_rules.json()
    assert len(rules) == 6
    rule_ids = {r["rule_id"] for r in rules}
    assert "SEC-RULE-RATE-001" in rule_ids
    assert "SEC-RULE-BULK-001" in rule_ids
    assert "SEC-RULE-IP-001" in rule_ids
    assert "SEC-RULE-PRIV-001" in rule_ids
    assert "SEC-RULE-BANK-001" in rule_ids
    assert "SEC-RULE-APPR-001" in rule_ids

    # 2. Summary
    res_sum = client.get("/api/v1/detection/summary")
    assert res_sum.status_code == status.HTTP_200_OK
    summary = res_sum.json()
    assert "total_incidents" in summary
    assert "by_status" in summary
    assert "by_severity" in summary
    assert "by_rule" in summary
    assert "top_services" in summary


def test_detection_engine_failure_resilience(client, db_session, sample_valid_event):
    """
    If a detection rule crashes unexpectedly, the event must still be safely persisted
    and an audit record generated without returning a 500 server crash.
    """
    class CrashingRule(BaseDetectionRule):
        def __init__(self):
            super().__init__("RULE-CRASH", "Crash Rule", "Always crashes")
        def evaluate(self, event, db):
            raise RuntimeError("Simulated internal rule failure")

    from sentinel.backend.app.detection.rule_registry import rule_registry
    crashing_rule = CrashingRule()
    rule_registry.register_rule(crashing_rule)

    try:
        ev = sample_valid_event.copy()
        ev_id = str(uuid.uuid4())
        ev["event_id"] = ev_id

        # Ingestion must succeed (201) despite rule crash
        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

        # Audit log must record the failure
        audit = db_session.query(SecurityAuditEvent).filter_by(
            event_type="DETECTION_RULE_ERROR",
            event_id_referenced=ev_id
        ).first()
        assert audit is not None
        assert audit.severity == "HIGH"
        assert "Simulated internal rule failure" in audit.error_message
    finally:
        # Clean up crashing rule from registry
        if "RULE-CRASH" in rule_registry._rules:
            del rule_registry._rules["RULE-CRASH"]
