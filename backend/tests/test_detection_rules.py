"""
Comprehensive Tests for All Six Deterministic Security Detection Rules
"""

import uuid
from datetime import datetime, timezone
from fastapi import status
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.api_event import ApiEvent


def test_normal_activity_generates_no_incidents(client, db_session, sample_valid_event):
    """Normal legitimate operations must not generate false alerts."""
    normal_event = sample_valid_event.copy()
    normal_event["event_id"] = str(uuid.uuid4())
    normal_event["service_identity"] = "srv-ledgerone-core"
    normal_event["endpoint"] = "/api/v1/vendors/vnd_10482"
    normal_event["http_method"] = "GET"
    normal_event["source_ip"] = "10.0.1.15"  # Sanctioned IP
    normal_event["action"] = "READ_VENDOR_RECORD"
    normal_event["response_size_bytes"] = 1500  # Normal size

    res = client.post("/api/v1/events", json=normal_event)
    assert res.status_code == status.HTTP_201_CREATED

    # Verify no incidents created for this event
    incidents = db_session.query(Incident).all()
    matching = [inc for inc in incidents if normal_event["event_id"] in (inc.related_event_ids or [])]
    assert len(matching) == 0, f"Expected 0 incidents for normal event, got: {matching}"


def test_rule_1_excessive_request_rate(client, db_session, sample_valid_event):
    """Rule 1: Exceeding request rate threshold within sliding window triggers incident."""
    service_id = "srv-tallybridge-sync"
    event_ids = []

    # Send 22 requests rapidly (threshold is 20)
    for i in range(22):
        ev = sample_valid_event.copy()
        ev_id = str(uuid.uuid4())
        event_ids.append(ev_id)
        ev["event_id"] = ev_id
        ev["service_identity"] = service_id
        ev["source_ip"] = "10.0.2.15"  # Valid IP for tallybridge
        ev["endpoint"] = "/api/v1/sync/vendors"
        ev["action"] = "SYNC_POLL"
        ev["timestamp"] = datetime.now(timezone.utc).isoformat()

        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    # Verify Rule 1 incident created
    rate_incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-RATE-001",
        Incident.service_identity == service_id
    ).first()

    assert rate_incident is not None, "Expected Excessive API Request Rate incident"
    assert rate_incident.severity in ("MEDIUM", "HIGH")
    assert rate_incident.evidence["measured_request_count"] >= 21
    assert rate_incident.evidence["threshold_count"] == 20
    assert "exceeding the security threshold of 20" in rate_incident.explanation


def test_rule_2_bulk_vendor_data_access(client, db_session, sample_valid_event):
    """Rule 2: High-volume bulk vendor download triggers incident."""
    bulk_event = sample_valid_event.copy()
    bulk_id = str(uuid.uuid4())
    bulk_event["event_id"] = bulk_id
    bulk_event["service_identity"] = "srv-tallybridge-sync"
    bulk_event["source_ip"] = "10.0.2.15"
    bulk_event["endpoint"] = "/api/v1/vendors/export"
    bulk_event["resource_type"] = "VENDOR_DATABASE"
    bulk_event["action"] = "BULK_DATA_EXPORT"
    bulk_event["response_size_bytes"] = 25_000_000  # 25 MB payload

    res = client.post("/api/v1/events", json=bulk_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-BULK-001",
        Incident.service_identity == "srv-tallybridge-sync"
    ).first()

    assert incident is not None
    assert incident.severity in ("MEDIUM", "HIGH")
    assert incident.evidence["current_event_bytes"] == 25_000_000
    assert bulk_id in incident.related_event_ids


def test_rule_3_unexpected_source_ip(client, db_session, sample_valid_event):
    """Rule 3: Activity from unsanctioned or unconfigured IP triggers incident."""
    # 1. Known service with external unapproved IP
    ip_event = sample_valid_event.copy()
    ev_id = str(uuid.uuid4())
    ip_event["event_id"] = ev_id
    ip_event["service_identity"] = "srv-ledgerone-core"  # allowed: 10.0.1.0/24, 127.0.0.1
    ip_event["source_ip"] = "198.51.100.88"  # External unauthorized IP
    ip_event["endpoint"] = "/api/v1/vendors/vnd_10482"

    res = client.post("/api/v1/events", json=ip_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-IP-001",
        Incident.service_identity == "srv-ledgerone-core"
    ).first()

    assert incident is not None
    assert incident.severity in ("HIGH", "CRITICAL")
    assert incident.evidence["source_ip"] == "198.51.100.88"
    assert ev_id in incident.related_event_ids


def test_rule_3_unconfigured_service_untrusted(client, db_session, sample_valid_event):
    """Rule 3: Unconfigured service is NOT treated as trusted."""
    rogue_event = sample_valid_event.copy()
    rogue_id = str(uuid.uuid4())
    rogue_event["event_id"] = rogue_id
    rogue_event["service_identity"] = "srv-unknown-external-tool"
    rogue_event["source_ip"] = "172.16.50.4"
    rogue_event["endpoint"] = "/api/v1/vendors"

    res = client.post("/api/v1/events", json=rogue_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-IP-001",
        Incident.service_identity == "srv-unknown-external-tool"
    ).first()

    assert incident is not None
    assert incident.evidence["is_registered_service"] is False
    assert "does not automatically trust unconfigured services" in incident.explanation


def test_rule_4_privilege_violation_read_only_mutation(client, db_session, sample_valid_event):
    """Rule 4: Read-only service attempting write operation triggers privilege violation."""
    ro_event = sample_valid_event.copy()
    ro_id = str(uuid.uuid4())
    ro_event["event_id"] = ro_id
    ro_event["service_identity"] = "srv-tallybridge-audit-ro"  # Read-only policy
    ro_event["source_ip"] = "10.0.2.20"
    ro_event["endpoint"] = "/api/v1/vendors"
    ro_event["http_method"] = "POST"  # Write attempt!
    ro_event["action"] = "CREATE_VENDOR"

    res = client.post("/api/v1/events", json=ro_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-PRIV-001",
        Incident.service_identity == "srv-tallybridge-audit-ro"
    ).first()

    assert incident is not None
    assert incident.severity in ("HIGH", "CRITICAL")
    assert ro_id in incident.related_event_ids
    assert "Unauthorized HTTP method 'POST'" in incident.explanation


def test_rule_5_sensitive_bank_account_modification(client, db_session, sample_valid_event):
    """Rule 5: Altering vendor bank account triggers critical incident with masked data."""
    bank_event = sample_valid_event.copy()
    bank_id = str(uuid.uuid4())
    bank_event["event_id"] = bank_id
    bank_event["service_identity"] = "srv-ledgerone-core"
    bank_event["source_ip"] = "10.0.1.15"
    bank_event["endpoint"] = "/api/v1/vendors/vnd_10482/bank-account"
    bank_event["http_method"] = "PATCH"
    bank_event["action"] = "MODIFY_VENDOR_BANK_ACCOUNT"
    bank_event["resource_type"] = "BANK_ACCOUNT"
    # Raw bank account number
    bank_event["resource_id"] = "ACC-987654321099"
    bank_event["approval_reference"] = "APP-2026-9812"

    res = client.post("/api/v1/events", json=bank_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-BANK-001",
        Incident.service_identity == "srv-ledgerone-core"
    ).first()

    assert incident is not None
    assert incident.severity == "CRITICAL"
    assert incident.risk_score >= 80
    assert bank_id in incident.related_event_ids
    
    # CRITICAL SECURITY CHECK: Raw bank account number must NEVER be exposed in incident!
    assert "987654321099" not in str(incident.evidence)
    assert "987654321099" not in incident.explanation
    assert "1099" in incident.resource_id  # Only masked last 4 digits present


def test_rule_6_missing_approval_reference(client, db_session, sample_valid_event):
    """Rule 6: Sensitive profile update lacking valid approval ticket triggers incident."""
    unapproved_event = sample_valid_event.copy()
    ev_id = str(uuid.uuid4())
    unapproved_event["event_id"] = ev_id
    unapproved_event["service_identity"] = "srv-helpdeskr-agent"
    unapproved_event["source_ip"] = "10.0.3.15"
    unapproved_event["endpoint"] = "/api/v1/vendors/vnd_10482/profile"
    unapproved_event["http_method"] = "PUT"
    unapproved_event["action"] = "UPDATE_VENDOR_PROFILE"
    # Malformed override assert instead of valid APP-xxxx-xxxx ticket
    unapproved_event["approval_reference"] = "EMERGENCY_OVERRIDE_NO_TICKET"

    res = client.post("/api/v1/events", json=unapproved_event)
    assert res.status_code == status.HTTP_201_CREATED

    incident = db_session.query(Incident).filter(
        Incident.rule_id == "SEC-RULE-APPR-001",
        Incident.service_identity == "srv-helpdeskr-agent"
    ).first()

    assert incident is not None
    assert incident.severity in ("HIGH", "CRITICAL")
    assert ev_id in incident.related_event_ids
    assert incident.evidence["is_financial_operation"] is False
    assert "Malformed approval reference" in incident.explanation
