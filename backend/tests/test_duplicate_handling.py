"""
Tests for Duplicate Event Handling and Anti-Replay Security Controls
"""

import uuid
from fastapi import status
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.security_audit import SecurityAuditEvent


def test_duplicate_event_id_rejected_with_409(client, db_session, sample_valid_event):
    """
    Submitting an event with an existing event_id must:
    1. Return HTTP 409 Conflict with detailed error message.
    2. Not silently discard or overwrite the original record.
    3. Generate a security audit entry.
    """
    duplicate_id = str(uuid.uuid4())
    event_payload = sample_valid_event.copy()
    event_payload["event_id"] = duplicate_id
    event_payload["action"] = "ORIGINAL_ACTION"

    # First submission: Must succeed
    res1 = client.post("/api/v1/events", json=event_payload)
    assert res1.status_code == status.HTTP_201_CREATED

    # Attempt second submission with same event_id but different action
    event_payload_modified = event_payload.copy()
    event_payload_modified["action"] = "TAMPERED_ACTION"

    res2 = client.post("/api/v1/events", json=event_payload_modified)
    assert res2.status_code == status.HTTP_409_CONFLICT
    err_body = res2.json()
    assert err_body["detail"]["error"] == "DuplicateEventError"
    assert duplicate_id in err_body["detail"]["message"]

    # Verify original record in database is intact and NOT overwritten
    stored = db_session.query(ApiEvent).filter_by(event_id=duplicate_id).first()
    assert stored is not None
    assert stored.action == "ORIGINAL_ACTION"

    # Verify security audit entry was created for the duplicate attempt
    audit = db_session.query(SecurityAuditEvent).filter_by(
        event_id_referenced=duplicate_id,
        event_type="DUPLICATE_EVENT_ATTEMPT"
    ).first()
    assert audit is not None
    assert audit.severity == "WARNING"
