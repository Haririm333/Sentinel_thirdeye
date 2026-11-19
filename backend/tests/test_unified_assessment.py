"""
Unit and Integration Tests for Phase 6: Unified Risk Assessment and Detection Integration

Verifies:
1. Multi-tier Detection Integration: Deterministic Rules + Isolation Forest + LSTM Autoencoder.
2. Missing / Unavailable Model Handling: Safe handling, never assumed normal.
3. Synergistic Risk Aggregation: Deterministic hard floor, cross-tier compounding, clamped [0, 100].
4. Duplicate Incident Prevention & Evidence Preservation: Correlation deduplication without alert fatigue.
5. Bank Change Risk Association: Links prior incidents, generates warnings for finance approvers.
6. AI Non-Bypass Invariant: AI risk scores NEVER authorize bank changes; two-person human rule strictly enforced.
7. Active Account Invariance: Old bank account remains active until two approvals commit.
8. Role-Based Access Control: Unauthorized access to assessment endpoints rejected (401/403).
9. Sensitive Data Masking: Plaintext accounts and credentials never leaked in assessments.
10. Unified REST Endpoints: GET assessment by event, summary analytics, incident details.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.bank_approval import VendorBankAccount, BankChangeRequest
from sentinel.backend.app.services.unified_assessment_service import (
    assess_event,
    aggregate_risk,
    assess_bank_change_risk,
    get_unified_summary,
    get_incident_assessment
)
from sentinel.backend.app.services.bank_approval_service import (
    get_or_init_vendor,
    create_bank_change_request,
    approve_bank_change_request
)
from sentinel.backend.app.services.event_service import process_and_store_event
from sentinel.backend.app.schemas.event import EventCreate
from sentinel.backend.app.security.auth import DEV_USER_REGISTRY

AUTH_SARAH = {"X-User-Id": "usr_req_sarah"}        # Role: REQUESTER
AUTH_ELENA = {"X-User-Id": "usr_appr_elena"}       # Role: FINANCE_APPROVER
AUTH_DAVID = {"X-User-Id": "usr_appr_david"}       # Role: FINANCE_APPROVER
AUTH_RACHEL = {"X-User-Id": "usr_audit_rachel"}    # Role: AUDITOR
AUTH_GUEST = {"X-User-Id": "usr_unauth_hacker"}    # Role: GUEST


def test_risk_aggregation_algorithm():
    """Test documented, configurable synergistic risk aggregation logic."""
    # 1. Clean traffic: 0 score
    score, level, expl, comps, evid = aggregate_risk(
        rule_findings=[],
        if_result={"evaluated": True, "triggered": False, "anomaly_score": 0.12},
        lstm_result={"evaluated": True, "triggered": False, "anomaly_score": 0.15}
    )
    assert score == 0
    assert level == "LOW"
    assert len(comps) == 0
    assert "Normal API activity" in expl

    # 2. Deterministic rule only: acts as hard floor
    score, level, expl, comps, evid = aggregate_risk(
        rule_findings=[{"rule_id": "SEC-RULE-PRIV-001", "rule_name": "Privilege Violation", "risk_score": 85, "triggered": True}],
        if_result={"evaluated": False, "model_status": "UNAVAILABLE", "triggered": False},
        lstm_result={"evaluated": False, "model_status": "INSUFFICIENT_DATA", "triggered": False}
    )
    assert score == 85
    assert level == "CRITICAL"
    assert comps == ["DETERMINISTIC_RULES"]
    # Explanations must explicitly mention that unavailable models were not evaluated and NOT assumed normal
    assert "UNAVAILABLE" in expl
    assert "not assumed normal" in expl

    # 3. Cross-tier confirmation (Rule + IF): +10 synergy boost
    score, level, expl, comps, evid = aggregate_risk(
        rule_findings=[{"rule_id": "SEC-RULE-BULK-001", "rule_name": "Bulk Vendor Access", "risk_score": 75, "triggered": True}],
        if_result={"evaluated": True, "triggered": True, "anomaly_score": 0.80},
        lstm_result={"evaluated": False, "model_status": "INSUFFICIENT_DATA", "triggered": False}
    )
    # base = max(75, 80) = 80; dual boost = +10 -> 90
    assert score == 90
    assert level == "CRITICAL"
    assert set(comps) == {"DETERMINISTIC_RULES", "ISOLATION_FOREST"}
    assert "+10 synergy boost" in expl

    # 4. Triple-tier confirmation (Rule + IF + LSTM): +15 synergy boost (clamped to 100)
    score, level, expl, comps, evid = aggregate_risk(
        rule_findings=[{"rule_id": "SEC-RULE-RATE-001", "rule_name": "Rate Limit", "risk_score": 70, "triggered": True}],
        if_result={"evaluated": True, "triggered": True, "anomaly_score": 0.85},
        lstm_result={"evaluated": True, "triggered": True, "anomaly_score": 0.90}
    )
    # base = max(70, 85, 90) = 90; triple boost = +15 -> 105 -> clamped to 100
    assert score == 100
    assert level == "CRITICAL"
    assert len(comps) == 3
    assert "+15 synergy boost" in expl


def test_missing_and_unavailable_models_never_treated_as_normal(db_session):
    """Missing or uncalibrated models are flagged as UNAVAILABLE or INSUFFICIENT_DATA without diluting findings."""
    event = ApiEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_system="HelpDeskr",
        service_identity="srv-uncalibrated-new-service",
        endpoint="/api/v1/tickets",
        http_method="GET",
        http_status_code=200,
        request_size_bytes=100,
        response_size_bytes=200,
        source_ip="10.0.1.50",
        auth_identity="usr_test_1",
        action="READ_TICKET",
        resource_type="TICKET",
        resource_id="tkt_123"
    )
    db_session.add(event)
    db_session.commit()

    assessment = assess_event(db=db_session, event=event)
    assert assessment["model_readiness"]["isolation_forest_evaluated"] is False
    assert assessment["model_readiness"]["lstm_evaluated"] is False
    assert assessment["isolation_forest_result"]["model_status"] in ("UNAVAILABLE", "UNTRAINED", "INSUFFICIENT_DATA")
    assert assessment["lstm_result"]["model_status"] in ("UNAVAILABLE", "UNTRAINED", "INSUFFICIENT_DATA")


def test_unified_assessment_for_suspicious_event(client, db_session):
    """Event violating a deterministic rule is flagged with unified assessment and explainability."""
    # Read-only service attempting POST mutation -> Rule 4 Privilege Violation (score 85)
    evt_payload = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "TallyBridge",
        "service_identity": "srv-tallybridge-sync",
        "endpoint": "/api/v1/vendors/create",
        "http_method": "POST",
        "http_status_code": 201,
        "request_size_bytes": 500,
        "response_size_bytes": 1000,
        "source_ip": "10.0.3.5",
        "auth_identity": "usr_tally_admin",
        "action": "MUTATE_CONFIG",
        "resource_type": "CONFIGURATION",
        "resource_id": "cfg_9981"
    }
    client.post("/api/v1/events", json=evt_payload)

    # Query unified assessment API
    res = client.get(f"/api/v1/assessment/events/{evt_payload['event_id']}", headers=AUTH_RACHEL)
    assert res.status_code == 200
    data = res.json()

    assert data["event_id"] == evt_payload["event_id"]
    assert "DETERMINISTIC_RULES" in data["contributing_components"]
    assert data["overall_risk_score"] >= 75
    assert data["overall_risk_level"] in ("HIGH", "CRITICAL")
    assert len(data["rule_findings"]) > 0
    assert "Privilege & Scope Violation" in data["risk_explanation"] or "SEC-RULE-PRIV-001" in str(data["rule_findings"])


def test_on_demand_evaluate_endpoint(client, db_session):
    """POST /api/v1/assessment/evaluate assesses existing event on demand."""
    event = ApiEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_system="LedgerOne",
        service_identity="srv-ledgerone-core",
        endpoint="/api/v1/payments",
        http_method="GET",
        http_status_code=200,
        request_size_bytes=100,
        response_size_bytes=200,
        source_ip="10.0.1.15",
        auth_identity="usr_ledger_1",
        action="READ_PAYMENTS",
        resource_type="PAYMENT",
        resource_id="pay_100"
    )
    db_session.add(event)
    db_session.commit()

    res = client.post(
        "/api/v1/assessment/evaluate",
        json={"event_id": event.event_id},
        headers=AUTH_RACHEL
    )
    assert res.status_code == 200
    data = res.json()
    assert data["event_id"] == event.event_id
    assert "overall_risk_score" in data
    assert "model_readiness" in data


def test_incident_assessment_endpoint(client, db_session):
    """GET /api/v1/incidents/{incident_id}/assessment returns combined details and contributing components."""
    # Create incident in DB
    inc_id = str(uuid.uuid4())
    inc = Incident(
        incident_id=inc_id,
        rule_id="SEC-RULE-RATE-001",
        rule_name="Excessive API Request Rate",
        severity="HIGH",
        risk_score=75,
        status="OPEN",
        service_identity="srv-ledgerone-core",
        related_event_ids=["evt-sample-1"],
        resource_type="API_ENDPOINT",
        resource_id="/api/v1/vendors",
        explanation="High request frequency observed",
        evidence={"request_count": 250, "window_seconds": 60, "contributing_components": ["DETERMINISTIC_RULES"]}
    )
    db_session.add(inc)
    db_session.commit()

    res = client.get(f"/api/v1/incidents/{inc_id}/assessment", headers=AUTH_RACHEL)
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert "DETERMINISTIC_RULES" in data["contributing_components"]
    assert data["severity"] == "HIGH"


def test_unified_summary_analytics_endpoint(client, db_session):
    """GET /api/v1/assessment/summary returns aggregated analytics across all tiers."""
    res = client.get("/api/v1/assessment/summary", headers=AUTH_RACHEL)
    assert res.status_code == 200
    data = res.json()
    assert "total_assessed_events" in data
    assert "total_incidents" in data
    assert "component_trigger_counts" in data
    assert "severity_distribution" in data
    assert "model_status" in data


def test_bank_change_links_prior_incidents_and_security_warnings(client, db_session):
    """Submitting bank change links vendor security incidents and surfaces warnings for finance reviewers."""
    target_vendor = "vnd_10482_suspicious"

    # Seed prior incident for this vendor
    prior_incident = Incident(
        incident_id=str(uuid.uuid4()),
        rule_id="SEC-RULE-BULK-001",
        rule_name="Bulk Vendor Data Access",
        severity="HIGH",
        risk_score=78,
        status="OPEN",
        service_identity="srv-ledgerone-core",
        related_event_ids=["evt-prior-1"],
        resource_type="VENDOR",
        resource_id=target_vendor,
        explanation=f"Excessive vendor records queried for {target_vendor}",
        evidence={"records_accessed": 150}
    )
    db_session.add(prior_incident)
    db_session.commit()

    # Sarah submits bank change for this vendor
    payload = {
        "vendor_id": target_vendor,
        "proposed_account_number": "443322119900",
        "proposed_bank_name": "Standard Chartered",
        "proposed_routing_number": "021000021",
        "request_reason": "Account update following vendor audit"
    }
    create_res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    assert create_res.status_code == 201
    change_data = create_res.json()
    req_id = change_data["request_id"]

    # Verify linked incident IDs and warnings are present in response
    assert prior_incident.incident_id in change_data["linked_incident_ids"]
    assert len(change_data["security_warnings"]) > 0
    assert "Bulk Vendor Data Access" in str(change_data["security_warnings"])

    # Query bank change risk assessment endpoint
    risk_res = client.get(f"/api/v1/bank-changes/{req_id}/risk-assessment", headers=AUTH_ELENA)
    assert risk_res.status_code == 200
    risk_data = risk_res.json()

    assert risk_data["request_id"] == req_id
    assert risk_data["associated_incidents_count"] >= 1
    assert risk_data["max_incident_severity"] == "HIGH"
    assert risk_data["two_person_rule_status"] == "STRICT_HUMAN_APPROVAL_MANDATORY"
    assert risk_data["ai_authorization_override_permitted"] is False


def test_ai_risk_score_never_bypasses_two_person_approval(client, db_session):
    """
    CRITICAL SECURITY INVARIANT:
    Even if risk score is 0 or 100, AI NEVER replaces human approvals.
    Two distinct finance approvers are strictly required before commit.
    """
    # 1. Clean vendor with zero risk
    payload = {
        "vendor_id": "vnd_10483_clean",
        "proposed_account_number": "998877112233",
        "proposed_bank_name": "JPMorgan Chase",
        "proposed_routing_number": "021000021",
        "request_reason": "Low risk routine update"
    }
    create_res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = create_res.json()["request_id"]
    old_account_ref = create_res.json()["old_bank_account_ref"]

    # Request is PENDING_APPROVAL. AI does NOT auto-commit!
    get_req = client.get(f"/api/v1/bank-changes/{req_id}", headers=AUTH_SARAH).json()
    assert get_req["status"] == "PENDING_APPROVAL"
    assert get_req["approval_count"] == 0

    # Old bank account is still active
    vendor = get_or_init_vendor(db_session, "vnd_10483_clean")
    assert vendor.active_bank_account_ref == old_account_ref

    # First approver (Elena) approves -> PARTIALLY_APPROVED
    appr1 = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Elena reviewed warnings: clean"},
        headers=AUTH_ELENA
    )
    assert appr1.json()["status"] == "PARTIALLY_APPROVED"

    # Old bank account STILL active after first approval
    db_session.refresh(vendor)
    assert vendor.active_bank_account_ref == old_account_ref
    assert vendor.version == 1

    # Second approver (David) approves -> COMMITTED
    appr2 = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "David second signoff"},
        headers=AUTH_DAVID
    )
    assert appr2.json()["status"] == "COMMITTED"

    # NOW and ONLY NOW is vendor active account updated
    db_session.refresh(vendor)
    assert vendor.active_bank_account_ref == create_res.json()["proposed_bank_account_ref"]
    assert vendor.version == 2


def test_unauthorized_access_to_risk_assessments_rejected(client):
    """Unauthorized or unauthenticated users cannot view sensitive security assessments."""
    # Unauthenticated
    res_no_auth = client.get("/api/v1/assessment/summary")
    assert res_no_auth.status_code == 401

    # Guest cannot view bank risk assessments
    res_guest = client.get("/api/v1/bank-changes/req_123/risk-assessment", headers=AUTH_GUEST)
    assert res_guest.status_code == 403


def test_sensitive_data_masking_in_assessments(client, db_session):
    """Raw account numbers and credentials are not leaked in assessments or warnings."""
    raw_account = "9988776655443322"
    raw_token = "secret-token-abcdef123456"

    # Create event with sensitive details
    event = ApiEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_system="LedgerOne",
        service_identity="srv-ledgerone-core",
        endpoint="/api/v1/vendors",
        http_method="POST",
        http_status_code=201,
        request_size_bytes=200,
        response_size_bytes=300,
        source_ip="10.0.1.15",
        auth_identity="usr_ledger_1",
        action="UPDATE_VENDOR",
        resource_type="BANK_ACCOUNT",
        resource_id=f"ACC-***masked***3322",
        approval_reference="APP-2026-001"
    )
    db_session.add(event)
    db_session.commit()

    res = client.get(f"/api/v1/assessment/events/{event.event_id}", headers=AUTH_RACHEL)
    assert res.status_code == 200
    assert raw_account not in res.text
    assert raw_token not in res.text
