"""
Unified Security Risk Assessment and Detection Integration Endpoints (Phase 6)
Endpoints:
- GET /api/v1/assessment/events/{event_id}: Retrieve unified multi-tier risk assessment for an event
- POST /api/v1/assessment/evaluate: Perform on-demand unified evaluation for an event
- GET /api/v1/assessment/summary: Multi-tier detection analytics and model readiness summary
- GET /api/v1/incidents/{incident_id}/assessment: Detailed combined assessment for an incident
- GET /api/v1/bank-changes/{request_id}/risk-assessment: Associated risk assessment and security warnings for bank changes
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from sentinel.backend.app.database import get_db
from sentinel.backend.app.security.auth import User, authenticate_user, require_role
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.bank_approval import BankChangeRequest
from sentinel.backend.app.schemas.unified_assessment import (
    UnifiedAssessmentResponse,
    UnifiedSummaryResponse,
    IncidentAssessmentResponse,
    BankChangeRiskAssessmentResponse
)
from sentinel.backend.app.services.unified_assessment_service import (
    assess_event,
    get_incident_assessment,
    get_unified_summary,
    assess_bank_change_risk
)

router = APIRouter(prefix="/api/v1", tags=["Unified Risk Assessment & Detection Integration"])


@router.get(
    "/assessment/events/{event_id}",
    response_model=UnifiedAssessmentResponse,
    summary="Get Unified Event Risk Assessment",
    description="Calculates or retrieves multi-tier risk assessment combining Deterministic Rules, Isolation Forest, and LSTM Autoencoder."
)
def get_event_unified_assessment(
    event_id: str,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve multi-tier assessment for a persisted event."""
    stmt = select(ApiEvent).where(ApiEvent.event_id == event_id)
    event = db.execute(stmt).scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "EventNotFound", "message": f"Event '{event_id}' not found."}
        )

    assessment = assess_event(db=db, event=event)
    return assessment


@router.post(
    "/assessment/evaluate",
    response_model=UnifiedAssessmentResponse,
    summary="On-Demand Unified Event Evaluation",
    description="Run on-demand multi-tier risk assessment by event ID."
)
def evaluate_event_on_demand(
    payload: Dict[str, Any],
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Evaluate event by event_id provided in body."""
    event_id = payload.get("event_id")
    if not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "MissingField", "message": "'event_id' is required in request body."}
        )

    stmt = select(ApiEvent).where(ApiEvent.event_id == event_id)
    event = db.execute(stmt).scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "EventNotFound", "message": f"Event '{event_id}' not found."}
        )

    assessment = assess_event(db=db, event=event)
    return assessment


@router.get(
    "/assessment/summary",
    response_model=UnifiedSummaryResponse,
    summary="Unified Detection Analytics & System Readiness Summary",
    description="Aggregated metrics across deterministic rules, Isolation Forest, and LSTM sequential detection subsystems."
)
def get_system_unified_summary(
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve system-wide multi-tier summary."""
    return get_unified_summary(db=db)


@router.get(
    "/incidents/{incident_id}/assessment",
    response_model=IncidentAssessmentResponse,
    summary="Get Incident Assessment Details",
    description="Retrieve combined multi-tier assessment, contributing detection components, and preserved evidence for an incident."
)
def get_incident_combined_assessment(
    incident_id: str,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve detailed combined assessment for a security incident."""
    assessment = get_incident_assessment(db=db, incident_id=incident_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "IncidentNotFound", "message": f"Incident '{incident_id}' not found."}
        )
    return assessment


@router.get(
    "/bank-changes/{request_id}/risk-assessment",
    response_model=BankChangeRiskAssessmentResponse,
    summary="Get Bank Change Linked Risk Assessment",
    description="Retrieve associated security incidents, anomaly warnings, and risk snapshot for a vendor bank change request."
)
def get_bank_change_linked_assessment(
    request_id: str,
    current_user: User = Depends(require_role(["FINANCE_APPROVER", "FINANCE_ADMIN", "AUDITOR"])),
    db: Session = Depends(get_db)
):
    """
    Retrieve security risk assessment and incident warning snapshot for finance reviewers.
    Enforces that AI risk scores NEVER replace human approvals.
    """
    stmt = select(BankChangeRequest).where(BankChangeRequest.request_id == request_id)
    change_req = db.execute(stmt).scalar_one_or_none()
    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' not found."}
        )

    # Compute live or retrieve snapshot
    snapshot = assess_bank_change_risk(
        db=db,
        vendor_id=change_req.vendor_id,
        requester_id=change_req.requester_id
    )

    return {
        "request_id": change_req.request_id,
        "vendor_id": change_req.vendor_id,
        "requester_id": change_req.requester_id,
        "request_status": change_req.status,
        "associated_incidents_count": snapshot.get("associated_incidents_count", 0),
        "max_incident_severity": snapshot.get("max_incident_severity", "NONE"),
        "max_incident_risk_score": snapshot.get("max_incident_risk_score", 0),
        "security_warnings": snapshot.get("security_warnings", []),
        "linked_incident_ids": snapshot.get("linked_incident_ids", []),
        "linked_incidents": snapshot.get("linked_incidents", []),
        "two_person_rule_status": "STRICT_HUMAN_APPROVAL_MANDATORY",
        "ai_authorization_override_permitted": False,
        "snapshot_timestamp": snapshot.get("snapshot_timestamp")
    }
