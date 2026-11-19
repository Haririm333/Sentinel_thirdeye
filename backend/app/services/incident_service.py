"""
Incident Management Service for SENTINEL
Handles incident creation, deduplication, correlation windows, lifecycle transitions,
and summary analytics.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import DetectionResult
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.api_event import ApiEvent


# Valid incident lifecycle state transitions
ALLOWED_TRANSITIONS = {
    "OPEN": {"INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"RESOLVED", "FALSE_POSITIVE", "OPEN"},
    "RESOLVED": {"OPEN", "INVESTIGATING"},
    "FALSE_POSITIVE": {"OPEN", "INVESTIGATING"}
}


class InvalidStatusTransitionError(ValueError):
    """Raised when an illegal incident lifecycle status change is requested."""
    pass


def create_or_update_incident(
    db: Session,
    result: DetectionResult,
    event: ApiEvent
) -> Incident:
    """
    Persist an incident or merge into an existing active incident if within the
    correlation deduplication window.
    """
    correlation_window = timedelta(seconds=detection_settings.CORRELATION_WINDOW_SECONDS)
    now_utc = datetime.now(timezone.utc)
    window_threshold = now_utc - correlation_window

    # Search for an active matching incident within the correlation window
    stmt = select(Incident).where(
        and_(
            Incident.rule_id == result.rule_id,
            Incident.service_identity == event.service_identity,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.updated_at >= window_threshold
        )
    ).order_by(Incident.updated_at.desc()).limit(1)

    existing_incident = db.execute(stmt).scalar_one_or_none()

    if existing_incident:
        # Correlate and merge: avoid duplicate incident storm
        related_ids = list(existing_incident.related_event_ids or [])
        if event.event_id not in related_ids:
            related_ids.append(event.event_id)
        existing_incident.related_event_ids = related_ids

        # Merge evidence metrics
        merged_evidence = dict(existing_incident.evidence or {})
        merged_evidence["occurrence_count"] = merged_evidence.get("occurrence_count", 1) + 1
        merged_evidence["last_event_id"] = event.event_id
        merged_evidence["latest_finding"] = result.evidence
        existing_incident.evidence = merged_evidence

        # Upgrade risk score if new event exhibits higher severity
        if result.risk_score > existing_incident.risk_score:
            existing_incident.risk_score = result.risk_score
            existing_incident.severity = result.severity

        existing_incident.updated_at = now_utc
        db.commit()
        db.refresh(existing_incident)
        return existing_incident

    # Create fresh incident
    incident_id = str(uuid.uuid4())
    initial_evidence = dict(result.evidence)
    initial_evidence["occurrence_count"] = 1

    new_incident = Incident(
        incident_id=incident_id,
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        severity=result.severity,
        risk_score=result.risk_score,
        status="OPEN",
        service_identity=event.service_identity,
        related_event_ids=[event.event_id],
        resource_type=result.resource_type or event.resource_type,
        resource_id=result.resource_id or event.resource_id,
        explanation=result.explanation,
        evidence=initial_evidence,
        created_at=now_utc,
        updated_at=now_utc
    )

    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)
    return new_incident


def get_incident_by_id(db: Session, incident_id: str) -> Optional[Incident]:
    """Retrieve an individual incident by its UUID."""
    stmt = select(Incident).where(Incident.incident_id == incident_id)
    return db.execute(stmt).scalar_one_or_none()


def query_incidents(
    db: Session,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    service_identity: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    max_risk_score: Optional[int] = None,
    page: int = 1,
    limit: int = 50
) -> Tuple[int, List[Incident]]:
    """
    Filter and paginate security incidents.
    Returns (total_count, list_of_incidents).
    """
    conditions = []
    if status:
        conditions.append(Incident.status == status.upper())
    if severity:
        conditions.append(Incident.severity == severity.upper())
    if rule_id:
        conditions.append(Incident.rule_id == rule_id)
    if service_identity:
        conditions.append(Incident.service_identity == service_identity)
    if min_risk_score is not None:
        conditions.append(Incident.risk_score >= min_risk_score)
    if max_risk_score is not None:
        conditions.append(Incident.risk_score <= max_risk_score)

    where_clause = and_(*conditions) if conditions else True

    # Count matching
    count_stmt = select(func.count(Incident.id)).where(where_clause)
    total = db.execute(count_stmt).scalar() or 0

    # Query page
    offset = (page - 1) * limit
    query_stmt = (
        select(Incident)
        .where(where_clause)
        .order_by(Incident.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    items = list(db.execute(query_stmt).scalars().all())

    return total, items


def update_incident_status(
    db: Session,
    incident_id: str,
    new_status: str,
    notes: Optional[str] = None
) -> Incident:
    """
    Transition incident lifecycle status with strict transition validation.
    """
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise ValueError(f"Incident with ID '{incident_id}' not found.")

    curr_status = incident.status.upper()
    target_status = new_status.upper()

    if curr_status == target_status:
        return incident

    valid_targets = ALLOWED_TRANSITIONS.get(curr_status, set())
    if target_status not in valid_targets:
        raise InvalidStatusTransitionError(
            f"Cannot transition incident from '{curr_status}' to '{target_status}'. "
            f"Allowed transitions from '{curr_status}': {sorted(list(valid_targets))}."
        )

    incident.status = target_status
    incident.updated_at = datetime.now(timezone.utc)
    
    if notes:
        evidence = dict(incident.evidence or {})
        audit_history = evidence.get("triage_history", [])
        audit_history.append({
            "from_status": curr_status,
            "to_status": target_status,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        evidence["triage_history"] = audit_history
        incident.evidence = evidence

    db.commit()
    db.refresh(incident)
    return incident


def get_detection_summary(db: Session) -> Dict[str, Any]:
    """Calculate aggregate incident metrics and status distributions."""
    total = db.execute(select(func.count(Incident.id))).scalar() or 0

    # By status
    status_rows = db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    ).all()
    by_status = {row[0]: row[1] for row in status_rows}

    # By severity
    sev_rows = db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    ).all()
    by_severity = {row[0]: row[1] for row in sev_rows}

    # By rule
    rule_rows = db.execute(
        select(Incident.rule_id, func.count(Incident.id)).group_by(Incident.rule_id)
    ).all()
    by_rule = {row[0]: row[1] for row in rule_rows}

    # Top targeted service identities
    service_rows = db.execute(
        select(Incident.service_identity, func.count(Incident.id))
        .group_by(Incident.service_identity)
        .order_by(func.count(Incident.id).desc())
        .limit(5)
    ).all()
    top_services = {row[0]: row[1] for row in service_rows}

    return {
        "total_incidents": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "top_services": top_services
    }
