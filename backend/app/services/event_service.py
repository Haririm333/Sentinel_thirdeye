"""
Event Ingestion and Retrieval Service for SENTINEL
Handles validation, timestamp normalization, duplicate detection, sanitization,
integrity hashing, and database persistence.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.service_identity import ServiceIdentity
from sentinel.backend.app.schemas.event import EventCreate
from sentinel.backend.app.services.sanitizer import sanitize_text
from sentinel.backend.app.services.audit_service import record_security_audit
from sentinel.backend.app.detection.engine import detection_engine

logger = logging.getLogger("sentinel.event_service")


class DuplicateEventException(Exception):
    """Raised when an incoming event possesses an event_id that already exists."""
    def __init__(self, event_id: str):
        self.event_id = event_id
        super().__init__(f"Duplicate event rejected: Event with ID '{event_id}' already exists.")


class ServiceSuspendedException(Exception):
    """Raised when an event originates from a suspended service identity."""
    def __init__(self, service_identity: str):
        self.service_identity = service_identity
        super().__init__(f"Service identity '{service_identity}' is suspended.")


def compute_payload_hash(event_dict: dict) -> str:
    """
    Compute deterministic SHA-256 integrity hash of canonical event payload.
    Used for tamper-evidence and audit verification.
    """
    # Exclude dynamic server fields if present
    canonical_dict = {
        k: str(v) for k, v in sorted(event_dict.items())
        if k not in ("id", "received_at", "payload_hash")
    }
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def process_and_store_event(db: Session, event_in: EventCreate, client_ip: str) -> ApiEvent:
    """
    Process, sanitize, validate, and store an incoming API activity event.
    Guarantees:
    - Safe handling of duplicate event IDs (records security audit, raises DuplicateEventException).
    - Normalization of timestamps to UTC.
    - Sanitization of sensitive data (passwords, tokens, bank accounts).
    - Integrity hash generation.
    - Non-silent failure recording.
    """
    # 1. Duplicate check (Idempotency and anti-replay protection)
    existing_stmt = select(ApiEvent).where(ApiEvent.event_id == event_in.event_id)
    existing_event = db.execute(existing_stmt).scalar_one_or_none()
    
    if existing_event:
        # Record security audit event for duplicate attempt
        record_security_audit(
            db=db,
            severity="WARNING",
            event_type="DUPLICATE_EVENT_ATTEMPT",
            details=f"Duplicate submission attempted for event_id={event_in.event_id} from system={event_in.source_system}",
            error_message="Duplicate event_id collision detected",
            source_ip=client_ip,
            event_id_referenced=event_in.event_id
        )
        raise DuplicateEventException(event_in.event_id)

    # 2. Service identity check
    service_stmt = select(ServiceIdentity).where(ServiceIdentity.service_id == event_in.service_identity)
    service_record = db.execute(service_stmt).scalar_one_or_none()
    if service_record:
        if service_record.status == "SUSPENDED":
            record_security_audit(
                db=db,
                severity="HIGH",
                event_type="SUSPENDED_SERVICE_ACTIVITY",
                details=f"Event received from suspended service: {event_in.service_identity}",
                source_ip=client_ip,
                event_id_referenced=event_in.event_id
            )
            raise ServiceSuspendedException(event_in.service_identity)
    else:
        # Log unregistered service identity for security visibility, but accept event
        record_security_audit(
            db=db,
            severity="INFO",
            event_type="UNREGISTERED_SERVICE_IDENTITY",
            details=f"Event received from unregistered service_identity='{event_in.service_identity}'",
            source_ip=client_ip,
            event_id_referenced=event_in.event_id
        )

    # 3. Data Sanitization (Redact secrets/full bank accounts from resource identifiers/approvals)
    sanitized_resource_id, mod_res = sanitize_text(event_in.resource_id)
    sanitized_approval, mod_app = sanitize_text(event_in.approval_reference)
    sanitized_endpoint, mod_ep = sanitize_text(event_in.endpoint)

    if mod_res or mod_app or mod_ep:
        record_security_audit(
            db=db,
            severity="WARNING",
            event_type="SENSITIVE_DATA_REDACTED",
            details=f"Sensitive patterns sanitized in incoming payload for event_id={event_in.event_id}",
            source_ip=client_ip,
            event_id_referenced=event_in.event_id
        )

    # 4. Normalize timestamp to UTC
    normalized_ts = event_in.timestamp
    if normalized_ts.tzinfo is None:
        normalized_ts = normalized_ts.replace(tzinfo=timezone.utc)
    else:
        normalized_ts = normalized_ts.astimezone(timezone.utc)

    # 5. Compute cryptographic hash of payload
    event_dict = event_in.model_dump()
    event_dict["endpoint"] = sanitized_endpoint
    event_dict["resource_id"] = sanitized_resource_id
    event_dict["approval_reference"] = sanitized_approval
    payload_hash = compute_payload_hash(event_dict)

    # 6. Construct DB model
    db_event = ApiEvent(
        event_id=event_in.event_id,
        timestamp=normalized_ts,
        received_at=datetime.now(timezone.utc),
        source_system=event_in.source_system,
        service_identity=event_in.service_identity,
        endpoint=sanitized_endpoint,
        http_method=event_in.http_method,
        http_status_code=event_in.http_status_code,
        request_size_bytes=event_in.request_size_bytes,
        response_size_bytes=event_in.response_size_bytes,
        source_ip=event_in.source_ip,
        auth_identity=event_in.auth_identity,
        action=event_in.action,
        resource_type=event_in.resource_type,
        resource_id=sanitized_resource_id,
        approval_reference=sanitized_approval,
        payload_hash=payload_hash
    )

    try:
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
    except Exception as exc:
        db.rollback()
        record_security_audit(
            db=db,
            severity="CRITICAL",
            event_type="DB_INSERTION_FAILURE",
            details=f"Failed to persist event {event_in.event_id}",
            error_message=str(exc),
            source_ip=client_ip,
            event_id_referenced=event_in.event_id
        )
        raise

    # 7. Run Deterministic Detection Engine against persisted event
    # Detection failures are handled gracefully so persisted telemetry is never lost
    try:
        detection_engine.analyze_event(db_event, db)
    except Exception as detect_exc:
        logger.error(
            "Detection engine encounter failure analyzing event %s: %s",
            db_event.event_id, str(detect_exc), exc_info=True
        )

    # 8. Run Machine Learning Behavioral Anomaly Detector (Phase 3)
    try:
        from sentinel.backend.app.ml.config import ml_settings
        from sentinel.backend.app.ml.features import extract_window_features
        from sentinel.backend.app.ml.detector import anomaly_detector

        window_start = db_event.timestamp - timedelta(seconds=ml_settings.WINDOW_SECONDS)
        recent_events = list(
            db.execute(
                select(ApiEvent).where(
                    and_(
                        ApiEvent.service_identity == db_event.service_identity,
                        ApiEvent.timestamp >= window_start,
                        ApiEvent.timestamp <= db_event.timestamp
                    )
                )
            ).scalars().all()
        )
        if recent_events and len(recent_events) >= ml_settings.MIN_EVENTS_PER_WINDOW:
            window_features = extract_window_features(recent_events, db_event.service_identity)
            anomaly_detector.evaluate_and_record_incident(window_features, db_event, db)
    except Exception as ml_exc:
        logger.error(
            "ML anomaly detector encounter failure analyzing event %s: %s",
            db_event.event_id, str(ml_exc), exc_info=True
        )

    return db_event


def get_event_by_id(db: Session, event_id: str) -> Optional[ApiEvent]:
    """Retrieve a single API event by event_id."""
    stmt = select(ApiEvent).where(ApiEvent.event_id == event_id)
    return db.execute(stmt).scalar_one_or_none()


def query_events(
    db: Session,
    source_system: Optional[str] = None,
    service_identity: Optional[str] = None,
    auth_identity: Optional[str] = None,
    endpoint: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    http_status_code: Optional[int] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = 1,
    limit: int = 50
) -> Tuple[int, List[ApiEvent]]:
    """
    Retrieve events matching filters with pagination.
    Returns (total_count, list_of_events).
    """
    conditions = []
    
    if source_system:
        conditions.append(ApiEvent.source_system == source_system)
    if service_identity:
        conditions.append(ApiEvent.service_identity == service_identity)
    if auth_identity:
        conditions.append(ApiEvent.auth_identity == auth_identity)
    if endpoint:
        conditions.append(ApiEvent.endpoint.ilike(f"%{endpoint}%"))
    if action:
        conditions.append(ApiEvent.action == action)
    if resource_type:
        conditions.append(ApiEvent.resource_type == resource_type)
    if http_status_code is not None:
        conditions.append(ApiEvent.http_status_code == http_status_code)
    if start_time:
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        conditions.append(ApiEvent.timestamp >= start_time)
    if end_time:
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        conditions.append(ApiEvent.timestamp <= end_time)

    where_clause = and_(*conditions) if conditions else True

    # Count total
    count_stmt = select(func.count(ApiEvent.id)).where(where_clause)
    total = db.execute(count_stmt).scalar() or 0

    # Query items with pagination
    offset = (page - 1) * limit
    query_stmt = (
        select(ApiEvent)
        .where(where_clause)
        .order_by(ApiEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    items = list(db.execute(query_stmt).scalars().all())

    return total, items
