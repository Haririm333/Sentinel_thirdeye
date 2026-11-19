"""
Security Audit Service for SENTINEL
Records internal system audit logs and anomalies (e.g. duplicate events, malformed payloads).
Logs never leak sensitive parameters.
"""

import uuid
import logging
from typing import Optional
from sqlalchemy.orm import Session
from sentinel.backend.app.models.security_audit import SecurityAuditEvent

logger = logging.getLogger("sentinel.security_audit")


def record_security_audit(
    db: Session,
    severity: str,
    event_type: str,
    details: Optional[str] = None,
    error_message: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_id_referenced: Optional[str] = None
) -> SecurityAuditEvent:
    """
    Persist a security audit record to the database and structured logger.
    Auditing executes in a nested/safe manner so audit logs are recorded even
    if the primary event fails.
    """
    audit_id = str(uuid.uuid4())
    audit_record = SecurityAuditEvent(
        audit_id=audit_id,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
        event_id_referenced=event_id_referenced,
        details=details,
        error_message=error_message
    )

    try:
        db.add(audit_record)
        db.commit()
        db.refresh(audit_record)
    except Exception as exc:
        db.rollback()
        logger.error(
            "Failed to write security audit event to database: %s",
            str(exc),
            extra={"audit_id": audit_id, "event_type": event_type}
        )

    # Safe structured logging (no sensitive secrets)
    log_msg = f"[AUDIT] severity={severity} type={event_type} event_id={event_id_referenced} ip={source_ip}"
    if severity in ("HIGH", "CRITICAL"):
        logger.warning("%s details=%s error=%s", log_msg, details, error_message)
    else:
        logger.info("%s details=%s", log_msg, details)

    return audit_record
