"""
SQLAlchemy Model for Internal Security Audit Events
Tracks system-level operational and security anomalies such as duplicate event submissions,
validation failures, payload size threshold violations, or malformed payloads.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from sentinel.backend.app.models.base import Base


class SecurityAuditEvent(Base):
    """
    Log of security audit events generated during ingestion.
    Provides non-repudiation and visibility into attempted malformed or duplicate traffic.
    """
    __tablename__ = "security_audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False
    )
    
    # Severity: INFO, WARNING, HIGH, CRITICAL
    severity = Column(String(20), index=True, nullable=False)
    
    # Event types: DUPLICATE_EVENT_ATTEMPT, VALIDATION_FAILURE,
    # SENSITIVE_DATA_DETECTED, REQUEST_SIZE_EXCEEDED, UNREGISTERED_SERVICE
    event_type = Column(String(100), index=True, nullable=False)
    
    source_ip = Column(String(45), nullable=True)
    event_id_referenced = Column(String(64), index=True, nullable=True)
    details = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<SecurityAuditEvent(audit_id='{self.audit_id}', "
            f"type='{self.event_type}', severity='{self.severity}')>"
        )
