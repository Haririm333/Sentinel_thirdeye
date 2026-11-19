"""
SQLAlchemy Model for Stored API Activity Events
Captures normalized events from LedgerOne, HelpDeskr, and TallyBridge.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, BigInteger, String, DateTime, Index
)
from sentinel.backend.app.models.base import Base


class ApiEvent(Base):
    """
    Persisted API activity log event.
    Contains structural, network, authentication, and resource metadata.
    Indexed for high-throughput temporal and identity-based security analytics.
    """
    __tablename__ = "api_events"

    # Primary key compatible with both PostgreSQL BigInteger and SQLite Integer
    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    
    # Unique Event UUID
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    
    # Normalized event timestamp (UTC)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False)
    
    # Ingestion timestamp recorded by SENTINEL (UTC)
    received_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False
    )
    
    # System metadata
    source_system = Column(String(50), index=True, nullable=False)
    service_identity = Column(String(100), index=True, nullable=False)
    
    # Request metadata
    endpoint = Column(String(255), index=True, nullable=False)
    http_method = Column(String(10), index=True, nullable=False)
    http_status_code = Column(Integer, index=True, nullable=False)
    request_size_bytes = Column(Integer, nullable=False, default=0)
    response_size_bytes = Column(Integer, nullable=False, default=0)
    
    # Network & Identity
    source_ip = Column(String(45), index=True, nullable=False)  # IPv4 (15) or IPv6 (45 max)
    auth_identity = Column(String(100), index=True, nullable=False)
    
    # Action & Resource Target
    action = Column(String(100), index=True, nullable=False)
    resource_type = Column(String(100), index=True, nullable=False)
    resource_id = Column(String(255), nullable=True)
    approval_reference = Column(String(100), nullable=True)
    
    # Tamper-evidence / deduplication audit hash (SHA-256)
    payload_hash = Column(String(64), nullable=True)

    # Composite indexes for frequent security queries
    __table_args__ = (
        Index("ix_api_events_ts_source", "timestamp", "source_system"),
        Index("ix_api_events_service_endpoint", "service_identity", "endpoint"),
        Index("ix_api_events_auth_action", "auth_identity", "action"),
    )

    def __repr__(self) -> str:
        return (
            f"<ApiEvent(event_id='{self.event_id}', source='{self.source_system}', "
            f"service='{self.service_identity}', method='{self.http_method}', "
            f"endpoint='{self.endpoint}', status={self.http_status_code})>"
        )
