"""
SQLAlchemy Model for Registered Service Identities
Defines authorized services, subsystems, and baseline connectivity rules.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime
from sentinel.backend.app.models.base import Base


class ServiceIdentity(Base):
    """
    Registry of authorized services (e.g. srv-tallybridge-sync, srv-ledgerone-core).
    Allows SENTINEL to detect unregistered or compromised service identities.
    """
    __tablename__ = "service_identities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String(100), unique=True, index=True, nullable=False)
    service_name = Column(String(150), nullable=False)
    source_system = Column(String(50), index=True, nullable=False)
    
    # Status: ACTIVE, SUSPENDED, DECOMMISSIONED
    status = Column(String(20), default="ACTIVE", nullable=False)
    
    # Optional CIDR or comma-delimited authorized source IP ranges
    allowed_ips = Column(String(500), nullable=True)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<ServiceIdentity(service_id='{self.service_id}', status='{self.status}')>"
