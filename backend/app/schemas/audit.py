"""
Pydantic Schemas for Security Audit Events
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class SecurityAuditEventResponse(BaseModel):
    id: int
    audit_id: str
    timestamp: datetime
    severity: str
    event_type: str
    source_ip: Optional[str] = None
    event_id_referenced: Optional[str] = None
    details: Optional[str] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
