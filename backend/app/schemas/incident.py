"""
Pydantic Schemas for Security Incidents and Detection Summaries
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict


VALID_INCIDENT_STATUSES = Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
VALID_SEVERITIES = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class IncidentResponse(BaseModel):
    """Schema for retrieved security incident."""
    id: int
    incident_id: str
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int = Field(..., ge=0, le=100)
    status: str
    service_identity: str
    related_event_ids: List[str]
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    explanation: str
    evidence: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentStatusUpdate(BaseModel):
    """Schema for updating incident triage lifecycle status."""
    status: VALID_INCIDENT_STATUSES
    notes: Optional[str] = Field(default=None, max_length=1000)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IncidentListResponse(BaseModel):
    """Paginated collection of security incidents."""
    total: int
    page: int
    limit: int
    pages: int
    items: List[IncidentResponse]


class DetectionRuleResponse(BaseModel):
    """Schema for inspection of registered detection rules."""
    rule_id: str
    name: str
    description: str
    severity: str
    base_risk_score: int
    is_enabled: bool
    parameters: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class DetectionSummaryResponse(BaseModel):
    """Aggregated detection metrics and telemetry summary."""
    total_incidents: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_rule: Dict[str, int]
    top_services: Dict[str, int]
