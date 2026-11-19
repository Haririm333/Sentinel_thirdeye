"""
Pydantic Schemas for Phase 6: Unified Risk Assessment and Detection Integration
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class RuleFindingSchema(BaseModel):
    """Deterministic security rule finding."""
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int
    triggered: bool = True
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class IsolationForestFindingSchema(BaseModel):
    """Point-in-time Isolation Forest behavioral anomaly finding."""
    evaluated: bool = False
    model_status: str = "UNAVAILABLE"  # READY, UNAVAILABLE, INSUFFICIENT_DATA, UNTRAINED
    triggered: bool = False
    anomaly_score: float = 0.0
    calibrated_threshold: Optional[float] = None
    explanation: str
    top_deviations: List[Dict[str, Any]] = Field(default_factory=list)


class LSTMFindingSchema(BaseModel):
    """Sequential LSTM Autoencoder anomaly finding."""
    evaluated: bool = False
    model_status: str = "UNAVAILABLE"  # READY, UNAVAILABLE, INSUFFICIENT_DATA, UNTRAINED
    triggered: bool = False
    anomaly_score: float = 0.0
    reconstruction_error: float = 0.0
    calibrated_threshold: float = 0.0
    explanation: str
    top_feature_errors: List[Dict[str, Any]] = Field(default_factory=list)


class ModelReadinessSchema(BaseModel):
    """Readiness status of all detection subsystems."""
    deterministic_rules_count: int = 6
    isolation_forest_status: str = "UNKNOWN"
    isolation_forest_evaluated: bool = False
    lstm_status: str = "UNKNOWN"
    lstm_evaluated: bool = False


class UnifiedAssessmentResponse(BaseModel):
    """Comprehensive multi-tier risk assessment for an API event."""
    assessment_id: str
    event_id: str
    service_identity: str
    overall_risk_score: int = Field(ge=0, le=100)
    overall_risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_explanation: str
    contributing_components: List[str] = Field(default_factory=list)
    rule_findings: List[RuleFindingSchema] = Field(default_factory=list)
    isolation_forest_result: IsolationForestFindingSchema
    lstm_result: LSTMFindingSchema
    model_readiness: ModelReadinessSchema
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    assessment_timestamp: datetime


class UnifiedSummaryResponse(BaseModel):
    """System-wide summary of multi-tier detections and analytics."""
    total_assessed_events: int
    total_incidents: int
    component_trigger_counts: Dict[str, int]
    severity_distribution: Dict[str, int]
    average_risk_score: float
    model_status: Dict[str, Any]


class IncidentAssessmentResponse(BaseModel):
    """Enriched security incident detail with combined multi-tier assessment."""
    incident_id: str
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int
    status: str
    service_identity: str
    contributing_components: List[str]
    explanation: str
    evidence: Dict[str, Any]
    unified_assessment: Optional[UnifiedAssessmentResponse] = None
    created_at: datetime
    updated_at: datetime


class BankChangeRiskAssessmentResponse(BaseModel):
    """Security risk assessment and incident warning snapshot for bank change requests."""
    request_id: str
    vendor_id: str
    requester_id: str
    request_status: str
    associated_incidents_count: int
    max_incident_severity: str
    max_incident_risk_score: int
    security_warnings: List[str] = Field(default_factory=list)
    linked_incident_ids: List[str] = Field(default_factory=list)
    linked_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    two_person_rule_status: str = "STRICT_HUMAN_APPROVAL_MANDATORY"
    ai_authorization_override_permitted: bool = False
    snapshot_timestamp: datetime
