"""
Base Rule Interface and Result Models for SENTINEL Detection Engine
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sentinel.backend.app.models.api_event import ApiEvent


class DetectionResult(BaseModel):
    """Encapsulates the finding and evidence of an evaluated detection rule."""
    triggered: bool
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int = Field(..., ge=0, le=100)
    explanation: str
    evidence: Dict[str, Any]
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None


class BaseDetectionRule(ABC):
    """
    Abstract base class for deterministic security detection rules.
    Subclasses implement rule evaluation logic and evidence construction.
    """
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        base_severity: str = "MEDIUM",
        base_risk_score: int = 50,
        is_enabled: bool = True
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.base_severity = base_severity
        self.base_risk_score = base_risk_score
        self.is_enabled = is_enabled

    @abstractmethod
    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        """
        Evaluate an incoming API event against this rule.
        
        Args:
            event: The newly persisted ApiEvent database model.
            db: Current database session for temporal or baseline queries.
            
        Returns:
            DetectionResult if suspicious behaviour is detected, otherwise None.
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Return rule metadata for documentation and registry APIs."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.base_severity,
            "base_risk_score": self.base_risk_score,
            "is_enabled": self.is_enabled
        }
