"""
SQLAlchemy Model for Registered Detection Rules
Tracks rule metadata, baseline parameters, and operational toggle status.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime
from sentinel.backend.app.models.base import Base


class DetectionRuleModel(Base):
    """
    Persistence record for detection rule configurations and operational status.
    """
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # Default baseline severity
    base_risk_score = Column(Integer, nullable=False)  # 0 to 100
    is_enabled = Column(Boolean, default=True, nullable=False)
    parameters = Column(JSON, nullable=False, default=dict)
    
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
        return f"<DetectionRule(rule_id='{self.rule_id}', enabled={self.is_enabled})>"
