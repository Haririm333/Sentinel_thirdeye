"""
Rule 1: Excessive API Request Rate
Detects unusually high API request velocity from the same service identity within a sliding window.
"""

from datetime import timedelta
from typing import Optional
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.services.risk_service import evaluate_risk


class ExcessiveRequestRateRule(BaseDetectionRule):
    """
    Flags API request flooding and potential automated enumeration / DoS attempts.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-RATE-001",
            name="Excessive API Request Rate",
            description="Detects request volume exceeding configured rate threshold for a single service identity.",
            base_severity="MEDIUM",
            base_risk_score=45,
            is_enabled=True
        )

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        window_seconds = detection_settings.RATE_LIMIT_WINDOW_SECONDS
        threshold = detection_settings.RATE_LIMIT_THRESHOLD_COUNT
        window_start = event.timestamp - timedelta(seconds=window_seconds)

        # Count events from this service identity within the temporal window
        count_stmt = select(func.count(ApiEvent.id)).where(
            and_(
                ApiEvent.service_identity == event.service_identity,
                ApiEvent.timestamp >= window_start,
                ApiEvent.timestamp <= event.timestamp
            )
        )
        measured_count = db.execute(count_stmt).scalar() or 0

        if measured_count > threshold:
            # Risk scoring with dynamic velocity modifiers
            modifiers = []
            if measured_count > threshold * 3:
                modifiers.append({"factor": "extreme_rate_multiplier", "points": +30, "reason": "Rate > 3x threshold"})
            elif measured_count > threshold * 1.5:
                modifiers.append({"factor": "high_rate_multiplier", "points": +15, "reason": "Rate > 1.5x threshold"})

            # Sample related event IDs in this window
            sample_stmt = select(ApiEvent.event_id).where(
                and_(
                    ApiEvent.service_identity == event.service_identity,
                    ApiEvent.timestamp >= window_start,
                    ApiEvent.timestamp <= event.timestamp
                )
            ).order_by(ApiEvent.timestamp.desc()).limit(10)
            sample_ids = list(db.execute(sample_stmt).scalars().all())

            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

            explanation = (
                f"Service identity '{event.service_identity}' issued {measured_count} requests "
                f"within {window_seconds}s, exceeding the security threshold of {threshold} requests."
            )

            evidence = {
                "service_identity": event.service_identity,
                "measured_request_count": measured_count,
                "threshold_count": threshold,
                "time_window_seconds": window_seconds,
                "window_start": window_start.isoformat(),
                "window_end": event.timestamp.isoformat(),
                "sample_event_ids": sample_ids,
                "scoring_breakdown": breakdown
            }

            return DetectionResult(
                triggered=True,
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=severity,
                risk_score=score,
                explanation=explanation,
                evidence=evidence,
                resource_type=event.resource_type,
                resource_id=event.resource_id
            )

        return None
