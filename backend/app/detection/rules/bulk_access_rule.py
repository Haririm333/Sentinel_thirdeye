"""
Rule 2: Bulk Vendor Data Access
Detects anomalous volume and repeated bulk extraction of vendor records.
"""

from datetime import timedelta
from typing import Optional
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.services.risk_service import evaluate_risk


class BulkVendorAccessRule(BaseDetectionRule):
    """
    Identifies high-volume vendor data exfiltration and abnormal bulk downloads.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-BULK-001",
            name="Bulk Vendor Data Access",
            description="Detects anomalous data extraction volume or repeated bulk access to vendor records.",
            base_severity="MEDIUM",
            base_risk_score=50,
            is_enabled=True
        )

    def _is_vendor_target(self, event: ApiEvent) -> bool:
        """Determine if the target resource relates to vendor records."""
        is_vendor_resource = (event.resource_type or "").upper() in ("VENDOR", "VENDOR_DATABASE", "VENDOR_RECORD")
        is_vendor_endpoint = "/vendors" in (event.endpoint or "").lower()
        return is_vendor_resource or is_vendor_endpoint

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        if not self._is_vendor_target(event):
            return None

        single_threshold = detection_settings.BULK_SINGLE_RESPONSE_BYTES_THRESHOLD
        window_seconds = detection_settings.BULK_WINDOW_SECONDS
        count_threshold = detection_settings.BULK_WINDOW_RECORD_COUNT_THRESHOLD
        total_bytes_threshold = detection_settings.BULK_WINDOW_TOTAL_BYTES_THRESHOLD

        window_start = event.timestamp - timedelta(seconds=window_seconds)

        # Check temporal window for cumulative vendor data access by this service
        agg_stmt = select(
            func.count(ApiEvent.id),
            func.coalesce(func.sum(ApiEvent.response_size_bytes), 0)
        ).where(
            and_(
                ApiEvent.service_identity == event.service_identity,
                ApiEvent.timestamp >= window_start,
                ApiEvent.timestamp <= event.timestamp,
                (ApiEvent.resource_type.in_(["VENDOR", "VENDOR_DATABASE", "VENDOR_RECORD"]) | 
                 ApiEvent.endpoint.ilike("%/vendors%"))
            )
        )
        window_count, window_volume = db.execute(agg_stmt).first()

        # Detection conditions:
        # 1. Single response exceeds bulk threshold
        is_single_bulk = event.response_size_bytes >= single_threshold
        # 2. Cumulative volume or record count in window exceeds repeated threshold
        is_repeated_bulk = (window_count >= count_threshold) or (window_volume >= total_bytes_threshold)

        if is_single_bulk or is_repeated_bulk:
            modifiers = []
            if window_volume > total_bytes_threshold * 2:
                modifiers.append({"factor": "excessive_cumulative_volume", "points": +25, "reason": f"Volume > 2x limit ({window_volume} bytes)"})
            elif is_repeated_bulk and is_single_bulk:
                modifiers.append({"factor": "repeated_large_downloads", "points": +15, "reason": "Both single large download and repeated access observed"})

            # Fetch relevant event IDs
            events_stmt = select(ApiEvent.event_id).where(
                and_(
                    ApiEvent.service_identity == event.service_identity,
                    ApiEvent.timestamp >= window_start,
                    ApiEvent.timestamp <= event.timestamp,
                    (ApiEvent.resource_type.in_(["VENDOR", "VENDOR_DATABASE", "VENDOR_RECORD"]) | 
                     ApiEvent.endpoint.ilike("%/vendors%"))
                )
            ).order_by(ApiEvent.timestamp.desc()).limit(15)
            relevant_event_ids = list(db.execute(events_stmt).scalars().all())

            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

            mode_desc = "Single bulk export" if is_single_bulk and not is_repeated_bulk else "Repeated high-volume access"
            explanation = (
                f"{mode_desc} detected for service '{event.service_identity}'. "
                f"Accessed {window_count} vendor records with total response volume of "
                f"{window_volume:,} bytes (current request: {event.response_size_bytes:,} bytes)."
            )

            evidence = {
                "service_identity": event.service_identity,
                "current_event_bytes": event.response_size_bytes,
                "cumulative_window_bytes": window_volume,
                "vendor_records_accessed": window_count,
                "single_response_threshold": single_threshold,
                "window_bytes_threshold": total_bytes_threshold,
                "window_seconds": window_seconds,
                "relevant_event_ids": relevant_event_ids,
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
                resource_type=event.resource_type or "VENDOR",
                resource_id=event.resource_id
            )

        return None
