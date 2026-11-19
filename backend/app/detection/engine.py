"""
Detection Engine Orchestrator for SENTINEL
Coordinates rule evaluations, handles exceptions defensively, and dispatches findings
to the Incident Management Service.
"""

import logging
from typing import List
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.rule_registry import rule_registry
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.services.incident_service import create_or_update_incident
from sentinel.backend.app.services.audit_service import record_security_audit

logger = logging.getLogger("sentinel.detection_engine")


class DetectionEngine:
    """
    Deterministic rule execution engine.
    Processes newly persisted API events through all registered and enabled security rules.
    """
    def __init__(self, registry=rule_registry):
        self.registry = registry

    def analyze_event(self, event: ApiEvent, db: Session) -> List[Incident]:
        """
        Evaluate an API event through all active rules.
        Guarantees that detection exceptions do not discard or corrupt the persisted event.
        
        Args:
            event: Newly committed ApiEvent instance.
            db: Database session for rule queries and incident persistence.
            
        Returns:
            List of created or updated Incident records.
        """
        incidents: List[Incident] = []
        rules = self.registry.list_rules()

        for rule in rules:
            if not rule.is_enabled:
                continue

            try:
                result = rule.evaluate(event, db)
                if result and result.triggered:
                    incident = create_or_update_incident(db=db, result=result, event=event)
                    incidents.append(incident)
                    logger.warning(
                        "[DETECTION TRIGGERED] Rule: %s (%s) | Severity: %s | Score: %d | Service: %s | Event: %s",
                        rule.rule_id, rule.name, result.severity, result.risk_score,
                        event.service_identity, event.event_id
                    )
            except Exception as rule_exc:
                logger.error(
                    "Detection rule %s raised an unexpected error on event %s: %s",
                    rule.rule_id, event.event_id, str(rule_exc), exc_info=True
                )
                # Safely record rule execution error in security audit log
                try:
                    record_security_audit(
                        db=db,
                        severity="HIGH",
                        event_type="DETECTION_RULE_ERROR",
                        details=f"Rule {rule.rule_id} crashed during evaluation",
                        error_message=str(rule_exc),
                        source_ip=event.source_ip,
                        event_id_referenced=event.event_id
                    )
                except Exception as audit_exc:
                    logger.critical("Failed to log detection rule error to audit: %s", str(audit_exc))

        return incidents


# Global singleton engine instance
detection_engine = DetectionEngine()
