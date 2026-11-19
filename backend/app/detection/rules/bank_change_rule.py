"""
Rule 5: Sensitive Bank Account Modification
Detects attempts to alter vendor banking and disbursement details.
"""

import re
from typing import Optional
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.services.risk_service import evaluate_risk
from sentinel.backend.app.services.sanitizer import sanitize_text


class SensitiveBankChangeRule(BaseDetectionRule):
    """
    Enforces heightened scrutiny on vendor banking details modifications.
    Every attempt to alter banking coordinates produces a high-priority incident.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-BANK-001",
            name="Sensitive Bank Account Modification",
            description="Detects attempts to update or overwrite vendor disbursement bank account details.",
            base_severity="CRITICAL",
            base_risk_score=80,
            is_enabled=True
        )

    def _is_bank_modification(self, event: ApiEvent) -> bool:
        """Identify if this event involves mutating banking coordinates."""
        action_match = (event.action or "").upper() in (
            "MODIFY_VENDOR_BANK_ACCOUNT",
            "UPDATE_BANK_ACCOUNT",
            "CHANGE_BANK_DETAILS",
            "UPDATE_DISBURSEMENT_ROUTE"
        )
        endpoint_match = "/bank-account" in (event.endpoint or "").lower()
        resource_match = (event.resource_type or "").upper() == "BANK_ACCOUNT"
        is_mutation_method = (event.http_method or "").upper() in ("POST", "PUT", "PATCH", "DELETE")

        return (action_match or (endpoint_match and is_mutation_method) or (resource_match and is_mutation_method))

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        if not self._is_bank_modification(event):
            return None

        modifiers = []

        # Check approval reference presence and syntax
        valid_regex = detection_settings.VALID_APPROVAL_REGEX
        approval = event.approval_reference or ""
        is_approval_valid = bool(re.match(valid_regex, approval.strip()))

        if not approval or not is_approval_valid:
            modifiers.append({
                "factor": "unverified_or_missing_approval",
                "points": +15,
                "reason": f"Bank modification attempted with invalid/missing approval: '{approval}'"
            })

        score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

        # Sanitize resource_id again defensively to guarantee zero plain bank account leakage
        sanitized_res_id, _ = sanitize_text(event.resource_id)

        explanation = (
            f"Sensitive vendor bank account modification attempted by service '{event.service_identity}' "
            f"for resource '{sanitized_res_id}'. "
            f"Approval Status: {'Verified (' + approval + ')' if is_approval_valid else 'UNAPPROVED / INVALID'}."
        )

        evidence = {
            "service_identity": event.service_identity,
            "action": event.action,
            "endpoint": event.endpoint,
            "http_method": event.http_method,
            "resource_type": event.resource_type,
            "resource_id": sanitized_res_id,  # Guaranteed masked
            "source_ip": event.source_ip,
            "approval_reference": approval,
            "is_approval_valid": is_approval_valid,
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
            resource_type=event.resource_type or "BANK_ACCOUNT",
            resource_id=sanitized_res_id
        )
