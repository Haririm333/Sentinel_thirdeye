"""
Rule 6: Missing Approval Reference
Detects sensitive business operations executed without a verified governance approval ticket.
"""

import re
from typing import Optional
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.services.risk_service import evaluate_risk


SENSITIVE_ACTIONS = {
    "MODIFY_VENDOR_BANK_ACCOUNT",
    "UPDATE_VENDOR_PROFILE",
    "BULK_DATA_EXPORT",
    "DELETE_VENDOR",
    "MODIFY_PAYMENT_LIMIT",
    "OVERRIDE_PAYMENT_SCHEDULE"
}


class MissingApprovalRule(BaseDetectionRule):
    """
    Flags sensitive business actions that fail to include a valid governance approval reference.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-APPR-001",
            name="Missing or Invalid Approval Reference",
            description="Detects sensitive corporate actions submitted without valid governance approval ticket.",
            base_severity="HIGH",
            base_risk_score=60,
            is_enabled=True
        )

    def _is_sensitive_operation(self, event: ApiEvent) -> bool:
        """Determine if this action requires prior ticket approval."""
        action = (event.action or "").upper()
        if action in SENSITIVE_ACTIONS:
            return True

        endpoint = (event.endpoint or "").lower()
        if any(keyword in endpoint for keyword in ("/bank-account", "/export", "/profile")):
            if (event.http_method or "").upper() in ("POST", "PUT", "PATCH", "DELETE"):
                return True

        return False

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        if not self._is_sensitive_operation(event):
            return None

        approval = (event.approval_reference or "").strip()
        valid_regex = detection_settings.VALID_APPROVAL_REGEX
        is_valid = bool(re.match(valid_regex, approval))

        if not is_valid:
            modifiers = []
            is_financial = "BANK" in (event.action or "").upper() or "/bank-account" in (event.endpoint or "").lower()
            if is_financial:
                modifiers.append({"factor": "financial_operation_without_approval", "points": +20, "reason": "Financial modification lacking governance authorization"})
            
            if "EMERGENCY" in approval.upper() or "OVERRIDE" in approval.upper():
                modifiers.append({"factor": "unverified_emergency_override", "points": +15, "reason": "Self-asserted emergency override string used in place of ticket"})

            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

            status_desc = "Missing approval reference" if not approval else f"Malformed approval reference ('{approval}')"
            explanation = (
                f"{status_desc} for sensitive action '{event.action}' on '{event.endpoint}' "
                f"by service '{event.service_identity}'. Expected format matching '{valid_regex}'."
            )

            evidence = {
                "service_identity": event.service_identity,
                "action": event.action,
                "endpoint": event.endpoint,
                "approval_reference_provided": approval if approval else None,
                "expected_format_regex": valid_regex,
                "is_financial_operation": is_financial,
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
