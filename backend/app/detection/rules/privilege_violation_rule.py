"""
Rule 4: Privilege and Scope Violation
Detects operations that exceed the configured permissions and endpoint scope of a service identity.
"""

import re
from typing import Optional
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import SIMULATED_SERVICE_POLICIES
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.services.risk_service import evaluate_risk


class PrivilegeViolationRule(BaseDetectionRule):
    """
    Identifies unauthorized method usage, out-of-scope endpoint requests,
    and privilege escalation attempts by service accounts.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-PRIV-001",
            name="Privilege and Scope Violation",
            description="Detects API actions and endpoint requests exceeding the configured scope of a service identity.",
            base_severity="HIGH",
            base_risk_score=75,
            is_enabled=True
        )

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        policy = SIMULATED_SERVICE_POLICIES.get(event.service_identity)
        if not policy:
            # Unregistered service attempting actions is flagged under IP anomaly and baseline policy
            return None

        violations = []
        modifiers = []

        # 1. Check HTTP Method Permission (Read-only vs Read-Write)
        allowed_methods = policy.get("allowed_methods", ["GET"])
        if event.http_method.upper() not in [m.upper() for m in allowed_methods]:
            violations.append(
                f"Unauthorized HTTP method '{event.http_method}' (Allowed methods: {allowed_methods})"
            )
            if policy.get("is_read_only", False) and event.http_method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                modifiers.append({"factor": "write_by_read_only_service", "points": +15, "reason": "Read-only service attempted state-changing mutation"})

        # 2. Check Endpoint Scope
        endpoint_patterns = policy.get("allowed_endpoints", [])
        endpoint_matched = False
        for pat in endpoint_patterns:
            if re.match(pat, event.endpoint, re.IGNORECASE):
                endpoint_matched = True
                break

        if not endpoint_matched:
            violations.append(
                f"Endpoint '{event.endpoint}' is outside the authorized scope for service '{event.service_identity}'"
            )

        # 3. Check Bank Modification Permission
        is_bank_endpoint = "/bank-account" in (event.endpoint or "").lower()
        is_bank_action = "BANK" in (event.action or "").upper()
        if (is_bank_endpoint or is_bank_action) and not policy.get("can_modify_bank_details", False):
            if event.http_method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                violations.append(
                    f"Service '{event.service_identity}' is explicitly prohibited from modifying bank account details"
                )
                modifiers.append({"factor": "unauthorized_bank_modification_attempt", "points": +20, "reason": "High-risk financial alteration attempted without privilege"})

        if violations:
            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

            explanation = (
                f"Privilege violation by '{event.service_identity}': " + "; ".join(violations)
            )

            evidence = {
                "service_identity": event.service_identity,
                "attempted_endpoint": event.endpoint,
                "attempted_method": event.http_method,
                "action": event.action,
                "violations": violations,
                "allowed_methods": allowed_methods,
                "is_read_only": policy.get("is_read_only", False),
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
