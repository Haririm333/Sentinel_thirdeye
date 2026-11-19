"""
Rule 3: Unexpected Source IP
Detects service activity originating from unapproved or anomalous IP addresses.
"""

import ipaddress
from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.backend.app.detection.base_rule import BaseDetectionRule, DetectionResult
from sentinel.backend.app.detection.config import SIMULATED_SERVICE_POLICIES, detection_settings
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.service_identity import ServiceIdentity
from sentinel.backend.app.services.risk_service import evaluate_risk


def is_ip_in_allowlist(client_ip_str: str, allowed_patterns: List[str]) -> bool:
    """
    Check if client IP matches an allowed list containing single IPs or CIDR blocks.
    """
    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        return False

    for pattern in allowed_patterns:
        cleaned = pattern.strip()
        if not cleaned:
            continue
        try:
            # Check if CIDR or single IP
            if "/" in cleaned:
                network = ipaddress.ip_network(cleaned, strict=False)
                if client_ip in network:
                    return True
            else:
                if client_ip == ipaddress.ip_address(cleaned):
                    return True
        except ValueError:
            continue

    return False


class UnexpectedSourceIPRule(BaseDetectionRule):
    """
    Flags API invocations from IP addresses outside a service's sanctioned network perimeter.
    """
    def __init__(self):
        super().__init__(
            rule_id="SEC-RULE-IP-001",
            name="Unexpected Source IP Address",
            description="Detects service activity originating from unverified or unapproved IP addresses.",
            base_severity="HIGH",
            base_risk_score=65,
            is_enabled=True
        )

    def evaluate(self, event: ApiEvent, db: Session) -> Optional[DetectionResult]:
        if not self.is_enabled:
            return None

        # 1. Fetch allowed IPs from database or simulated policy
        allowed_ips = []
        is_registered = False

        # Query database registry
        db_service = db.execute(
            select(ServiceIdentity).where(ServiceIdentity.service_id == event.service_identity)
        ).scalar_one_or_none()

        if db_service:
            is_registered = True
            if db_service.allowed_ips:
                allowed_ips.extend([ip.strip() for ip in db_service.allowed_ips.split(",") if ip.strip()])

        # Check simulated service policies
        policy = SIMULATED_SERVICE_POLICIES.get(event.service_identity)
        if policy:
            is_registered = True
            allowed_ips.extend(policy.get("allowed_ips", []))

        # Deduplicate allowed IP list
        allowed_ips = list(set(allowed_ips))

        # Check for unconfigured service: Do NOT treat as automatically trusted!
        if not is_registered or not allowed_ips:
            modifiers = [
                {"factor": "unregistered_or_unconfigured_service", "points": +15, "reason": "No allowed IP baseline exists"}
            ]
            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)
            
            explanation = (
                f"API event received from unconfigured service identity '{event.service_identity}' "
                f"from IP '{event.source_ip}'. System does not automatically trust unconfigured services."
            )
            
            evidence = {
                "service_identity": event.service_identity,
                "source_ip": event.source_ip,
                "is_registered_service": is_registered,
                "configured_allowed_ips": allowed_ips,
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

        # Check if source_ip is authorized
        is_allowed = is_ip_in_allowlist(event.source_ip, allowed_ips)
        if not is_allowed:
            modifiers = []
            try:
                ip_obj = ipaddress.ip_address(event.source_ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    modifiers.append({"factor": "external_public_ip", "points": +20, "reason": "IP originates from public internet"})
            except ValueError:
                modifiers.append({"factor": "malformed_ip", "points": +10, "reason": "Unparseable IP syntax"})

            score, severity, breakdown = evaluate_risk(self.base_risk_score, modifiers)

            explanation = (
                f"Service '{event.service_identity}' accessed API from unapproved IP '{event.source_ip}'. "
                f"Sanctioned perimeter: {allowed_ips}."
            )

            evidence = {
                "service_identity": event.service_identity,
                "source_ip": event.source_ip,
                "is_registered_service": is_registered,
                "configured_allowed_ips": allowed_ips,
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
