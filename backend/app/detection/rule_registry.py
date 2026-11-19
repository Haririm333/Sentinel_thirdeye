"""
Rule Registry for SENTINEL Detection Engine
Maintains active security rules, dynamic toggling, and metadata query capabilities.
"""

from typing import Dict, List, Optional
from sentinel.backend.app.detection.base_rule import BaseDetectionRule


class RuleRegistry:
    """Registry maintaining instances of BaseDetectionRule."""
    def __init__(self):
        self._rules: Dict[str, BaseDetectionRule] = {}
        self._register_default_rules()

    def _register_default_rules(self):
        """Instantiate and register all Phase 2 security rules."""
        from sentinel.backend.app.detection.rules import (
            ExcessiveRequestRateRule,
            BulkVendorAccessRule,
            UnexpectedSourceIPRule,
            PrivilegeViolationRule,
            SensitiveBankChangeRule,
            MissingApprovalRule
        )
        rules = [
            ExcessiveRequestRateRule(),
            BulkVendorAccessRule(),
            UnexpectedSourceIPRule(),
            PrivilegeViolationRule(),
            SensitiveBankChangeRule(),
            MissingApprovalRule()
        ]
        for rule in rules:
            self.register_rule(rule)

    def register_rule(self, rule: BaseDetectionRule) -> None:
        """Register a detection rule instance."""
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[BaseDetectionRule]:
        """Fetch a registered rule by its rule_id."""
        return self._rules.get(rule_id)

    def list_rules(self) -> List[BaseDetectionRule]:
        """Return list of all registered rules."""
        return list(self._rules.values())

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        if rule_id in self._rules:
            self._rules[rule_id].is_enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        if rule_id in self._rules:
            self._rules[rule_id].is_enabled = False
            return True
        return False


# Global singleton registry
rule_registry = RuleRegistry()
