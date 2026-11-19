"""
Central Detection Configuration for SENTINEL
Provides configurable thresholds, service permissions, and scope definitions.
All identities, IP addresses, and thresholds here are SIMULATED DEVELOPMENT CONFIGURATION.
"""

from typing import Dict, List, Any
from pydantic import BaseModel, Field


class DetectionEngineSettings(BaseModel):
    """
    Configurable detection thresholds and correlation parameters.
    Can be adjusted without modifying rule logic.
    """
    # Global incident correlation / deduplication window
    CORRELATION_WINDOW_SECONDS: int = Field(
        default=600,
        description="Time window in seconds to correlate and merge repeated rule firings into one incident."
    )

    # Rule 1: Excessive API Request Rate
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, description="Sliding window in seconds.")
    RATE_LIMIT_THRESHOLD_COUNT: int = Field(default=20, description="Max requests permitted in window.")

    # Rule 2: Bulk Vendor Data Access
    BULK_SINGLE_RESPONSE_BYTES_THRESHOLD: int = Field(
        default=5_000_000,
        description="Threshold in bytes (5 MB) for a single bulk vendor data response."
    )
    BULK_WINDOW_SECONDS: int = Field(default=300, description="Window in seconds for repeated bulk accesses.")
    BULK_WINDOW_RECORD_COUNT_THRESHOLD: int = Field(
        default=10,
        description="Vendor records accessed within window before flagging repeated bulk access."
    )
    BULK_WINDOW_TOTAL_BYTES_THRESHOLD: int = Field(
        default=15_000_000,
        description="Total response volume (15 MB) within window before flagging repeated bulk access."
    )

    # Rule 3: Unexpected Source IP
    TREAT_UNCONFIGURED_SERVICE_AS_UNTRUSTED: bool = Field(
        default=True,
        description="If True, any service not in the registry is flagged for untrusted IP."
    )

    # Rule 4: Privilege & Scope Violation
    STRICT_SCOPE_ENFORCEMENT: bool = Field(default=True)

    # Rule 5: Sensitive Bank Account Modification
    SENSITIVE_BANK_ALERT_ENABLED: bool = Field(default=True)

    # Rule 6: Missing Approval Reference
    VALID_APPROVAL_REGEX: str = Field(
        default=r"^APP-\d{4}-\d{4,}$",
        description="Regex pattern for valid governance approval references (e.g. APP-2026-9812)."
    )


# ==============================================================================
# SIMULATED DEVELOPMENT SERVICE SCOPES AND PERMISSION POLICIES
# In production, these policies are loaded dynamically from an IAM directory
# or cryptographically signed policy bundle.
# ==============================================================================
SIMULATED_SERVICE_POLICIES: Dict[str, Dict[str, Any]] = {
    "srv-ledgerone-core": {
        "description": "LedgerOne Core Financial Management Service",
        "source_system": "LedgerOne",
        "allowed_methods": ["GET", "POST", "PUT"],
        "allowed_endpoints": [
            r"^/api/v1/vendors(/.*)?$",
            r"^/api/v1/payments(/.*)?$",
            r"^/api/v1/invoices(/.*)?$"
        ],
        "allowed_ips": ["10.0.1.0/24", "127.0.0.1"],
        "can_modify_bank_details": True,
        "is_read_only": False
    },
    "srv-ledgerone-paygate": {
        "description": "LedgerOne Payment Gateway Service",
        "source_system": "LedgerOne",
        "allowed_methods": ["GET", "POST"],
        "allowed_endpoints": [
            r"^/api/v1/payments(/.*)?$"
        ],
        "allowed_ips": ["10.0.1.0/24", "127.0.0.1"],
        "can_modify_bank_details": False,
        "is_read_only": False
    },
    "srv-helpdeskr-agent": {
        "description": "HelpDeskr Support Integration Service",
        "source_system": "HelpDeskr",
        "allowed_methods": ["GET", "POST", "PUT"],
        "allowed_endpoints": [
            r"^/api/v1/tickets(/.*)?$",
            r"^/api/v1/vendors/[^/]+/profile$",
            r"^/api/v1/users(/.*)?$"
        ],
        "allowed_ips": ["10.0.3.0/24", "127.0.0.1"],
        "can_modify_bank_details": False,
        "is_read_only": False
    },
    "srv-tallybridge-sync": {
        "description": "TallyBridge ERP Sync Connector",
        "source_system": "TallyBridge",
        "allowed_methods": ["GET", "POST"],
        "allowed_endpoints": [
            r"^/api/v1/sync(/.*)?$",
            r"^/api/v1/vendors$",
            r"^/api/v1/payments$"
        ],
        "allowed_ips": ["10.0.2.0/24", "127.0.0.1"],
        "can_modify_bank_details": False,
        "is_read_only": False
    },
    "srv-tallybridge-audit-ro": {
        "description": "TallyBridge Read-Only Audit Connector",
        "source_system": "TallyBridge",
        "allowed_methods": ["GET"],
        "allowed_endpoints": [
            r"^/api/v1/vendors(/.*)?$",
            r"^/api/v1/payments(/.*)?$"
        ],
        "allowed_ips": ["10.0.2.0/24", "127.0.0.1"],
        "can_modify_bank_details": False,
        "is_read_only": True
    }
}

# Singleton instance of detection settings
detection_settings = DetectionEngineSettings()
