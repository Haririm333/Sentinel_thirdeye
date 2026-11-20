"""
Pydantic Schemas for Two-Person Vendor Bank Approval Workflow
Ensures:
- Strict input validation on submission.
- Complete masking of account numbers and routing codes in all responses.
- No plain account numbers or raw secrets in output schemas.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, AliasChoices


class CreateBankChangeRequest(BaseModel):
    """Payload to initiate a vendor bank account change request."""
    vendor_id: str = Field(..., min_length=2, max_length=64, examples=["vnd_10482"])
    proposed_account_number: str = Field(
        ...,
        min_length=6,
        max_length=34,
        description="Raw bank account / IBAN (will be masked and encrypted immediately).",
        validation_alias=AliasChoices("proposed_account_number", "proposed_bank_account")
    )
    proposed_bank_name: str = Field(..., min_length=2, max_length=128, examples=["JPMorgan Chase & Co."])
    proposed_routing_number: str = Field(..., min_length=4, max_length=32, examples=["021000021"])
    request_reason: str = Field(..., min_length=5, max_length=500, examples=["Vendor formal notice of banking partner change"])

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class ModifyBankChangeRequest(BaseModel):
    """Payload to modify an existing bank change request before final commitment."""
    proposed_account_number: str = Field(
        ...,
        min_length=6,
        max_length=34,
        description="Raw bank account / IBAN (will be masked and encrypted immediately).",
        validation_alias=AliasChoices("proposed_account_number", "proposed_bank_account")
    )
    proposed_bank_name: str = Field(..., min_length=2, max_length=128, examples=["JPMorgan Chase & Co."])
    proposed_routing_number: str = Field(..., min_length=4, max_length=32, examples=["021000021"])
    request_reason: str = Field(..., min_length=5, max_length=500, examples=["Updated vendor bank account"])

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class ApprovalActionRequest(BaseModel):
    """Payload for approver authorization decision."""
    comment: Optional[str] = Field(
        default=None,
        max_length=500,
        examples=["Verified with vendor CFO via out-of-band phone call."],
        validation_alias=AliasChoices("comment", "notes")
    )

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class RejectActionRequest(BaseModel):
    """Payload for rejecting a change request."""
    reason: str = Field(..., min_length=5, max_length=500, examples=["Discrepancy in beneficiary documentation; verification failed."])

    model_config = ConfigDict(extra="forbid")


class CancelActionRequest(BaseModel):
    """Payload for requester or admin cancellation."""
    reason: Optional[str] = Field(default=None, max_length=500, examples=["Duplicate submission cancelled by requester."])

    model_config = ConfigDict(extra="forbid")


class ApprovalSummaryResponse(BaseModel):
    """Public summary of an individual human approval."""
    approval_id: str
    approver_id: str
    decision: str
    approval_order: int
    fingerprint_approved: str
    comment: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BankChangeResponse(BaseModel):
    """Public masked representation of a bank change request."""
    request_id: str
    vendor_id: str
    requester_id: str
    old_bank_account_ref: str
    proposed_bank_account_ref: str
    proposed_bank_name: str
    proposed_routing_masked: str
    request_reason: str
    status: str
    fingerprint: str
    version: int
    approval_count: int = 0
    approvals: List[ApprovalSummaryResponse] = []
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    rejection_reason: Optional[str] = None
    cancelled_by: Optional[str] = None
    linked_incident_ids: List[str] = []
    risk_assessment_snapshot: Optional[Dict[str, Any]] = None
    security_warnings: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    """Audit log entry for authorization history."""
    id: int
    request_id: str
    actor_id: str
    action: str
    result: str
    evidence: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VendorBankAccountResponse(BaseModel):
    """Active vendor bank details (masked for safe display)."""
    vendor_id: str
    vendor_name: str
    active_bank_account_ref: str
    bank_name: str
    routing_number_masked: str
    version: int
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
