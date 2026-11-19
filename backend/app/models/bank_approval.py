"""
Database Models for Two-Person Vendor Bank Account Change Enforcement
Tables:
- vendor_bank_accounts: Active bank account records per vendor.
- bank_change_requests: Immutable change requests bound to SHA-256 fingerprints.
- bank_change_approvals: Independent human approvals cryptographically bound to the fingerprint.
- bank_approval_audit_logs: Complete audit trail of authorization events.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, String, Text, Integer, DateTime, ForeignKey,
    Index, UniqueConstraint, JSON
)
from sqlalchemy.orm import relationship

from sentinel.backend.app.models.base import Base


def utc_now() -> datetime:
    """Helper returning timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class VendorBankAccount(Base):
    """
    Vendor Bank Account Master Record.
    Guarantees exactly one active bank account per vendor.
    Details at rest are encrypted with authenticated Fernet/AES.
    """
    __tablename__ = "vendor_bank_accounts"

    vendor_id = Column(String(64), primary_key=True, index=True)
    vendor_name = Column(String(128), nullable=False)
    active_bank_account_ref = Column(String(64), nullable=False)  # Masked e.g. ACC-***masked***1048
    encrypted_bank_details = Column(Text, nullable=False)        # Authenticated encrypted JSON
    bank_name = Column(String(128), nullable=False)
    routing_number_masked = Column(String(64), nullable=False)
    version = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    def __repr__(self) -> str:
        return f"<VendorBankAccount(vendor_id='{self.vendor_id}', ref='{self.active_bank_account_ref}', v={self.version})>"


class BankChangeRequest(Base):
    """
    Immutable Bank Account Change Request.
    Lifecycle:
    PENDING_APPROVAL -> PARTIALLY_APPROVED -> APPROVED -> COMMITTED
    or REJECTED / CANCELLED / EXPIRED.
    """
    __tablename__ = "bank_change_requests"

    request_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vendor_id = Column(String(64), ForeignKey("vendor_bank_accounts.vendor_id"), nullable=False, index=True)
    requester_id = Column(String(64), nullable=False, index=True)
    old_bank_account_ref = Column(String(64), nullable=False)
    proposed_bank_account_ref = Column(String(64), nullable=False)
    proposed_bank_name = Column(String(128), nullable=False)
    proposed_routing_masked = Column(String(64), nullable=False)
    encrypted_proposed_bank_details = Column(Text, nullable=False)
    request_reason = Column(Text, nullable=False)
    status = Column(String(32), default="PENDING_APPROVAL", nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    version = Column(Integer, default=1, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    rejection_reason = Column(Text, nullable=True)
    cancelled_by = Column(String(64), nullable=True)

    # Relationships
    vendor = relationship("VendorBankAccount", backref="change_requests")
    approvals = relationship("BankApproval", back_populates="request", cascade="all, delete-orphan", order_by="BankApproval.approval_order")
    audit_logs = relationship("ApprovalAuditLog", back_populates="request", cascade="all, delete-orphan", order_by="ApprovalAuditLog.created_at")

    __table_args__ = (
        Index("ix_bank_req_vendor_status", "vendor_id", "status"),
        Index("ix_bank_req_fingerprint_status", "fingerprint", "status"),
    )

    def __repr__(self) -> str:
        return f"<BankChangeRequest(id='{self.request_id}', vendor='{self.vendor_id}', status='{self.status}', v={self.version})>"


class BankApproval(Base):
    """
    Human Approver Authorization Record.
    Enforces that two distinct approvers must approve the exact cryptographic fingerprint.
    """
    __tablename__ = "bank_change_approvals"

    approval_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(36), ForeignKey("bank_change_requests.request_id", ondelete="CASCADE"), nullable=False, index=True)
    approver_id = Column(String(64), nullable=False, index=True)
    decision = Column(String(16), default="APPROVE", nullable=False)  # APPROVE, REJECT
    approval_order = Column(Integer, nullable=False)                   # 1 for first approval, 2 for second
    fingerprint_approved = Column(String(64), nullable=False)         # SHA-256 fingerprint verified at sign-off
    comment = Column(Text, nullable=True)
    auth_context = Column(JSON, nullable=True)                        # Context: role, auth_method, ip
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    request = relationship("BankChangeRequest", back_populates="approvals")

    __table_args__ = (
        # Same approver can never approve the same request twice
        UniqueConstraint("request_id", "approver_id", name="uq_bank_request_approver"),
        Index("ix_bank_approval_req_order", "request_id", "approval_order"),
    )

    def __repr__(self) -> str:
        return f"<BankApproval(id='{self.approval_id}', approver='{self.approver_id}', order={self.approval_order})>"


class ApprovalAuditLog(Base):
    """
    Immutable Audit Log for all Authorization Actions.
    Zero raw bank account numbers are stored in evidence metadata.
    """
    __tablename__ = "bank_approval_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(36), ForeignKey("bank_change_requests.request_id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = Column(String(64), nullable=False, index=True)
    action = Column(String(32), nullable=False, index=True)  # CREATE_REQUEST, FIRST_APPROVAL, SECOND_APPROVAL, COMMIT_CHANGE, REJECT_REQUEST, CANCEL_REQUEST, EXPIRED, TAMPER_DETECTED
    result = Column(String(16), nullable=False)              # SUCCESS, DENIED, FAILURE
    evidence = Column(JSON, nullable=True)                   # Masked metadata evidence
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    request = relationship("BankChangeRequest", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<ApprovalAuditLog(action='{self.action}', actor='{self.actor_id}', result='{self.result}')>"
