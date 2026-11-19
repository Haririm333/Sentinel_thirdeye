"""
Two-Person Vendor Bank Change Authorization and Atomic Enforcement Service
Enforces:
1. Strict Two-Person Rule: Two distinct authorized human approvers must approve.
2. Anti-Self-Approval: The requester can never approve their own request.
3. Anti-Duplicate: The same approver cannot approve twice.
4. Cryptographic Binding: Approvals are bound to a canonical SHA-256 fingerprint.
5. Atomic Commitment: Row-level locking ensures atomic update; old bank details remain active until step 8 commits.
6. Incident Engine Correlation: Connects requests to SENTINEL detection incidents without AI override.
"""

import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_
from fastapi import HTTPException, status

from sentinel.backend.app.config import get_settings
from sentinel.backend.app.models.bank_approval import (
    VendorBankAccount,
    BankChangeRequest,
    BankApproval,
    ApprovalAuditLog
)
from sentinel.backend.app.security.auth import User
from sentinel.backend.app.security.bank_crypto import (
    encrypt_bank_payload,
    decrypt_bank_payload,
    mask_account_number,
    mask_routing_number,
    compute_change_fingerprint
)
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.detection.base_rule import DetectionResult
from sentinel.backend.app.services.incident_service import create_or_update_incident

logger = logging.getLogger("sentinel.bank_approval")

# Standard Baseline Vendors
DEFAULT_BASELINE_VENDORS = {
    "vnd_10482": {
        "vendor_name": "Acme Industrial Supplies LLC",
        "account_num": "987654321048",
        "bank_name": "JPMorgan Chase & Co.",
        "routing": "021000021"
    },
    "vnd_10483": {
        "vendor_name": "Global Cloud Logistics Corp",
        "account_num": "442198001123",
        "bank_name": "Bank of America NA",
        "routing": "026009593"
    },
    "vnd_20491": {
        "vendor_name": "Starlight Enterprise Consulting",
        "account_num": "881200948291",
        "bank_name": "Wells Fargo Bank NA",
        "routing": "121000247"
    }
}


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def record_approval_audit(
    db: Session,
    request_id: str,
    actor_id: str,
    action: str,
    result: str,
    evidence: Optional[Dict[str, Any]] = None
) -> ApprovalAuditLog:
    """
    Record an immutable audit log entry.
    Strictly guarantees zero plaintext bank account numbers in evidence.
    """
    audit = ApprovalAuditLog(
        request_id=request_id,
        actor_id=actor_id,
        action=action,
        result=result,
        evidence=evidence or {},
        created_at=utc_now()
    )
    db.add(audit)
    return audit


def get_or_init_vendor(db: Session, vendor_id: str) -> VendorBankAccount:
    """
    Retrieve active vendor bank record or initialize from enterprise baseline directory.
    Guarantees exactly one active bank account per vendor.
    """
    stmt = select(VendorBankAccount).where(VendorBankAccount.vendor_id == vendor_id)
    vendor = db.execute(stmt).scalar_one_or_none()

    if not vendor:
        seed = DEFAULT_BASELINE_VENDORS.get(vendor_id, {
            "vendor_name": f"Vendor {vendor_id}",
            "account_num": "112233445566",
            "bank_name": "Standard Chartered Bank",
            "routing": "021000021"
        })
        masked_acc = mask_account_number(seed["account_num"])
        masked_rout = mask_routing_number(seed["routing"])
        encrypted_details = encrypt_bank_payload({
            "vendor_id": vendor_id,
            "account_number": seed["account_num"],
            "bank_name": seed["bank_name"],
            "routing_number": seed["routing"]
        })

        vendor = VendorBankAccount(
            vendor_id=vendor_id,
            vendor_name=seed["vendor_name"],
            active_bank_account_ref=masked_acc,
            encrypted_bank_details=encrypted_details,
            bank_name=seed["bank_name"],
            routing_number_masked=masked_rout,
            version=1,
            created_at=utc_now(),
            updated_at=utc_now()
        )
        db.add(vendor)
        db.commit()
        db.refresh(vendor)

    return vendor


def create_bank_change_request(
    db: Session,
    requester: User,
    vendor_id: str,
    proposed_account_number: str,
    proposed_bank_name: str,
    proposed_routing_number: str,
    request_reason: str,
    client_ip: str = "127.0.0.1"
) -> BankChangeRequest:
    """
    Submit a bank change request.
    Validates requester role, masks references, encrypts details at rest,
    computes canonical SHA-256 fingerprint, and initializes status PENDING_APPROVAL.
    """
    settings = get_settings()

    # 1. Authorize requester role
    if not requester.has_any_role(["REQUESTER", "FINANCE_ADMIN"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AccessDenied", "message": "Only authorized REQUESTER or FINANCE_ADMIN users may submit bank changes."}
        )

    # 2. Acquire active vendor bank record
    vendor = get_or_init_vendor(db, vendor_id)

    # 3. Check for existing pending requests on this vendor
    pending_stmt = select(BankChangeRequest).where(
        and_(
            BankChangeRequest.vendor_id == vendor_id,
            BankChangeRequest.status.in_(["PENDING_APPROVAL", "PARTIALLY_APPROVED"])
        )
    )
    existing_pending = db.execute(pending_stmt).scalars().all()
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "PendingRequestExists",
                "message": f"Vendor '{vendor_id}' already has a pending change request ({existing_pending[0].request_id}). Complete or cancel it first."
            }
        )

    # 4. Mask and encrypt proposed bank details
    proposed_ref = mask_account_number(proposed_account_number)
    proposed_routing_masked = mask_routing_number(proposed_routing_number)

    encrypted_proposed = encrypt_bank_payload({
        "vendor_id": vendor_id,
        "account_number": proposed_account_number,
        "bank_name": proposed_bank_name,
        "routing_number": proposed_routing_number,
        "requester_id": requester.user_id
    })

    # 5. Compute cryptographic change fingerprint (version 1)
    version = 1
    fingerprint = compute_change_fingerprint(
        vendor_id=vendor.vendor_id,
        old_account_ref=vendor.active_bank_account_ref,
        proposed_account_ref=proposed_ref,
        proposed_bank_name=proposed_bank_name,
        proposed_routing_masked=proposed_routing_masked,
        requester_id=requester.user_id,
        version=version
    )

    request_id = str(uuid.uuid4())
    expires_at = utc_now() + timedelta(hours=settings.BANK_CHANGE_EXPIRY_HOURS)

    # 6. Instantiate and persist request
    change_request = BankChangeRequest(
        request_id=request_id,
        vendor_id=vendor.vendor_id,
        requester_id=requester.user_id,
        old_bank_account_ref=vendor.active_bank_account_ref,
        proposed_bank_account_ref=proposed_ref,
        proposed_bank_name=proposed_bank_name,
        proposed_routing_masked=proposed_routing_masked,
        encrypted_proposed_bank_details=encrypted_proposed,
        request_reason=request_reason,
        status="PENDING_APPROVAL",
        fingerprint=fingerprint,
        version=version,
        created_at=utc_now(),
        updated_at=utc_now(),
        expires_at=expires_at
    )
    db.add(change_request)

    # 7. Record immutable audit log
    record_approval_audit(
        db=db,
        request_id=request_id,
        actor_id=requester.user_id,
        action="CREATE_REQUEST",
        result="SUCCESS",
        evidence={
            "vendor_id": vendor_id,
            "old_account_ref": vendor.active_bank_account_ref,
            "proposed_account_ref": proposed_ref,
            "fingerprint": fingerprint,
            "client_ip": client_ip,
            "expires_at": expires_at.isoformat()
        }
    )

    # 8. SENTINEL Incident Engine Integration
    # Log sensitive banking operation event
    try:
        detection_res = DetectionResult(
            triggered=True,
            rule_id="SEC-RULE-BANK-001",
            rule_name="Sensitive Bank Account Modification",
            severity="HIGH",
            risk_score=75,
            explanation=(
                f"Two-person approval initiated for vendor '{vendor_id}' bank account modification "
                f"by requester '{requester.user_id}'. Request ID: {request_id}. Status: PENDING_APPROVAL."
            ),
            evidence={
                "bank_change_request_id": request_id,
                "vendor_id": vendor_id,
                "requester_id": requester.user_id,
                "approval_workflow_status": "PENDING_APPROVAL",
                "approvals_completed": 0,
                "approvals_required": settings.BANK_APPROVALS_REQUIRED,
                "scoring_breakdown": {
                    "base_score": 75,
                    "modifiers": [],
                    "final_score": 75,
                    "severity": "HIGH"
                }
            },
            resource_type="BANK_ACCOUNT",
            resource_id=proposed_ref
        )
        synth_event = ApiEvent(
            event_id=f"evt-bank-{request_id[:8]}",
            source_system="LedgerOne",
            service_identity="srv-ledgerone-core",
            endpoint="/api/v1/bank-changes",
            http_method="POST",
            http_status_code=201,
            source_ip=client_ip,
            auth_identity=requester.user_id,
            action="CREATE_BANK_CHANGE_REQUEST",
            resource_type="BANK_ACCOUNT",
            resource_id=proposed_ref,
            request_size_bytes=256,
            response_size_bytes=512,
            timestamp=utc_now()
        )
        create_or_update_incident(db=db, result=detection_res, event=synth_event)
    except Exception as exc:
        logger.warning("Incident engine correlation logged warning: %s", exc)

    db.commit()
    db.refresh(change_request)
    logger.info("Created BankChangeRequest %s for vendor %s by %s", request_id, vendor_id, requester.user_id)
    return change_request


def approve_bank_change_request(
    db: Session,
    request_id: str,
    approver: User,
    comment: Optional[str] = None,
    client_ip: str = "127.0.0.1"
) -> BankChangeRequest:
    """
    Execute human approval with atomic database concurrency locking.
    Enforces:
    - No self-approval (requester cannot approve).
    - No duplicate approval (same approver cannot approve twice).
    - Cryptographic fingerprint match.
    - Two distinct approvals required before atomic commit.
    - Old bank account remains active until second approval commits.
    """
    settings = get_settings()

    # 1. Acquire row-level lock on BankChangeRequest within transaction
    # with_for_update() serializes concurrent approval attempts safely
    stmt = (
        select(BankChangeRequest)
        .where(BankChangeRequest.request_id == request_id)
        .with_for_update()
    )
    change_req = db.execute(stmt).scalar_one_or_none()

    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' does not exist."}
        )

    # 2. Check Expiration
    now = utc_now()
    exp = change_req.expires_at
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and exp < now and change_req.status in ("PENDING_APPROVAL", "PARTIALLY_APPROVED"):
        change_req.status = "EXPIRED"
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="EXPIRE_REQUEST",
            result="FAILURE",
            evidence={"reason": "Approval window expired", "expired_at": change_req.expires_at.isoformat()}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "RequestExpired", "message": "This bank change request has expired and cannot be approved."}
        )

    # 3. Check Legal Status Transition
    if change_req.status not in ("PENDING_APPROVAL", "PARTIALLY_APPROVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "InvalidStatusTransition",
                "message": f"Cannot approve request in '{change_req.status}' status. Only PENDING_APPROVAL or PARTIALLY_APPROVED requests can be approved."
            }
        )

    # 4. Anti-Self-Approval Enforcement
    if approver.user_id == change_req.requester_id:
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="FIRST_APPROVAL" if change_req.status == "PENDING_APPROVAL" else "SECOND_APPROVAL",
            result="DENIED",
            evidence={"reason": "Self-approval violation: requester attempted approval", "actor": approver.user_id}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "SelfApprovalProhibited",
                "message": "Security policy violation: The requester cannot approve their own bank change request."
            }
        )

    # 5. Role-Based Approver Authorization
    if not approver.has_any_role(["FINANCE_APPROVER", "FINANCE_ADMIN"]):
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="APPROVE",
            result="DENIED",
            evidence={"reason": "User does not have FINANCE_APPROVER role", "roles": approver.roles}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AccessDenied", "message": "Approver must possess FINANCE_APPROVER or FINANCE_ADMIN role."}
        )

    # 6. Anti-Duplicate Approver Enforcement
    existing_approvals = change_req.approvals
    existing_approver_ids = {appr.approver_id for appr in existing_approvals}
    if approver.user_id in existing_approver_ids:
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="SECOND_APPROVAL",
            result="DENIED",
            evidence={"reason": "Duplicate approver violation: user already approved", "actor": approver.user_id}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "DuplicateApprovalProhibited",
                "message": f"User '{approver.user_id}' has already approved this request. Two distinct approvers are required."
            }
        )

    # 7. Cryptographic Fingerprint Verification (Tamper / Invalidation Detection)
    expected_fingerprint = compute_change_fingerprint(
        vendor_id=change_req.vendor_id,
        old_account_ref=change_req.old_bank_account_ref,
        proposed_account_ref=change_req.proposed_bank_account_ref,
        proposed_bank_name=change_req.proposed_bank_name,
        proposed_routing_masked=change_req.proposed_routing_masked,
        requester_id=change_req.requester_id,
        version=change_req.version
    )
    if change_req.fingerprint != expected_fingerprint:
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="TAMPER_DETECTED",
            result="FAILURE",
            evidence={"stored_fingerprint": change_req.fingerprint, "computed_fingerprint": expected_fingerprint}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "FingerprintMismatch",
                "message": "Security integrity failure: Request cryptographic fingerprint mismatch. Request has been modified or tampered."
            }
        )

    # 8. Record Approval Record
    current_approval_count = len(existing_approvals) + 1
    new_approval = BankApproval(
        approval_id=str(uuid.uuid4()),
        request_id=change_req.request_id,
        approver_id=approver.user_id,
        decision="APPROVE",
        approval_order=current_approval_count,
        fingerprint_approved=change_req.fingerprint,
        comment=comment,
        auth_context={
            "roles": approver.roles,
            "auth_method": approver.auth_method,
            "client_ip": client_ip
        },
        created_at=utc_now()
    )
    db.add(new_approval)
    db.flush()

    # 9. Lifecycle Transition & Atomic Commit Execution
    if current_approval_count < settings.BANK_APPROVALS_REQUIRED:
        # First approval: update to PARTIALLY_APPROVED
        change_req.status = "PARTIALLY_APPROVED"
        change_req.updated_at = utc_now()
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="FIRST_APPROVAL",
            result="SUCCESS",
            evidence={
                "approval_order": 1,
                "approver": approver.user_id,
                "comment": comment,
                "status": "PARTIALLY_APPROVED"
            }
        )
        db.commit()
        db.refresh(change_req)
        logger.info("Request %s reached FIRST_APPROVAL by %s", request_id, approver.user_id)
        return change_req

    else:
        # Second approval: STRICT ATOMIC COMMIT
        # Re-validate that two distinct approver identities exist
        all_approvers = {a.approver_id for a in change_req.approvals}
        all_approvers.add(approver.user_id)
        if len(all_approvers) < settings.BANK_APPROVALS_REQUIRED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "TwoPersonRuleViolation", "message": "Two distinct human approvers required."}
            )

        # Row-lock active vendor record to update atomically
        vendor_stmt = (
            select(VendorBankAccount)
            .where(VendorBankAccount.vendor_id == change_req.vendor_id)
            .with_for_update()
        )
        vendor = db.execute(vendor_stmt).scalar_one_or_none()
        if not vendor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "VendorNotFound", "message": f"Vendor '{change_req.vendor_id}' not found."}
            )

        # ATOMIC COMMIT: update active bank details
        vendor.active_bank_account_ref = change_req.proposed_bank_account_ref
        vendor.encrypted_bank_details = change_req.encrypted_proposed_bank_details
        vendor.bank_name = change_req.proposed_bank_name
        vendor.routing_number_masked = change_req.proposed_routing_masked
        vendor.version += 1
        vendor.updated_at = utc_now()

        change_req.status = "COMMITTED"
        change_req.updated_at = utc_now()

        # Audit logs for final authorization and commit
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id=approver.user_id,
            action="SECOND_APPROVAL",
            result="SUCCESS",
            evidence={
                "approval_order": 2,
                "approver": approver.user_id,
                "comment": comment
            }
        )
        record_approval_audit(
            db=db,
            request_id=request_id,
            actor_id="SYSTEM",
            action="COMMIT_CHANGE",
            result="SUCCESS",
            evidence={
                "vendor_id": vendor.vendor_id,
                "active_account_ref": vendor.active_bank_account_ref,
                "vendor_version": vendor.version,
                "approved_by": list(all_approvers)
            }
        )

        db.commit()
        db.refresh(change_req)
        logger.info(
            "Request %s COMMITTED successfully. Vendor %s updated to %s",
            request_id, vendor.vendor_id, vendor.active_bank_account_ref
        )
        return change_req


def reject_bank_change_request(
    db: Session,
    request_id: str,
    approver: User,
    reason: str,
    client_ip: str = "127.0.0.1"
) -> BankChangeRequest:
    """
    Reject a pending or partially approved change request.
    Old bank details remain completely active.
    """
    stmt = (
        select(BankChangeRequest)
        .where(BankChangeRequest.request_id == request_id)
        .with_for_update()
    )
    change_req = db.execute(stmt).scalar_one_or_none()

    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' not found."}
        )

    if not approver.has_any_role(["FINANCE_APPROVER", "FINANCE_ADMIN"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AccessDenied", "message": "Only FINANCE_APPROVER or FINANCE_ADMIN users may reject change requests."}
        )

    if change_req.status not in ("PENDING_APPROVAL", "PARTIALLY_APPROVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "InvalidStatusTransition", "message": f"Cannot reject request in '{change_req.status}' status."}
        )

    change_req.status = "REJECTED"
    change_req.rejection_reason = reason
    change_req.updated_at = utc_now()

    record_approval_audit(
        db=db,
        request_id=request_id,
        actor_id=approver.user_id,
        action="REJECT_REQUEST",
        result="SUCCESS",
        evidence={"rejected_by": approver.user_id, "reason": reason, "client_ip": client_ip}
    )

    db.commit()
    db.refresh(change_req)
    return change_req


def cancel_bank_change_request(
    db: Session,
    request_id: str,
    user: User,
    reason: Optional[str] = None,
    client_ip: str = "127.0.0.1"
) -> BankChangeRequest:
    """
    Cancel a pending change request.
    Only the original requester or a FINANCE_ADMIN can cancel.
    """
    stmt = (
        select(BankChangeRequest)
        .where(BankChangeRequest.request_id == request_id)
        .with_for_update()
    )
    change_req = db.execute(stmt).scalar_one_or_none()

    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' not found."}
        )

    if user.user_id != change_req.requester_id and not user.has_role("FINANCE_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AccessDenied", "message": "Only the original requester or a FINANCE_ADMIN can cancel this request."}
        )

    if change_req.status not in ("PENDING_APPROVAL", "PARTIALLY_APPROVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "InvalidStatusTransition", "message": f"Cannot cancel request in '{change_req.status}' status."}
        )

    change_req.status = "CANCELLED"
    change_req.cancelled_by = user.user_id
    change_req.updated_at = utc_now()

    record_approval_audit(
        db=db,
        request_id=request_id,
        actor_id=user.user_id,
        action="CANCEL_REQUEST",
        result="SUCCESS",
        evidence={"cancelled_by": user.user_id, "reason": reason, "client_ip": client_ip}
    )

    db.commit()
    db.refresh(change_req)
    return change_req


def modify_change_request(
    db: Session,
    request_id: str,
    user: User,
    proposed_account_number: str,
    proposed_bank_name: str,
    proposed_routing_number: str,
    request_reason: str,
    client_ip: str = "127.0.0.1"
) -> BankChangeRequest:
    """
    Modify an existing change request.
    Enforces Section 5 requirements:
    - Increments request version.
    - Invalidates / deletes previous approvals.
    - Recalculates cryptographic fingerprint.
    - Resets status to PENDING_APPROVAL.
    - Requires both approvals again.
    """
    stmt = (
        select(BankChangeRequest)
        .where(BankChangeRequest.request_id == request_id)
        .with_for_update()
    )
    change_req = db.execute(stmt).scalar_one_or_none()

    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' not found."}
        )

    if user.user_id != change_req.requester_id and not user.has_role("FINANCE_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AccessDenied", "message": "Only the original requester or a FINANCE_ADMIN can modify this request."}
        )

    if change_req.status not in ("PENDING_APPROVAL", "PARTIALLY_APPROVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "InvalidStatusTransition", "message": f"Cannot modify request in '{change_req.status}' status."}
        )

    # Invalidate previous approvals
    had_approvals = len(change_req.approvals) > 0
    change_req.approvals.clear()

    # Increment version
    change_req.version += 1

    # Re-encrypt and re-mask
    proposed_ref = mask_account_number(proposed_account_number)
    proposed_routing_masked = mask_routing_number(proposed_routing_number)

    encrypted_proposed = encrypt_bank_payload({
        "vendor_id": change_req.vendor_id,
        "account_number": proposed_account_number,
        "bank_name": proposed_bank_name,
        "routing_number": proposed_routing_number,
        "requester_id": change_req.requester_id
    })

    # Recalculate fingerprint with new version and parameters
    new_fingerprint = compute_change_fingerprint(
        vendor_id=change_req.vendor_id,
        old_account_ref=change_req.old_bank_account_ref,
        proposed_account_ref=proposed_ref,
        proposed_bank_name=proposed_bank_name,
        proposed_routing_masked=proposed_routing_masked,
        requester_id=change_req.requester_id,
        version=change_req.version
    )

    change_req.proposed_bank_account_ref = proposed_ref
    change_req.proposed_bank_name = proposed_bank_name
    change_req.proposed_routing_masked = proposed_routing_masked
    change_req.encrypted_proposed_bank_details = encrypted_proposed
    change_req.request_reason = request_reason
    change_req.fingerprint = new_fingerprint
    change_req.status = "PENDING_APPROVAL"
    change_req.updated_at = utc_now()

    record_approval_audit(
        db=db,
        request_id=request_id,
        actor_id=user.user_id,
        action="MODIFY_REQUEST",
        result="SUCCESS",
        evidence={
            "new_version": change_req.version,
            "new_fingerprint": new_fingerprint,
            "invalidated_previous_approvals": had_approvals,
            "client_ip": client_ip
        }
    )

    db.commit()
    db.refresh(change_req)
    return change_req


def get_change_request_by_id(db: Session, request_id: str) -> Optional[BankChangeRequest]:
    """Retrieve change request with eager-loaded approvals."""
    stmt = (
        select(BankChangeRequest)
        .where(BankChangeRequest.request_id == request_id)
    )
    return db.execute(stmt).scalar_one_or_none()


def list_change_requests(
    db: Session,
    vendor_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    page: int = 1,
    limit: int = 20
) -> Tuple[int, List[BankChangeRequest]]:
    """Retrieve change requests matching filters with pagination."""
    conditions = []
    if vendor_id:
        conditions.append(BankChangeRequest.vendor_id == vendor_id)
    if status_filter:
        conditions.append(BankChangeRequest.status == status_filter)

    query = select(BankChangeRequest).order_by(BankChangeRequest.created_at.desc())
    if conditions:
        query = query.where(and_(*conditions))

    # Count
    count_stmt = select(BankChangeRequest)
    if conditions:
        count_stmt = count_stmt.where(and_(*conditions))
    total = len(db.execute(count_stmt).scalars().all())

    items = db.execute(query.offset((page - 1) * limit).limit(limit)).scalars().all()
    return total, items


def get_audit_trail(db: Session, request_id: str) -> List[ApprovalAuditLog]:
    """Retrieve complete chronological audit log for a change request."""
    stmt = (
        select(ApprovalAuditLog)
        .where(ApprovalAuditLog.request_id == request_id)
        .order_by(ApprovalAuditLog.created_at.asc())
    )
    return list(db.execute(stmt).scalars().all())
