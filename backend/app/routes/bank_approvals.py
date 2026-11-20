"""
Two-Person Vendor Bank Change Approval REST API Endpoints
Endpoints:
- POST /api/v1/bank-changes: Submit a bank change request
- GET /api/v1/bank-changes: Query bank change requests with filters
- GET /api/v1/bank-changes/{request_id}: Get change request details
- POST /api/v1/bank-changes/{request_id}/approve: Authorize approval step
- POST /api/v1/bank-changes/{request_id}/reject: Reject change request
- POST /api/v1/bank-changes/{request_id}/cancel: Cancel change request
- GET /api/v1/bank-changes/{request_id}/audit: Complete audit history trail
- GET /api/v1/vendors/{vendor_id}/bank-account: Active vendor bank details
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from sentinel.backend.app.database import get_db
from sentinel.backend.app.security.auth import (
    User,
    authenticate_user,
    require_role
)
from sentinel.backend.app.schemas.bank_approval import (
    CreateBankChangeRequest,
    ModifyBankChangeRequest,
    ApprovalActionRequest,
    RejectActionRequest,
    CancelActionRequest,
    BankChangeResponse,
    ApprovalSummaryResponse,
    AuditLogResponse,
    VendorBankAccountResponse
)
from sentinel.backend.app.services.bank_approval_service import (
    create_bank_change_request,
    modify_change_request,
    approve_bank_change_request,
    reject_bank_change_request,
    cancel_bank_change_request,
    get_change_request_by_id,
    list_change_requests,
    get_audit_trail,
    get_or_init_vendor
)

router = APIRouter(prefix="/api/v1", tags=["Two-Person Bank Account Approvals"])


def _to_response_dict(req) -> dict:
    """Format BankChangeRequest ORM into safe public dictionary."""
    approvals = [
        ApprovalSummaryResponse(
            approval_id=a.approval_id,
            approver_id=a.approver_id,
            decision=a.decision,
            approval_order=a.approval_order,
            fingerprint_approved=a.fingerprint_approved,
            comment=a.comment,
            created_at=a.created_at
        )
        for a in req.approvals
    ]
    return {
        "request_id": req.request_id,
        "vendor_id": req.vendor_id,
        "requester_id": req.requester_id,
        "old_bank_account_ref": req.old_bank_account_ref,
        "proposed_bank_account_ref": req.proposed_bank_account_ref,
        "proposed_bank_name": req.proposed_bank_name,
        "proposed_routing_masked": req.proposed_routing_masked,
        "request_reason": req.request_reason,
        "status": req.status,
        "fingerprint": req.fingerprint,
        "version": req.version,
        "approval_count": len(approvals),
        "approvals": approvals,
        "created_at": req.created_at,
        "updated_at": req.updated_at,
        "expires_at": req.expires_at,
        "rejection_reason": req.rejection_reason,
        "cancelled_by": req.cancelled_by,
        "linked_incident_ids": getattr(req, "linked_incident_ids", []) or [],
        "risk_assessment_snapshot": getattr(req, "risk_assessment_snapshot", {}) or {},
        "security_warnings": (getattr(req, "risk_assessment_snapshot", {}) or {}).get("security_warnings", [])
    }


@router.post(
    "/bank-changes",
    response_model=BankChangeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Vendor Bank Account Change Request",
    description="Authorized requester submits a bank change request. Details are encrypted at rest."
)
def submit_bank_change(
    payload: CreateBankChangeRequest,
    request: Request,
    current_user: User = Depends(require_role(["REQUESTER", "FINANCE_ADMIN"])),
    db: Session = Depends(get_db)
):
    """Submit a bank change request entering PENDING_APPROVAL."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    change_req = create_bank_change_request(
        db=db,
        requester=current_user,
        vendor_id=payload.vendor_id,
        proposed_account_number=payload.proposed_account_number,
        proposed_bank_name=payload.proposed_bank_name,
        proposed_routing_number=payload.proposed_routing_number,
        request_reason=payload.request_reason,
        client_ip=client_ip
    )
    return _to_response_dict(change_req)


@router.get(
    "/bank-changes",
    summary="List Vendor Bank Account Change Requests",
    description="Retrieve paginated list of bank change requests with optional filters."
)
def get_bank_changes(
    vendor_id: Optional[str] = Query(None, description="Filter by vendor ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by request status"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """List change requests matching filters."""
    total, items = list_change_requests(
        db=db,
        vendor_id=vendor_id,
        status_filter=status_filter,
        page=page,
        limit=limit
    )
    pages = (total + limit - 1) // limit if total > 0 else 0
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages,
        "items": [_to_response_dict(item) for item in items]
    }


@router.get(
    "/bank-changes/{request_id}",
    response_model=BankChangeResponse,
    summary="Get Bank Change Request by ID",
    description="Retrieve detailed status and approval history for a specific request."
)
def get_bank_change(
    request_id: str,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve single bank change request."""
    change_req = get_change_request_by_id(db, request_id)
    if not change_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "RequestNotFound", "message": f"Bank change request '{request_id}' not found."}
        )
    return _to_response_dict(change_req)


@router.put(
    "/bank-changes/{request_id}",
    response_model=BankChangeResponse,
    summary="Modify Bank Change Request",
    description="Requester or admin modifies change request details. Invalidates prior approvals, increments version, and resets status to PENDING_APPROVAL."
)
def update_bank_change(
    request_id: str,
    payload: ModifyBankChangeRequest,
    request: Request,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Modify change request details, invalidate prior approvals, and reset to PENDING_APPROVAL."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    updated_req = modify_change_request(
        db=db,
        request_id=request_id,
        user=current_user,
        proposed_account_number=payload.proposed_account_number,
        proposed_bank_name=payload.proposed_bank_name,
        proposed_routing_number=payload.proposed_routing_number,
        request_reason=payload.request_reason,
        client_ip=client_ip
    )
    return _to_response_dict(updated_req)


@router.post(
    "/bank-changes/{request_id}/approve",
    response_model=BankChangeResponse,
    summary="Approve Bank Change Request (Human Authorization)",
    description="Authorized finance approver signs off on the request. Requires two independent approvers."
)
def approve_bank_change(
    request_id: str,
    payload: ApprovalActionRequest,
    request: Request,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Approve a bank change step. Commits atomically when 2 approvals are reached."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    updated_req = approve_bank_change_request(
        db=db,
        request_id=request_id,
        approver=current_user,
        comment=payload.comment,
        client_ip=client_ip
    )
    return _to_response_dict(updated_req)


@router.post(
    "/bank-changes/{request_id}/reject",
    response_model=BankChangeResponse,
    summary="Reject Bank Change Request",
    description="Reject a pending bank change. Old bank details remain active."
)
def reject_bank_change(
    request_id: str,
    payload: RejectActionRequest,
    request: Request,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Reject change request."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    rejected_req = reject_bank_change_request(
        db=db,
        request_id=request_id,
        approver=current_user,
        reason=payload.reason,
        client_ip=client_ip
    )
    return _to_response_dict(rejected_req)


@router.post(
    "/bank-changes/{request_id}/cancel",
    response_model=BankChangeResponse,
    summary="Cancel Bank Change Request",
    description="Requester or admin cancels a pending bank change."
)
def cancel_bank_change(
    request_id: str,
    request: Request,
    payload: Optional[CancelActionRequest] = None,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Cancel change request."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    reason = payload.reason if payload else None
    cancelled_req = cancel_bank_change_request(
        db=db,
        request_id=request_id,
        user=current_user,
        reason=reason,
        client_ip=client_ip
    )
    return _to_response_dict(cancelled_req)


@router.get(
    "/bank-changes/{request_id}/audit",
    response_model=List[AuditLogResponse],
    summary="Get Bank Change Audit History",
    description="Retrieve complete immutable audit trail for a change request."
)
def get_bank_change_audit(
    request_id: str,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve audit trail for request."""
    logs = get_audit_trail(db, request_id)
    return logs


@router.get(
    "/vendors/{vendor_id}/bank-account",
    response_model=VendorBankAccountResponse,
    summary="Get Active Vendor Bank Account",
    description="Retrieve current active bank account details for a vendor (masked)."
)
def get_vendor_bank_account(
    vendor_id: str,
    current_user: User = Depends(authenticate_user),
    db: Session = Depends(get_db)
):
    """Retrieve active vendor bank account."""
    vendor = get_or_init_vendor(db, vendor_id)
    return {
        "vendor_id": vendor.vendor_id,
        "vendor_name": vendor.vendor_name,
        "active_bank_account_ref": vendor.active_bank_account_ref,
        "bank_name": vendor.bank_name,
        "routing_number_masked": vendor.routing_number_masked,
        "version": vendor.version,
        "updated_at": vendor.updated_at
    }
