"""
Unit and Integration Tests for Phase 5: Two-Person Approval and Bank Change Enforcement.

Verifies:
1. Strict Two-Person Authorization: Exactly two distinct approvers required.
2. Anti-Self-Approval: Requesters cannot approve their own requests under any circumstances.
3. Anti-Duplicate Approver: The same approver cannot sign off twice.
4. Old Bank Account Active Until Step 8: Active account remains unchanged until commit.
5. Cryptographic Fingerprint Verification: SHA-256 fingerprint validates immutability.
6. Role-Based Authorization: Only REQUESTER can create, only FINANCE_APPROVER can approve.
7. Rejection and Cancellation Workflows.
8. Request Expiration Handling.
9. Modification & Approval Invalidation Workflow.
10. Sensitive Data Masking: API responses and audit logs never leak plaintext account numbers.
11. Incident Engine Integration: SEC-RULE-BANK-001 correlated without AI override.
12. Concurrency Conflict: Single active pending request per vendor.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sentinel.backend.app.models.bank_approval import VendorBankAccount, BankChangeRequest, BankApproval, ApprovalAuditLog
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.services.bank_approval_service import (
    get_or_init_vendor,
    create_bank_change_request,
    approve_bank_change_request,
    reject_bank_change_request,
    cancel_bank_change_request,
    modify_change_request
)
from sentinel.backend.app.security.auth import DEV_USER_REGISTRY, User
from sentinel.backend.app.security.bank_crypto import decrypt_bank_payload


# Standard test auth headers
AUTH_SARAH = {"X-User-Id": "usr_req_sarah"}        # Role: REQUESTER
AUTH_ELENA = {"X-User-Id": "usr_appr_elena"}       # Role: FINANCE_APPROVER
AUTH_DAVID = {"X-User-Id": "usr_appr_david"}       # Role: FINANCE_APPROVER
AUTH_ALEX = {"X-User-Id": "usr_admin_alex"}        # Role: FINANCE_ADMIN
AUTH_RACHEL = {"X-User-Id": "usr_audit_rachel"}    # Role: AUDITOR (read-only)
AUTH_REVOKED = {"X-User-Id": "usr_revoked_james"}  # Status: REVOKED


def test_create_bank_change_request_success(client, db_session):
    """Authorized requester can create a bank change request; initiates PENDING_APPROVAL and creates incident."""
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": "998877665544",
        "proposed_bank_name": "Citibank NA",
        "proposed_routing_number": "021000089",
        "request_reason": "Vendor corporate treasury migration to new operating account"
    }

    response = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    assert response.status_code == 201
    data = response.json()

    assert data["vendor_id"] == "vnd_10482"
    assert data["requester_id"] == "usr_req_sarah"
    assert data["status"] == "PENDING_APPROVAL"
    assert data["approval_count"] == 0
    assert len(data["fingerprint"]) == 64
    assert data["version"] == 1
    # Check masking
    assert "998877665544" not in data["proposed_bank_account_ref"]
    assert data["proposed_bank_account_ref"].endswith("5544")
    assert "021000089" not in data["proposed_routing_masked"]

    # Verify incident engine logged high severity bank incident
    incident = db_session.query(Incident).filter(Incident.rule_id == "SEC-RULE-BANK-001").first()
    assert incident is not None
    assert incident.severity == "HIGH"
    assert incident.risk_score >= 75
    assert incident.evidence["approval_workflow_status"] == "PENDING_APPROVAL"


def test_create_request_unauthorized_user(client):
    """Users without REQUESTER or FINANCE_ADMIN role cannot create bank change requests."""
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": "111222333444",
        "proposed_bank_name": "Barclays",
        "proposed_routing_number": "123456789",
        "request_reason": "Unauthorized attempt"
    }

    # Auditor cannot create
    res_auditor = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_RACHEL)
    assert res_auditor.status_code == 403

    # Revoked user cannot create
    res_revoked = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_REVOKED)
    assert res_revoked.status_code == 403
    assert res_revoked.json()["detail"]["error"] == "AccountRevoked"

    # Missing authentication
    res_no_auth = client.post("/api/v1/bank-changes", json=payload)
    assert res_no_auth.status_code == 401


def test_conflict_on_duplicate_pending_request(client):
    """Cannot submit a second change request while one is already pending for the vendor."""
    payload1 = {
        "vendor_id": "vnd_10483",
        "proposed_account_number": "123123123123",
        "proposed_bank_name": "Chase",
        "proposed_routing_number": "021000021",
        "request_reason": "First request"
    }
    res1 = client.post("/api/v1/bank-changes", json=payload1, headers=AUTH_SARAH)
    assert res1.status_code == 201

    payload2 = {
        "vendor_id": "vnd_10483",
        "proposed_account_number": "456456456456",
        "proposed_bank_name": "Wells Fargo",
        "proposed_routing_number": "021000021",
        "request_reason": "Second conflicting request"
    }
    res2 = client.post("/api/v1/bank-changes", json=payload2, headers=AUTH_SARAH)
    assert res2.status_code == 409
    assert res2.json()["detail"]["error"] == "PendingRequestExists"


def test_anti_self_approval_enforcement(client):
    """Requester CANNOT approve their own bank change request."""
    # 1. Sarah creates request
    payload = {
        "vendor_id": "vnd_20491",
        "proposed_account_number": "554433221100",
        "proposed_bank_name": "Bank of America",
        "proposed_routing_number": "026009593",
        "request_reason": "Self-approval test"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    assert res.status_code == 201
    req_id = res.json()["request_id"]

    # 2. Sarah attempts to approve her own request
    approve_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Self signoff"},
        headers=AUTH_SARAH
    )
    # Sarah doesn't have approver role, so returns 403 AccessDenied
    assert approve_res.status_code == 403

    # Now test if a user who has BOTH REQUESTER and FINANCE_ADMIN/APPROVER (Alex) requests and self-approves
    res_alex_req = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_alex",
            "proposed_account_number": "777888999000",
            "proposed_bank_name": "PNC Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Admin request"
        },
        headers=AUTH_ALEX
    )
    assert res_alex_req.status_code == 201
    alex_req_id = res_alex_req.json()["request_id"]

    # Alex has FINANCE_ADMIN role, but IS the requester
    self_appr_res = client.post(
        f"/api/v1/bank-changes/{alex_req_id}/approve",
        json={"comment": "Admin trying to approve own request"},
        headers=AUTH_ALEX
    )
    assert self_appr_res.status_code == 403
    assert self_appr_res.json()["detail"]["error"] == "SelfApprovalProhibited"


def test_first_approval_transitions_to_partially_approved(client, db_session):
    """First approval transitions to PARTIALLY_APPROVED and vendor active account is NOT modified."""
    # Create request
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": "999888777666",
        "proposed_bank_name": "Silicon Valley Bank",
        "proposed_routing_number": "121000247",
        "request_reason": "Quarterly account update"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]
    old_account_ref = res.json()["old_bank_account_ref"]

    # First approver (Elena) approves
    appr1_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Elena review: verified with vendor treasury officer"},
        headers=AUTH_ELENA
    )
    assert appr1_res.status_code == 200
    appr1_data = appr1_res.json()
    assert appr1_data["status"] == "PARTIALLY_APPROVED"
    assert appr1_data["approval_count"] == 1
    assert appr1_data["approvals"][0]["approver_id"] == "usr_appr_elena"
    assert appr1_data["approvals"][0]["approval_order"] == 1

    # Check vendor's active bank account in DB: MUST REMAIN OLD ACCOUNT
    vendor = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482").first()
    assert vendor.active_bank_account_ref == old_account_ref
    assert vendor.version == 1


def test_anti_duplicate_approver_enforcement(client, db_session):
    """The same approver cannot approve twice."""
    payload = {
        "vendor_id": "vnd_10483",
        "proposed_account_number": "888999111222",
        "proposed_bank_name": "Deutsche Bank",
        "proposed_routing_number": "021000021",
        "request_reason": "Duplicate approver test"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]

    # First approval by Elena
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Elena first"}, headers=AUTH_ELENA)

    # Elena tries to approve a second time
    dup_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Elena second attempt"},
        headers=AUTH_ELENA
    )
    assert dup_res.status_code == 400
    assert dup_res.json()["detail"]["error"] == "DuplicateApprovalProhibited"

    # Status must still be PARTIALLY_APPROVED
    req = client.get(f"/api/v1/bank-changes/{req_id}", headers=AUTH_SARAH).json()
    assert req["status"] == "PARTIALLY_APPROVED"
    assert req["approval_count"] == 1


def test_full_two_person_approval_commits_atomically(client, db_session):
    """Two distinct approvers commit the bank change atomically; vendor active account is updated."""
    payload = {
        "vendor_id": "vnd_20491",
        "proposed_account_number": "334455667788",
        "proposed_bank_name": "Morgan Stanley",
        "proposed_routing_number": "021000021",
        "request_reason": "Full two person approval test"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]
    proposed_ref = res.json()["proposed_bank_account_ref"]

    # First approval: Elena
    res1 = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Approver 1: Vendor call confirmed"},
        headers=AUTH_ELENA
    )
    assert res1.json()["status"] == "PARTIALLY_APPROVED"

    # Second approval: David (different approver)
    res2 = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Approver 2: Documentation and signature match"},
        headers=AUTH_DAVID
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == "COMMITTED"
    assert data2["approval_count"] == 2
    assert [a["approver_id"] for a in data2["approvals"]] == ["usr_appr_elena", "usr_appr_david"]

    # Verify active vendor bank account updated in database atomically
    vendor = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_20491").first()
    assert vendor.active_bank_account_ref == proposed_ref
    assert vendor.bank_name == "Morgan Stanley"
    assert vendor.version == 2

    # Verify active vendor endpoint matches
    v_res = client.get("/api/v1/vendors/vnd_20491/bank-account", headers=AUTH_SARAH)
    assert v_res.status_code == 200
    assert v_res.json()["active_bank_account_ref"] == proposed_ref
    assert v_res.json()["version"] == 2

    # Cannot approve again after commit
    res_after = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Third approver attempt"},
        headers=AUTH_ALEX
    )
    assert res_after.status_code == 400
    assert res_after.json()["detail"]["error"] == "InvalidStatusTransition"


def test_reject_change_request_workflow(client, db_session):
    """Finance approver can reject a request; vendor active account is untouched."""
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": "112233449900",
        "proposed_bank_name": "Suspicious Offshore Bank",
        "proposed_routing_number": "021000021",
        "request_reason": "Urgent wire routing redirection"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]
    old_account_ref = res.json()["old_bank_account_ref"]

    # Reject by David
    reject_res = client.post(
        f"/api/v1/bank-changes/{req_id}/reject",
        json={"reason": "Vendor security contact flagged callback as fraudulent"},
        headers=AUTH_DAVID
    )
    assert reject_res.status_code == 200
    data = reject_res.json()
    assert data["status"] == "REJECTED"
    assert data["rejection_reason"] == "Vendor security contact flagged callback as fraudulent"

    # Active vendor account must NOT change
    vendor = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482").first()
    assert vendor.active_bank_account_ref == old_account_ref

    # Attempting to approve rejected request must fail
    appr_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Late approval"},
        headers=AUTH_ELENA
    )
    assert appr_res.status_code == 400
    assert appr_res.json()["detail"]["error"] == "InvalidStatusTransition"


def test_cancel_change_request_workflow(client):
    """Requester or admin can cancel a pending request."""
    payload = {
        "vendor_id": "vnd_10483",
        "proposed_account_number": "555666777888",
        "proposed_bank_name": "Standard Chartered",
        "proposed_routing_number": "021000021",
        "request_reason": "Typo in submitted account"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]

    # Unauthorized user (David) cannot cancel Sarah's request
    cancel_david = client.post(
        f"/api/v1/bank-changes/{req_id}/cancel",
        json={"reason": "Not the requester"},
        headers=AUTH_DAVID
    )
    assert cancel_david.status_code == 403

    # Sarah cancels her own request
    cancel_sarah = client.post(
        f"/api/v1/bank-changes/{req_id}/cancel",
        json={"reason": "Correcting account details in new submission"},
        headers=AUTH_SARAH
    )
    assert cancel_sarah.status_code == 200
    assert cancel_sarah.json()["status"] == "CANCELLED"
    assert cancel_sarah.json()["cancelled_by"] == "usr_req_sarah"


def test_expired_request_cannot_be_approved(client, db_session):
    """Requests that have exceeded BANK_CHANGE_EXPIRY_HOURS cannot be approved."""
    payload = {
        "vendor_id": "vnd_20491",
        "proposed_account_number": "777666555444",
        "proposed_bank_name": "HSBC",
        "proposed_routing_number": "021000021",
        "request_reason": "Expiration test"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]

    # Manually backdate expires_at to 1 hour in the past
    req_obj = db_session.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
    req_obj.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    # Attempt approval
    appr_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Attempting approval on expired request"},
        headers=AUTH_ELENA
    )
    assert appr_res.status_code == 400
    assert appr_res.json()["detail"]["error"] == "RequestExpired"

    # Status must be EXPIRED
    db_session.refresh(req_obj)
    assert req_obj.status == "EXPIRED"


def test_fingerprint_tamper_detection(client, db_session):
    """If request details or fingerprint are tampered with in database, approval fails with FingerprintMismatch."""
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": "443322119988",
        "proposed_bank_name": "PNC Bank",
        "proposed_routing_number": "021000021",
        "request_reason": "Tamper test"
    }
    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = res.json()["request_id"]

    # Tamper with the proposed bank name directly in the DB
    req_obj = db_session.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
    req_obj.proposed_bank_name = "Hacked Malicious Bank LLC"
    db_session.commit()

    # Elena attempts to approve tampered request
    appr_res = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Reviewing"},
        headers=AUTH_ELENA
    )
    assert appr_res.status_code == 409
    assert appr_res.json()["detail"]["error"] == "FingerprintMismatch"

    # Check audit log for TAMPER_DETECTED
    audit = db_session.query(ApprovalAuditLog).filter(
        ApprovalAuditLog.request_id == req_id,
        ApprovalAuditLog.action == "TAMPER_DETECTED"
    ).first()
    assert audit is not None
    assert audit.result == "FAILURE"


def test_modification_invalidates_previous_approvals(db_session):
    """Modifying a request increments version, invalidates previous approvals, and resets status to PENDING_APPROVAL."""
    sarah = DEV_USER_REGISTRY["usr_req_sarah"]
    elena = DEV_USER_REGISTRY["usr_appr_elena"]
    david = DEV_USER_REGISTRY["usr_appr_david"]

    # 1. Create request
    req = create_bank_change_request(
        db=db_session,
        requester=sarah,
        vendor_id="vnd_10483",
        proposed_account_number="111222333444",
        proposed_bank_name="First Republic",
        proposed_routing_number="021000021",
        request_reason="Initial proposal"
    )
    assert req.version == 1
    assert req.status == "PENDING_APPROVAL"
    req_id = req.request_id

    # 2. Elena approves
    req = approve_bank_change_request(
        db=db_session,
        request_id=req_id,
        approver=elena,
        comment="Elena signs off"
    )
    assert req.status == "PARTIALLY_APPROVED"
    assert len(req.approvals) == 1

    # 3. Requester modifies bank details
    req = modify_change_request(
        db=db_session,
        request_id=req_id,
        user=sarah,
        proposed_account_number="999888777666",
        proposed_bank_name="JPMorgan Chase",
        proposed_routing_number="021000021",
        request_reason="Updated to official vendor checking account"
    )

    # Approvals must be wiped, version incremented, status reset
    assert req.version == 2
    assert req.status == "PENDING_APPROVAL"
    assert len(req.approvals) == 0

    # 4. Elena can now approve again (valid because previous approvals were invalidated)
    req = approve_bank_change_request(
        db=db_session,
        request_id=req_id,
        approver=elena,
        comment="Elena re-approval for v2"
    )
    assert req.status == "PARTIALLY_APPROVED"
    assert len(req.approvals) == 1

    # 5. David approves
    req = approve_bank_change_request(
        db=db_session,
        request_id=req_id,
        approver=david,
        comment="David second approval for v2"
    )
    assert req.status == "COMMITTED"
    assert len(req.approvals) == 2


def test_sensitive_data_never_leaked_in_api_or_audit(client, db_session):
    """Plaintext account number is NEVER present in API responses, audit logs, or DB plain text columns."""
    raw_acc = "8899001122334455"
    raw_rout = "021000088"
    payload = {
        "vendor_id": "vnd_20491",
        "proposed_account_number": raw_acc,
        "proposed_bank_name": "State Street Bank",
        "proposed_routing_number": raw_rout,
        "request_reason": "Data privacy masking validation"
    }
    create_res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    req_id = create_res.json()["request_id"]

    # Verify not in create response
    assert raw_acc not in create_res.text
    assert raw_rout not in create_res.text

    # Elena approves
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Elena audit test"}, headers=AUTH_ELENA)

    # Verify not in GET by id
    get_res = client.get(f"/api/v1/bank-changes/{req_id}", headers=AUTH_RACHEL)
    assert raw_acc not in get_res.text
    assert raw_rout not in get_res.text

    # Verify not in audit logs API
    audit_res = client.get(f"/api/v1/bank-changes/{req_id}/audit", headers=AUTH_RACHEL)
    assert raw_acc not in audit_res.text
    assert raw_rout not in audit_res.text

    # Verify in DB: proposed details are encrypted bytes, not plaintext
    req_db = db_session.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
    assert req_db.proposed_bank_account_ref.startswith("ACC-***")
    assert raw_acc not in req_db.proposed_bank_account_ref
    # Decrypt and check underlying content
    decrypted = decrypt_bank_payload(req_db.encrypted_proposed_bank_details)
    assert decrypted["account_number"] == raw_acc
    assert decrypted["routing_number"] == raw_rout


def test_list_and_filter_bank_changes(client):
    """Test listing change requests with status and vendor filtering."""
    # List all
    res = client.get("/api/v1/bank-changes", headers=AUTH_RACHEL)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)

    # Filter by vendor
    res_vnd = client.get("/api/v1/bank-changes?vendor_id=vnd_10482", headers=AUTH_RACHEL)
    assert res_vnd.status_code == 200
    for item in res_vnd.json()["items"]:
        assert item["vendor_id"] == "vnd_10482"
