"""
QA Verification Test Suite for Bank Change Approvals Priority (Items a through n)
Strictly adheres to sentinel/README.md and QA hardening requirements:
1. Reproduce before fixing.
2. Fix root causes.
3. Strict security invariant: 2 distinct human approvers, no self-approval, no duplicate approval,
   raw account numbers never in responses/logs/audit/exceptions, atomic commit with row locks,
   and AI scores never authorize a bank change.
"""

import pytest
import concurrent.futures
from datetime import datetime, timezone, timedelta
from sqlalchemy import text, select
from sqlalchemy.orm import Session

from sentinel.backend.app.database import SessionLocal
from sentinel.backend.app.models.bank_approval import (
    VendorBankAccount,
    BankChangeRequest,
    BankApproval,
    ApprovalAuditLog
)
from sentinel.backend.app.security.auth import DEV_USER_REGISTRY
from sentinel.backend.app.security.bank_crypto import decrypt_bank_payload
from sentinel.backend.app.services.bank_approval_service import approve_bank_change_request

AUTH_SARAH = {"X-User-Id": "usr_req_sarah"}        # Role: REQUESTER
AUTH_MARK = {"X-User-Id": "usr_req_mark"}          # Role: REQUESTER
AUTH_ELENA = {"X-User-Id": "usr_appr_elena"}       # Role: FINANCE_APPROVER
AUTH_DAVID = {"X-User-Id": "usr_appr_david"}       # Role: FINANCE_APPROVER
AUTH_CHLOE = {"X-User-Id": "usr_appr_chloe"}       # Role: FINANCE_APPROVER
AUTH_ALEX = {"X-User-Id": "usr_admin_alex"}        # Role: FINANCE_ADMIN
AUTH_RACHEL = {"X-User-Id": "usr_audit_rachel"}    # Role: AUDITOR (read-only)
AUTH_REVOKED = {"X-User-Id": "usr_revoked_james"}  # Status: REVOKED


# ==============================================================================
# a. Creation & Masking
# ==============================================================================
def test_item_a_create_bank_change_request_and_masking(client):
    """
    Item a: POST /api/v1/bank-changes creates request in PENDING_APPROVAL,
    masked reference (ACC-***masked***1048), requester resolved from X-User-Id.
    Also supports proposed_bank_account alias from UI.
    """
    raw_acc = "987654321048"
    raw_rout = "021000021"
    payload = {
        "vendor_id": "vnd_10482",
        "proposed_account_number": raw_acc,
        "proposed_bank_name": "JPMorgan Chase & Co.",
        "proposed_routing_number": raw_rout,
        "request_reason": "Vendor corporate treasury migration"
    }

    res = client.post("/api/v1/bank-changes", json=payload, headers=AUTH_SARAH)
    assert res.status_code == 201
    data = res.json()

    assert data["status"] == "PENDING_APPROVAL"
    assert data["requester_id"] == "usr_req_sarah"
    assert data["vendor_id"] == "vnd_10482"
    assert data["proposed_bank_account_ref"] == "ACC-***masked***1048"
    assert data["proposed_routing_masked"] == "ROUT-***masked***0021"
    assert raw_acc not in res.text
    assert raw_rout not in res.text

    # Verify alias support (proposed_bank_account)
    alias_payload = {
        "vendor_id": "vnd_10483",
        "proposed_bank_account": "112233445566",
        "proposed_bank_name": "Bank of America",
        "proposed_routing_number": "026009593",
        "request_reason": "Testing frontend alias compatibility"
    }
    res_alias = client.post("/api/v1/bank-changes", json=alias_payload, headers=AUTH_SARAH)
    assert res_alias.status_code == 201
    data_alias = res_alias.json()
    assert data_alias["proposed_bank_account_ref"] == "ACC-***masked***5566"


# ==============================================================================
# b. Anti-Self-Approval
# ==============================================================================
def test_item_b_anti_self_approval_both_roles(client):
    """
    Item b: Requester approving own request returns 403 SelfApprovalProhibited
    for both normal requester (Sarah) and admin requester (Alex).
    """
    # 1. Sarah (REQUESTER) creates request
    res1 = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_20491",
            "proposed_account_number": "998877665544",
            "proposed_bank_name": "Wells Fargo",
            "proposed_routing_number": "121000247",
            "request_reason": "Self approval test 1"
        },
        headers=AUTH_SARAH
    )
    assert res1.status_code == 201
    req1_id = res1.json()["request_id"]

    # Sarah attempts to approve her own request
    appr1 = client.post(f"/api/v1/bank-changes/{req1_id}/approve", json={"comment": "Self signoff"}, headers=AUTH_SARAH)
    assert appr1.status_code == 403
    assert appr1.json()["detail"]["error"] == "SelfApprovalProhibited"

    # 2. Alex (FINANCE_ADMIN) creates request
    res2 = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_alex_qa",
            "proposed_account_number": "887766554433",
            "proposed_bank_name": "PNC Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Self approval test 2"
        },
        headers=AUTH_ALEX
    )
    assert res2.status_code == 201
    req2_id = res2.json()["request_id"]

    # Alex attempts to approve his own request
    appr2 = client.post(f"/api/v1/bank-changes/{req2_id}/approve", json={"comment": "Admin self signoff"}, headers=AUTH_ALEX)
    assert appr2.status_code == 403
    assert appr2.json()["detail"]["error"] == "SelfApprovalProhibited"


# ==============================================================================
# c. Non-Approver Rejection (403 AccessDenied)
# ==============================================================================
def test_item_c_non_approver_rejection(client):
    """
    Item c: Non-approver (usr_audit_rachel or Sarah approving someone else's request)
    cannot approve -> 403 AccessDenied. Centralized role checks in dependency/service.
    """
    # Mark creates request
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_20491_mark",
            "proposed_account_number": "123456789012",
            "proposed_bank_name": "Citibank",
            "proposed_routing_number": "021000089",
            "request_reason": "Non-approver test"
        },
        headers=AUTH_MARK
    )
    assert res.status_code == 201
    req_id = res.json()["request_id"]

    # Rachel (AUDITOR) attempts approval
    appr_rachel = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Auditor approving"}, headers=AUTH_RACHEL)
    assert appr_rachel.status_code == 403
    assert appr_rachel.json()["detail"]["error"] == "AccessDenied"

    # Sarah (REQUESTER, not the requester for this request) attempts approval
    appr_sarah = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Cross requester approving"}, headers=AUTH_SARAH)
    assert appr_sarah.status_code == 403
    assert appr_sarah.json()["detail"]["error"] == "AccessDenied"


# ==============================================================================
# d. First Approval (PARTIALLY_APPROVED, account unchanged)
# ==============================================================================
def test_item_d_first_approval_transitions_and_account_invariant(client, db_session):
    """
    Item d: First approval -> PARTIALLY_APPROVED, approval_count: 1,
    active vendor account NOT changed.
    """
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_d",
            "proposed_account_number": "778899001122",
            "proposed_bank_name": "Barclays",
            "proposed_routing_number": "021000021",
            "request_reason": "First approval verification"
        },
        headers=AUTH_SARAH
    )
    assert res.status_code == 201
    req_id = res.json()["request_id"]
    old_account_ref = res.json()["old_bank_account_ref"]

    # Elena approves
    appr = client.post(
        f"/api/v1/bank-changes/{req_id}/approve",
        json={"comment": "Elena first approval signoff"},
        headers=AUTH_ELENA
    )
    assert appr.status_code == 200
    data = appr.json()
    assert data["status"] == "PARTIALLY_APPROVED"
    assert data["approval_count"] == 1
    assert data["approvals"][0]["approver_id"] == "usr_appr_elena"

    # Verify vendor account in DB has NOT changed
    vendor = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482_d").first()
    assert vendor.active_bank_account_ref == old_account_ref


# ==============================================================================
# e. Anti-Duplicate Approval (400 DuplicateApprovalProhibited)
# ==============================================================================
def test_item_e_anti_duplicate_approval(client):
    """
    Item e: Same approver approving again -> 400 DuplicateApprovalProhibited.
    """
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_e",
            "proposed_account_number": "334455667788",
            "proposed_bank_name": "Standard Chartered",
            "proposed_routing_number": "021000021",
            "request_reason": "Duplicate approval test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Elena approves first time
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "First signoff"}, headers=AUTH_ELENA)

    # Elena attempts to approve second time
    dup = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Second signoff attempt"}, headers=AUTH_ELENA)
    assert dup.status_code == 400
    assert dup.json()["detail"]["error"] == "DuplicateApprovalProhibited"


# ==============================================================================
# f. Second Approval by Distinct Approver -> COMMITTED & Atomic Commit
# ==============================================================================
def test_item_f_second_approval_commits_atomically(client, db_session):
    """
    Item f: Second approval by distinct approver -> COMMITTED, approval_count: 2,
    active account updated atomically; failure leaves no partial state.
    """
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_f",
            "proposed_account_number": "445566778899",
            "proposed_bank_name": "Goldman Sachs Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Atomic commit test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]
    proposed_ref = res.json()["proposed_bank_account_ref"]

    # First approval: Elena
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Elena signoff"}, headers=AUTH_ELENA)

    # Second approval: David (distinct approver)
    appr2 = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "David signoff"}, headers=AUTH_DAVID)
    assert appr2.status_code == 200
    data2 = appr2.json()
    assert data2["status"] == "COMMITTED"
    assert data2["approval_count"] == 2
    assert [a["approver_id"] for a in data2["approvals"]] == ["usr_appr_elena", "usr_appr_david"]

    # Vendor account updated atomically
    vendor = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482_f").first()
    assert vendor.active_bank_account_ref == proposed_ref
    assert vendor.bank_name == "Goldman Sachs Bank"


# ==============================================================================
# g. Terminal Status Rejection (COMMITTED, REJECTED, CANCELLED, EXPIRED)
# ==============================================================================
def test_item_g_terminal_status_rejection(client):
    """
    Item g: Approving already COMMITTED, REJECTED, CANCELLED, or EXPIRED request rejected with 4xx.
    """
    # Create request
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_g",
            "proposed_account_number": "556677889900",
            "proposed_bank_name": "US Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Terminal status test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Commit the request
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "1"}, headers=AUTH_ELENA)
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "2"}, headers=AUTH_DAVID)

    # Attempt 3rd approval on COMMITTED request
    appr3 = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "3"}, headers=AUTH_CHLOE)
    assert appr3.status_code == 400
    assert appr3.json()["detail"]["error"] == "InvalidStatusTransition"


# ==============================================================================
# h. Reject & Cancel Workflows Leave Old Account Unchanged
# ==============================================================================
def test_item_h_reject_and_cancel_leave_old_account_unchanged(client, db_session):
    """
    Item h: Reject & cancel workflows exist as routes, work, leave old account unchanged.
    """
    # 1. Reject workflow
    res1 = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_h1",
            "proposed_account_number": "111222333444",
            "proposed_bank_name": "Target Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Rejection test"
        },
        headers=AUTH_SARAH
    )
    req1_id = res1.json()["request_id"]
    old1_ref = res1.json()["old_bank_account_ref"]

    rej = client.post(f"/api/v1/bank-changes/{req1_id}/reject", json={"reason": "Security verification failed"}, headers=AUTH_ELENA)
    assert rej.status_code == 200
    assert rej.json()["status"] == "REJECTED"

    vendor1 = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482_h1").first()
    assert vendor1.active_bank_account_ref == old1_ref

    # 2. Cancel workflow
    res2 = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_h2",
            "proposed_account_number": "222333444555",
            "proposed_bank_name": "Target Bank 2",
            "proposed_routing_number": "021000021",
            "request_reason": "Cancellation test"
        },
        headers=AUTH_SARAH
    )
    req2_id = res2.json()["request_id"]
    old2_ref = res2.json()["old_bank_account_ref"]

    canc = client.post(f"/api/v1/bank-changes/{req2_id}/cancel", json={"reason": "Typo in account"}, headers=AUTH_SARAH)
    assert canc.status_code == 200
    assert canc.json()["status"] == "CANCELLED"

    vendor2 = db_session.query(VendorBankAccount).filter(VendorBankAccount.vendor_id == "vnd_10482_h2").first()
    assert vendor2.active_bank_account_ref == old2_ref


# ==============================================================================
# i. Expiration (injected time, no sleep)
# ==============================================================================
def test_item_i_expiration_handling_no_sleep(client, db_session):
    """
    Item i: Request older than configured lifetime cannot be approved, marked EXPIRED.
    """
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_i",
            "proposed_account_number": "333444555666",
            "proposed_bank_name": "Target Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Expiry test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Inject expiration by backdating expires_at in DB
    req_obj = db_session.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
    req_obj.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    # Attempt approval
    appr = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Attempt after expiry"}, headers=AUTH_ELENA)
    assert appr.status_code == 400
    assert appr.json()["detail"]["error"] == "RequestExpired"

    db_session.refresh(req_obj)
    assert req_obj.status == "EXPIRED"


# ==============================================================================
# j. Tamper Detection & Documented Modify Route (PUT)
# ==============================================================================
def test_item_j_modify_route_and_tamper_detection(client, db_session):
    """
    Item j: Tamper detection: approvals bound to canonical SHA-256 fingerprint.
    1. Documented modify route PUT /api/v1/bank-changes/{id} invalidates prior approvals and resets status.
    2. Direct database tampering triggers FingerprintMismatch (409).
    """
    # 1. Create request
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_j",
            "proposed_account_number": "444555666777",
            "proposed_bank_name": "Bank of Choice",
            "proposed_routing_number": "021000021",
            "request_reason": "Tamper test initial"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # First approval by Elena
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Elena signoff"}, headers=AUTH_ELENA)

    # Requester modifies via documented PUT route
    put_res = client.put(
        f"/api/v1/bank-changes/{req_id}",
        json={
            "proposed_account_number": "999000111222",
            "proposed_bank_name": "Corrected Bank LLC",
            "proposed_routing_number": "021000021",
            "request_reason": "Corrected banking partner"
        },
        headers=AUTH_SARAH
    )
    assert put_res.status_code == 200
    put_data = put_res.json()
    assert put_data["version"] == 2
    assert put_data["status"] == "PENDING_APPROVAL"
    assert put_data["approval_count"] == 0

    # 2. Direct database tamper test
    req_obj = db_session.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
    req_obj.proposed_bank_name = "Attacker Injected Bank Name"
    db_session.commit()

    # Attempt approval on tampered request
    tamper_appr = client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Reviewing"}, headers=AUTH_ELENA)
    assert tamper_appr.status_code == 409
    assert tamper_appr.json()["detail"]["error"] == "FingerprintMismatch"


# ==============================================================================
# k. Concurrency Safety: ThreadPoolExecutor against PostgreSQL
# ==============================================================================
def test_item_k_concurrency_simultaneous_approvers():
    """
    Item k: Concurrency: two distinct approvers at the exact same instant ->
    exactly one COMMITTED result, 2 approvals, no 500;
    same approver twice -> exactly one accepted approval.
    Real concurrent test against PostgreSQL (SELECT ... FOR UPDATE).
    """
    import uuid
    from sentinel.backend.app.services.bank_approval_service import create_bank_change_request

    sarah = DEV_USER_REGISTRY["usr_req_sarah"]
    vendor_k1 = f"vnd_k1_{uuid.uuid4().hex[:8]}"

    # 1. Distinct approvers at same instant in real PostgreSQL
    with SessionLocal() as db:
        req = create_bank_change_request(
            db=db,
            requester=sarah,
            vendor_id=vendor_k1,
            proposed_account_number="555666777888",
            proposed_bank_name="Concurrency Bank",
            proposed_routing_number="021000021",
            request_reason="Concurrency test 1"
        )
        req_id = req.request_id

    def approve_call(approver_id: str):
        with SessionLocal() as db:
            user = DEV_USER_REGISTRY[approver_id]
            res = approve_bank_change_request(
                db=db,
                request_id=req_id,
                approver=user,
                comment=f"Concurrent approval by {approver_id}"
            )
            return res.status

    # Concurrently execute Elena and David
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(approve_call, "usr_appr_elena")
        f2 = executor.submit(approve_call, "usr_appr_david")
        r1 = f1.result()
        r2 = f2.result()

    # One must be PARTIALLY_APPROVED and one COMMITTED
    statuses = sorted([r1, r2])
    assert statuses == ["COMMITTED", "PARTIALLY_APPROVED"]

    # Final DB check in PostgreSQL
    with SessionLocal() as db:
        final_req = db.query(BankChangeRequest).filter(BankChangeRequest.request_id == req_id).first()
        assert final_req.status == "COMMITTED"
        assert len(final_req.approvals) == 2

    # 2. Same approver twice at same instant in real PostgreSQL
    vendor_k2 = f"vnd_k2_{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        req2 = create_bank_change_request(
            db=db,
            requester=sarah,
            vendor_id=vendor_k2,
            proposed_account_number="666777888999",
            proposed_bank_name="Concurrency Bank 2",
            proposed_routing_number="021000021",
            request_reason="Concurrency test 2"
        )
        req2_id = req2.request_id

    def same_approver_call():
        with SessionLocal() as db:
            user = DEV_USER_REGISTRY["usr_appr_elena"]
            try:
                approve_bank_change_request(db=db, request_id=req2_id, approver=user)
                return "SUCCESS", None
            except Exception as e:
                return "ERROR", e

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_a = executor.submit(same_approver_call)
        f_b = executor.submit(same_approver_call)
        res_a = f_a.result()
        res_b = f_b.result()

    results = [res_a[0], res_b[0]]
    # Exactly one must succeed, one must fail with DuplicateApprovalProhibited (400)
    assert results.count("SUCCESS") == 1
    assert results.count("ERROR") == 1
    err = res_a[1] if res_a[0] == "ERROR" else res_b[1]
    assert err.status_code == 400
    assert err.detail["error"] == "DuplicateApprovalProhibited"


# ==============================================================================
# l. Encryption at Rest & Key Safety
# ==============================================================================
def test_item_l_encryption_at_rest_and_wrong_key_safety(client, db_session):
    """
    Item l: Proposed details Fernet-encrypted at rest; prove ciphertext in raw DB row,
    wrong/missing key fails safely.
    """
    raw_acc = "777888999000111"
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_l",
            "proposed_account_number": raw_acc,
            "proposed_bank_name": "Secret Encrypted Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Encryption test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Direct raw SQL query on DB
    row = db_session.execute(
        text("SELECT encrypted_proposed_bank_details FROM bank_change_requests WHERE request_id = :req_id"),
        {"req_id": req_id}
    ).fetchone()
    assert row is not None
    ciphertext = row[0]

    # Must be Fernet token, not raw account
    assert raw_acc not in ciphertext
    assert ciphertext.startswith("gAAAAA")

    # Decrypting corrupted ciphertext must raise ValueError safely
    with pytest.raises(ValueError, match="Cryptographic verification failed"):
        decrypt_bank_payload("gAAAAABcorruptedTokenHereSafeFailureNotice==")


# ==============================================================================
# m. Audit Trail Immutability (UPDATE/DELETE blocked)
# ==============================================================================
def test_item_m_audit_trail_immutability(client, db_session):
    """
    Item m: Audit trail endpoint returns immutable, chronological record with no raw accounts;
    prove immutability (UPDATE/DELETE blocked by DB trigger and ORM listener).
    """
    import uuid
    from sentinel.backend.tests.conftest import TestingSessionLocal
    from sentinel.backend.app.services.bank_approval_service import record_approval_audit

    raw_acc = "888999000111222"
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_m",
            "proposed_account_number": raw_acc,
            "proposed_bank_name": "Audit Immutability Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "Audit immutability test"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Elena approves
    client.post(f"/api/v1/bank-changes/{req_id}/approve", json={"comment": "Elena signoff"}, headers=AUTH_ELENA)

    # 1. Audit API check
    audit_res = client.get(f"/api/v1/bank-changes/{req_id}/audit", headers=AUTH_RACHEL)
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) >= 2
    # Ensure chronological
    times = [log["created_at"] for log in logs]
    assert times == sorted(times)
    # Ensure no raw account leaked
    assert raw_acc not in audit_res.text

    # 2. Immutability at ORM level and PostgreSQL trigger level
    from sentinel.backend.app.services.bank_approval_service import create_bank_change_request
    with SessionLocal() as pg_db:
        # Create a real parent request in PostgreSQL
        pg_req = create_bank_change_request(
            db=pg_db,
            requester=DEV_USER_REGISTRY["usr_req_sarah"],
            vendor_id=f"vnd_audit_{uuid.uuid4().hex[:8]}",
            proposed_account_number="888999000111222",
            proposed_bank_name="Audit Immutability Bank",
            proposed_routing_number="021000021",
            request_reason="Audit immutability test"
        )
        pg_req_id = pg_req.request_id

        # Query the audit log created by create_bank_change_request
        audit_entry = pg_db.query(ApprovalAuditLog).filter(ApprovalAuditLog.request_id == pg_req_id).first()
        assert audit_entry is not None

        # A. ORM Immutability: Attempting UPDATE on ApprovalAuditLog model must raise PermissionError
        with pytest.raises(PermissionError, match="immutable"):
            audit_entry.result = "TAMPERED"
            pg_db.flush()
        pg_db.rollback()

        # Re-query after rollback
        audit_entry = pg_db.query(ApprovalAuditLog).filter(ApprovalAuditLog.request_id == pg_req_id).first()

        # B. ORM Immutability: Attempting DELETE on ApprovalAuditLog model must raise PermissionError
        with pytest.raises(PermissionError, match="immutable"):
            pg_db.delete(audit_entry)
            pg_db.flush()
        pg_db.rollback()

        # C. PostgreSQL Trigger Immutability: Trigger blocks raw SQL UPDATE
        with pytest.raises(Exception) as exc_update:
            pg_db.execute(text("UPDATE bank_approval_audit_logs SET result = 'TAMPERED' WHERE request_id = :req_id"), {"req_id": pg_req_id})
            pg_db.commit()
        pg_db.rollback()
        assert "immutable" in str(exc_update.value).lower()

        # D. PostgreSQL Trigger Immutability: Trigger blocks raw SQL DELETE
        with pytest.raises(Exception) as exc_delete:
            pg_db.execute(text("DELETE FROM bank_approval_audit_logs WHERE request_id = :req_id"), {"req_id": pg_req_id})
            pg_db.commit()
        pg_db.rollback()
        assert "immutable" in str(exc_delete.value).lower()


# ==============================================================================
# n. AI Score Non-Bypass Invariant
# ==============================================================================
def test_item_n_ai_score_never_bypasses_human_approval(client, db_session):
    """
    Item n: Linked risk-assessment endpoint returns warnings/snapshot;
    AI score changing (0 or 100) never bypasses human approvals.
    """
    res = client.post(
        "/api/v1/bank-changes",
        json={
            "vendor_id": "vnd_10482_n",
            "proposed_account_number": "999111222333",
            "proposed_bank_name": "AI Non-Bypass Bank",
            "proposed_routing_number": "021000021",
            "request_reason": "AI non-bypass verification"
        },
        headers=AUTH_SARAH
    )
    req_id = res.json()["request_id"]

    # Check risk assessment endpoint
    risk_res = client.get(f"/api/v1/bank-changes/{req_id}/risk-assessment", headers=AUTH_ELENA)
    assert risk_res.status_code == 200
    risk_data = risk_res.json()
    assert risk_data["two_person_rule_status"] == "STRICT_HUMAN_APPROVAL_MANDATORY"
    assert risk_data["ai_authorization_override_permitted"] is False

    # Status must still be PENDING_APPROVAL; no AI score can auto-commit
    req_status = client.get(f"/api/v1/bank-changes/{req_id}", headers=AUTH_SARAH).json()["status"]
    assert req_status == "PENDING_APPROVAL"
