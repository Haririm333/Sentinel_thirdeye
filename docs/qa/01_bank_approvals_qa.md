# SENTINEL QA Report: Bank Change Approvals & Enforcement (Phase 2)

**Status**: Verified & Passing (14 / 14 Priority QA Tests Passed)  
**Date**: November 20, 2026  
**Auditor**: Senior Backend + QA Engineering

---

## 1. Executive Summary

This report documents the verification, root-cause analysis, and hardening of the **Two-Person Bank Change Approval Engine** in SENTINEL.
A comprehensive test suite (`tests/test_bank_approval_qa.py`) was constructed to test items **a through n** defined in the project specification and `sentinel/README.md`.

All identified defects were reproduced with failing tests prior to remediation, root-caused to exact files and lines, resolved without weakening security guarantees, and proven passing across both SQLite in-memory harnesses and live PostgreSQL 16 row-locking engines.

---

## 2. Item-by-Item Verification Matrix

| Item | Requirement | Status | Test Function | Key Evidence / Proof |
| :--- | :--- | :---: | :--- | :--- |
| **a** | Submission creates `PENDING_APPROVAL`, masks account reference (`ACC-***masked***1048`), extracts requester from `X-User-Id`. | **PASS** | `test_item_a_create_bank_change_request_and_masking` | Response ref: `ACC-***masked***1048`. Raw numbers redacted from response body and logs. Supports frontend alias `proposed_bank_account`. |
| **b** | Requester approving own request rejected with `403 SelfApprovalProhibited`. | **PASS** | `test_item_b_anti_self_approval_both_roles` | Both standard requester (`usr_req_sarah`) and admin requester (`usr_admin_alex`) rejected with `403 SelfApprovalProhibited`. |
| **c** | Non-approver cannot approve (`403 AccessDenied`). | **PASS** | `test_item_c_non_approver_rejection` | Auditor (`usr_audit_rachel`) and cross-requester attempts return `403 AccessDenied`. |
| **d** | First approval transitions to `PARTIALLY_APPROVED`, `approval_count: 1`, active vendor account unchanged. | **PASS** | `test_item_d_first_approval_transitions_and_account_invariant` | State: `PARTIALLY_APPROVED`. Active vendor account in database remains original baseline account. |
| **e** | Same approver approving again rejected with `400 DuplicateApprovalProhibited`. | **PASS** | `test_item_e_anti_duplicate_approval` | Second signoff attempt by `usr_appr_elena` returns `400 DuplicateApprovalProhibited`. |
| **f** | Second approval by distinct approver commits atomically, `approval_count: 2`, active account updated. | **PASS** | `test_item_f_second_approval_commits_atomically` | State: `COMMITTED`. Active vendor account updated to proposed ref in atomic transaction. |
| **g** | Approving already `COMMITTED`, `REJECTED`, `CANCELLED`, or `EXPIRED` request rejected with `400 InvalidStatusTransition`. | **PASS** | `test_item_g_terminal_status_rejection` | Subsequent approval attempts on terminal requests return `400 InvalidStatusTransition`. |
| **h** | Reject & cancel workflows exist as routes, work, leave old account unchanged. | **PASS** | `test_item_h_reject_and_cancel_leave_old_account_unchanged` | `/reject` sets `REJECTED`; `/cancel` sets `CANCELLED`. In both cases, active vendor details remain unchanged. |
| **i** | Expiration: request older than configured lifetime cannot be approved, marked `EXPIRED`. | **PASS** | `test_item_i_expiration_handling_no_sleep` | Injected backdated timestamp; approval attempt sets status `EXPIRED` and returns `400 RequestExpired`. |
| **j** | Tamper detection: approvals bound to canonical SHA-256 fingerprint. Documented modify route invalidates prior approvals. | **PASS** | `test_item_j_modify_route_and_tamper_detection` | `PUT /api/v1/bank-changes/{id}` increments version, resets to `PENDING_APPROVAL`, clears prior approvals. DB tampering triggers `409 FingerprintMismatch`. |
| **k** | Concurrency safety: 2 approvers at same instant commit cleanly; same approver twice accepts exactly one. | **PASS** | `test_item_k_concurrency_simultaneous_approvers` | Multi-threaded test via `ThreadPoolExecutor` against PostgreSQL 16 with `SELECT ... FOR UPDATE` locks. Exactly 1 `COMMITTED`, no 500 error. |
| **l** | Encryption at rest: proposed details Fernet-encrypted; raw account absent from DB column; wrong key fails safely. | **PASS** | `test_item_l_encryption_at_rest_and_wrong_key_safety` | PostgreSQL column `encrypted_proposed_bank_details` contains Fernet token (`gAAAAA...`). Tampered token raises `ValueError` safely. |
| **m** | Audit trail endpoint returns immutable chronological record with no raw accounts; immutability enforced. | **PASS** | `test_item_m_audit_trail_immutability` | `/audit` returns chronological log without raw accounts. Both ORM (`PermissionError`) and PostgreSQL trigger (`trg_bank_approval_audit_logs_immutable`) block `UPDATE` and `DELETE`. |
| **n** | Linked risk assessment endpoint returns warnings/snapshot; AI score never authorizes bank changes. | **PASS** | `test_item_n_ai_score_never_bypasses_human_approval` | `/risk-assessment` returns `STRICT_HUMAN_APPROVAL_MANDATORY`. AI risk score variation never bypasses dual human sign-off. |

---

## 3. Defects Identified, Root Causes, and Remediations

### Bug 1: Requester Self-Approval Returned `403 AccessDenied` Instead of `403 SelfApprovalProhibited`
- **Failing Reproduction**:
  `tests/test_bank_approval_qa.py::test_reproduce_requester_self_approval_must_return_403_self_approval_prohibited` failed with:
  `AssertionError: Expected SelfApprovalProhibited, got {'error': 'AccessDenied'}`.
- **Root Cause**:
  In `sentinel/backend/app/routes/bank_approvals.py` line 177:
  ```python
  def approve_bank_change(..., current_user: User = Depends(require_role(["FINANCE_APPROVER", "FINANCE_ADMIN"]))):
  ```
  FastAPI's `require_role` dependency intercepted the request before the domain service could execute. Because a requester (`usr_req_sarah`) lacks approver roles, generic role denial (`AccessDenied`) was returned before checking if the caller was the requester of the target change request.
- **Fix**:
  Updated `approve_bank_change` to authenticate the user via `Depends(authenticate_user)` and delegate authorization to `approve_bank_change_request` in `sentinel/backend/app/services/bank_approval_service.py`. The service evaluates anti-self-approval (Step 4) *before* approver role checks (Step 5), correctly logging audit evidence and raising `403 SelfApprovalProhibited`.
- **Verification**: `test_item_b_anti_self_approval_both_roles` passes.

---

### Bug 2: Missing HTTP Route for Change Request Modification (Item j)
- **Failing Reproduction**:
  Clients had no endpoint to modify a pending request. `PUT /api/v1/bank-changes/{request_id}` returned `405 Method Not Allowed`.
- **Root Cause**:
  `modify_change_request` was implemented in `bank_approval_service.py` (lines 679-779), but was never registered as an HTTP route in `routes/bank_approvals.py`.
- **Fix**:
  Added `PUT /api/v1/bank-changes/{request_id}` endpoint in `routes/bank_approvals.py` accepting schema `ModifyBankChangeRequest`. Modification increments version, clears prior approvals, recalculates the SHA-256 fingerprint, and resets status to `PENDING_APPROVAL`.
- **Verification**: `test_item_j_modify_route_and_tamper_detection` passes.

---

### Bug 3: Schema Key Discrepancies Between Frontend and Backend
- **Failing Reproduction**:
  Frontend `NewBankChangeModal.tsx` dispatched `proposed_bank_account` while backend `CreateBankChangeRequest` expected `proposed_account_number` with `extra="forbid"`, returning `422 Unprocessable Entity`.
  Frontend `approveBankChange` sent `{ notes: "..." }` while backend expected `{ comment: "..." }`.
  Frontend `cancelBankChange` sent empty POST body, triggering 422.
- **Root Cause**:
  In `sentinel/backend/app/schemas/bank_approval.py`, schemas lacked validation aliases and had strict `extra="forbid"`.
- **Fix**:
  Added `AliasChoices("proposed_account_number", "proposed_bank_account")` and `AliasChoices("comment", "notes")` in schemas. Configured `extra="ignore"` and made `CancelActionRequest` payload optional in `routes/bank_approvals.py`. Updated frontend `client.ts` to supply both keys and handle array audit responses.
- **Verification**: `test_item_a_create_bank_change_request_and_masking` and frontend build pass without errors.

---

### Bug 4: Audit Trail Immutability Not Enforced at Database and ORM Layers (Item m)
- **Failing Reproduction**:
  Direct `UPDATE` or `DELETE` on `bank_approval_audit_logs` succeeded without raising errors.
- **Root Cause**:
  `bank_approval_audit_logs` lacked database-level triggers and SQLAlchemy model listeners preventing mutation.
- **Fix**:
  1. Created Alembic migration `20261120_0005_audit_log_immutability.py` defining PostgreSQL trigger `trg_bank_approval_audit_logs_immutable` and trigger function `block_audit_log_mutation()`.
  2. Added SQLAlchemy event listeners (`before_update`, `before_delete`) on `ApprovalAuditLog` model raising `PermissionError`.
- **Verification**: `test_item_m_audit_trail_immutability` passes for both ORM and raw SQL mutations.

---

## 4. Test Suite Totals

- **Previous Baseline**: 103 tests passing
- **New Bank Approval Priority Tests**: 14 tests passing
- **Total Backend Test Suite**: **117 tests passing**, 0 failed, 1 warning (Starlette deprecation)
- **System Verification (`verify_sentinel.py`)**: 7 of 7 checks PASSED
