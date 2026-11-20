# SENTINEL Comprehensive System QA & Architecture Audit Report

**Date**: November 20, 2026  
**Auditor**: Senior Backend + QA Engineering  
**Scope**: Full Platform Audit (Phases 1–7), Real Case Data Fit, Known Limitations

---

## 1. System-Wide Verification Summary

| Component / Subsystem | Status | Verification Tool | Summary |
| :--- | :---: | :--- | :--- |
| **System Health Probe** (`/api/v1/health`) | **PASS** | `verify_sentinel.py` / Pytest | DB connection healthy (latency ~1.5ms), environment reported accurately. |
| **Event Ingestion Pipeline** | **PASS** | Pytest (`test_events.py`, `test_middleware.py`) | 1MB payload limit enforced (`413 Payload Too Large`), malformed input rejected (`422`), duplicate events rejected (`409`). |
| **Defensive Sanitizer** | **PASS** | Pytest (`test_sanitizer.py`) | Redacts passwords, API bearer tokens, Luhn-valid credit card numbers, masks bank account numbers (`ACC-***masked***XXXX`). |
| **Security Headers** | **PASS** | Pytest (`test_middleware.py`) | Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options (`nosniff`), X-Frame-Options (`DENY`). |
| **Deterministic Rules 1–6** | **PASS** | Pytest (`test_detection_rules.py`) | Rules 1 to 6 fire correctly on thresholds; isolated rule failures do not crash ingestion (`500` prevented). |
| **Incident Management** | **PASS** | Pytest (`test_incidents_api.py`) | Correlation window deduplication, triage status lifecycle (`OPEN` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`). |
| **Isolation Forest ML** | **PASS** | Pytest (`test_ml_*.py`) / `verify_sentinel.py` | 15-feature extraction, sliding windows, calibrated thresholds, data sufficiency guard (>=20 samples). |
| **LSTM Autoencoder** | **PASS** | Pytest (`test_lstm_*.py`) / `verify_sentinel.py` | Chronological 20-event sequences per service, PyTorch CPU inference, safe `state_dict` loading, MSE reconstruction loss. |
| **Two-Person Bank Approvals** | **PASS** | Pytest (`test_bank_approval_*.py`) | Strict 2-person rule, anti-self-approval, anti-duplicate, Fernet encryption at rest, atomic PostgreSQL `SELECT ... FOR UPDATE` locks. |
| **Unified Risk Assessment** | **PASS** | Pytest (`test_unified_assessment.py`) | Hard floor, multi-tier boosts (+10, +15), unavailable models never treated as normal, clamped [0, 100]. |
| **SOC Dashboard (Frontend)** | **PASS** | Vite build / TypeScript compiler | React 19 + TypeScript builds cleanly in 7.4s with 0 errors. All 7 modules functional. |

---

## 2. Phase 4: Real Case Data Fit Analysis (Report Only)

### Findings
An investigation was conducted comparing SENTINEL's governance ticket validation against the real-world case artifacts (`E19_vendor_master_change_log.csv`):

1. **Rule 6 Pattern in Configuration**:
   In `sentinel/backend/app/detection/config.py` line 54:
   ```python
   VALID_APPROVAL_REGEX: str = r"^APP-\d{4}-\d{4,}$"
   ```
   This regex mandates governance approval references formatted strictly as `APP-<year>-<ticket>`, e.g., `APP-2026-9812`.

2. **Real Case Data Formats in `E19_vendor_master_change_log.csv`**:
   Inspection of the evidence changelog revealed two distinct approval ticket conventions:
   - **Individual approvals**: `APR-\d{4}` (e.g. `APR-1102`, `APR-1108`, `APR-1182`).
   - **Bulk import batch approvals**: `BULK-\d{4}` (e.g. `BULK-0731`).

3. **Impact**:
   If raw events containing legitimate enterprise changes (e.g. approved via `APR-1182` or batch `BULK-0731`) are ingested directly, Rule 6 (`SEC-RULE-APPR-001`) flags them as "Malformed approval reference" because they fail to match `^APP-\d{4}-\d{4,}$`.

### Proposed Minimal Fix (Non-Breaking, Configurable)
Update `DetectionEngineSettings` in `sentinel/backend/app/detection/config.py`:
```python
VALID_APPROVAL_REGEX: str = Field(
    default=r"^(APP-\d{4}-\d{4,}|APR-\d{4,}|BULK-\d{4,})$",
    description="Regex pattern for valid governance approval references (supporting APP-YYYY-NNNN, APR-NNNN, and BULK-NNNN)."
)
```
*Note: In accordance with project instructions, this is submitted as a proposal only and has not been applied to production code pending stakeholder sign-off.*

---

## 3. Clarification of "Step 8" in Bank Approval Lifecycle

The phrase *"The existing active bank account remains active until Step 8 of the second approval commits"* in `sentinel/README.md` refers to the internal step sequence executed inside `approve_bank_change_request` in `bank_approval_service.py`:

1. **Step 1: Row Locking**: Acquire atomic row-level lock (`SELECT ... FOR UPDATE`) on `BankChangeRequest`.
2. **Step 2: Expiration Guard**: Check `expires_at`; transition to `EXPIRED` if lifetime exceeded.
3. **Step 3: Status Transition**: Verify request is currently in `PENDING_APPROVAL` or `PARTIALLY_APPROVED`.
4. **Step 4: Anti-Self-Approval**: Check `approver.user_id != requester_id`; reject with `403 SelfApprovalProhibited` if matched.
5. **Step 5: Role Authorization**: Check approver possesses `FINANCE_APPROVER` or `FINANCE_ADMIN`; reject with `403 AccessDenied` if lacking.
6. **Step 6: Anti-Duplicate Verification**: Check `approver.user_id not in prior_approvers`; reject with `400 DuplicateApprovalProhibited`.
7. **Step 7: Cryptographic Fingerprint Integrity**: Recompute SHA-256 canonical hash; reject with `409 FingerprintMismatch` if tampered.
8. **Step 8: Final Authorization & Atomic Commit**:
   - For Approval 1: Transition request to `PARTIALLY_APPROVED`, commit transaction, vendor account unchanged.
   - For Approval 2: Acquire row lock on `VendorBankAccount`, update active account details atomically, transition request to `COMMITTED`, commit transaction.

Thus, the active vendor account remains unchanged through all prior steps and approvals until Step 8 of the second independent human approval.

---

## 4. Known Limitations & Hardening Recommendations

1. **Development Authentication Adapter**:
   The `X-User-Id` header mechanism is designed for development and automated QA testing. For production deployment, integrate with an enterprise OpenID Connect (OIDC) / SAML 2.0 Identity Provider with Multi-Factor Authentication (MFA) and cryptographic JWT validation.
2. **Approval Reference Format Configurability**:
   As detailed in Section 2, legacy systems utilizing `APR-XXXX` and `BULK-XXXX` ticket formats should be added to the configurable regex whitelist.
3. **Distributed Worker Caching**:
   Sliding rate limit counters (Rule 1) and bulk access accumulators (Rule 2) currently leverage SQLAlchemy/PostgreSQL aggregation queries. In high-throughput distributed architectures (>10,000 req/s), fronting these with Redis sliding window counters will minimize database query load.
4. **Passive AI Safeguards**:
   All ML and DL anomaly detectors operate as analytical observers and risk advisors; they intentionally do not possess write or override authorization over sensitive financial transactions.
