# SENTINEL - Phase 2: Deterministic Security Detection Engine

## 1. Engine Architecture & Execution Lifecycle

The SENTINEL Detection Engine operates on an inline-intercept pattern integrated directly into the event ingestion pipeline:

```
Incoming Event JSON -> Validation -> Sanitization -> Persistence (api_events)
                                                               │
                                                               ▼
                                                  [Detection Engine]
                                                               │
               ┌───────────────────────┬───────────────────────┼───────────────────────┬───────────────────────┐
               ▼                       ▼                       ▼                       ▼                       ▼
          [Rule 1: Rate]        [Rule 2: Bulk]          [Rule 3: IP]        [Rule 4: Priv]          [Rule 5: Bank]       [Rule 6: Appr]
               │                       │                       │                       │                       │                │
               └───────────────────────┴───────────────────────┼───────────────────────┴───────────────────────┴────────────────┘
                                                               ▼
                                               [Incident Correlator / Deduplication]
                                                               │
                                            ┌──────────────────┴──────────────────┐
                                            ▼                                     ▼
                                  [Existing Incident Updated]           [New Incident Created]
                                  (Within Correlation Window)           (Fresh finding)
```

### Ingestion Sequence Guarantee:
1. **Receive & Validate**: Structural schema check via Pydantic v2.
2. **Sanitize**: Credentials and full financial identifiers are redacted in-memory.
3. **Persist Event**: Committed to `api_events` table before rules run.
4. **Evaluate Rules**: The event is evaluated against all active rules in `rule_registry`.
5. **Correlate & Deduplicate**: Matches existing incidents within the 10-minute sliding window or opens a new incident.
6. **Fault Isolation**: Any runtime anomaly in a detection rule is logged to `security_audit_events` with severity `HIGH`; the event itself is never lost or rolled back.

---

## 2. Detection Rule Catalog

### Rule 1: Excessive API Request Rate (`SEC-RULE-RATE-001`)
- **Objective**: Identify automated scraping, credential stuffing, enumeration, or denial-of-service attempts by an authorized service identity.
- **Trigger**: Request count from the same `service_identity` exceeds threshold (default: 20 requests) within a sliding temporal window (default: 60s).
- **Base Severity**: `MEDIUM` (Base score: 45).
- **Modifiers**:
  - `rate > 1.5x threshold`: +15 points.
  - `rate > 3.0x threshold`: +30 points.
- **Evidence Fields**: `measured_request_count`, `threshold_count`, `time_window_seconds`, `window_start`, `window_end`, `sample_event_ids`, `scoring_breakdown`.

---

### Rule 2: Bulk Vendor Data Access (`SEC-RULE-BULK-001`)
- **Objective**: Detect mass exfiltration of sensitive vendor databases.
- **Trigger**:
  - *Single Large Response*: `response_size_bytes >= 5,000,000` (5 MB) on vendor endpoints (`/vendors`).
  - *Repeated Bulk Extraction*: >= 10 vendor access requests OR >= 15 MB cumulative response size within 300 seconds.
- **Base Severity**: `MEDIUM` (Base score: 50).
- **Modifiers**:
  - `cumulative volume > 2x limit`: +25 points (elevates to `HIGH`).
  - `both single large and repeated`: +15 points.
- **Evidence Fields**: `current_event_bytes`, `cumulative_window_bytes`, `vendor_records_accessed`, `single_response_threshold`, `relevant_event_ids`.

---

### Rule 3: Unexpected Source IP Address (`SEC-RULE-IP-001`)
- **Objective**: Flag compromised credentials or token replay from outside approved corporate networks.
- **Trigger**:
  - Activity from an IP not present in the service's configured allowlist (supports exact IP and CIDR subnets like `10.0.1.0/24`).
  - **Zero Trust Principle**: Any unconfigured or unregistered service identity is treated as *untrusted* and automatically triggers an alert.
- **Base Severity**: `HIGH` (Base score: 65).
- **Modifiers**:
  - `unregistered service`: +15 points.
  - `public internet IP`: +20 points (elevates to `CRITICAL`).
- **Evidence Fields**: `service_identity`, `source_ip`, `is_registered_service`, `configured_allowed_ips`.

---

### Rule 4: Privilege and Scope Violation (`SEC-RULE-PRIV-001`)
- **Objective**: Prevent privilege escalation, unauthorized mutations, and lateral boundary hopping.
- **Trigger**:
  - Read-only service identity attempting write operations (`POST`, `PUT`, `PATCH`, `DELETE`).
  - Service accessing API endpoints outside its sanctioned regex patterns.
  - Service attempting banking mutations when not explicitly granted `can_modify_bank_details`.
- **Base Severity**: `HIGH` (Base score: 75).
- **Modifiers**:
  - `write by read-only service`: +15 points (score 90, `CRITICAL`).
  - `unauthorized bank alteration attempt`: +20 points (score 95, `CRITICAL`).
- **Evidence Fields**: `attempted_endpoint`, `attempted_method`, `violations`, `allowed_methods`, `is_read_only`.

---

### Rule 5: Sensitive Bank Account Modification (`SEC-RULE-BANK-001`)
- **Objective**: Prevent business email compromise (BEC), payment redirection, and unauthorized vendor disbursement changes.
- **Trigger**: Any state-changing API call targeting bank accounts (`MODIFY_VENDOR_BANK_ACCOUNT`, `/bank-account`, `resource_type == BANK_ACCOUNT`).
- **Base Severity**: `CRITICAL` (Base score: 80).
- **Modifiers**:
  - `unverified or missing approval reference`: +15 points (score 95, `CRITICAL`).
- **Data Protection**: Full bank account numbers are masked before reaching the incident record (e.g. `ACC-***masked***1012`). Real bank account records are not modified during detection.

---

### Rule 6: Missing or Invalid Approval Reference (`SEC-RULE-APPR-001`)
- **Objective**: Enforce governance compliance on sensitive business operations.
- **Trigger**: Sensitive operations (`MODIFY_VENDOR_BANK_ACCOUNT`, `UPDATE_VENDOR_PROFILE`, `BULK_DATA_EXPORT`, `/profile`, `/export`) executed without an approval reference or with malformed/override strings (e.g. `EMERGENCY_OVERRIDE_NO_TICKET`).
- **Expected Pattern**: Valid ticket format matching `^APP-\d{4}-\d{4,}$` (e.g. `APP-2026-9812`).
- **Base Severity**: `HIGH` (Base score: 60).
- **Modifiers**:
  - `financial operation`: +20 points (score 80, `CRITICAL`).
  - `unverified emergency override string`: +15 points.
