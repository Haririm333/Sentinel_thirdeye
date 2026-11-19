# SENTINEL - Phase 1 Architecture Specification

## 1. System Overview
**SENTINEL** is a security-grade API Behavior Monitoring and Suspicious Activity Detection System. Its primary mission is to provide continuous visibility into inter-system API activity across three enterprise systems:
1. **LedgerOne**: Core financial management and vendor disbursement platform.
2. **HelpDeskr**: Enterprise customer and vendor ticketing support system.
3. **TallyBridge**: Integration middleware synchronizing transactional data between external platforms and LedgerOne.

Phase 1 establishes the ingestion pipeline, schema enforcement, data normalization, sensitive data sanitization, cryptographic integrity hashing, and persistent storage.

---

## 2. Component Architecture

```
  +-------------------------------------------------------------+
  |              Incoming API Activity Event Sources            |
  |    (LedgerOne, HelpDeskr, TallyBridge, Event Simulator)     |
  +-------------------------------------------------------------+
                               |
                               | HTTP POST /api/v1/events (JSON)
                               v
  +-------------------------------------------------------------+
  |                    FastAPI Web Tier                         |
  |  - SecurityHeadersMiddleware (HSTS, CSP, nosniff, DENY)     |
  |  - RequestSizeLimitMiddleware (Strict 1 MB DoS limit)       |
  |  - Host Binding Validation (127.0.0.1 for local dev)        |
  +-------------------------------------------------------------+
                               |
                               v
  +-------------------------------------------------------------+
  |                   Schema & Validation Layer                 |
  |  - Pydantic v2 Schema Enforcement (EventCreate)             |
  |  - Strict UUID v4 regex validation                          |
  |  - ISO 8601 parsing & UTC timezone normalization            |
  |  - RFC-compliant IP address validation (IPv4/IPv6)          |
  |  - HTTP Method & Status code range checks                   |
  |  - Strict 'extra="forbid"' (Anti-parameter injection)       |
  +-------------------------------------------------------------+
                               |
                               v
  +-------------------------------------------------------------+
  |                   Event Processing Service                  |
  |  1. Anti-Replay / Duplicate Detection                       |
  |     - Query api_events for event_id                         |
  |     - Rejection: HTTP 409 Conflict                          |
  |     - Audit: Log DUPLICATE_EVENT_ATTEMPT                    |
  |  2. Service Identity Verification                           |
  |     - Check service_identities registry                     |
  |     - Reject SUSPENDED services (HTTP 403)                  |
  |     - Flag UNREGISTERED services (Audit INFO)               |
  |  3. Data Sanitization & Secret Redaction                    |
  |     - Strip passwords, API keys, tokens                    |
  |     - Mask Bank Account numbers (preserve last 4 digits)    |
  |     - Luhn credit card detection & redaction                |
  |  4. Cryptographic Integrity Hashing                         |
  |     - SHA-256 canonical hash computation                   |
  +-------------------------------------------------------------+
                               |
                               v
  +-------------------------------------------------------------+
  |                  SQLAlchemy ORM Data Tier                   |
  |  - Managed Connection Pooling (pre-ping, timeout, overflow) |
  |  - PostgreSQL Database (sentinel_db)                        |
  |  - Alembic Schema Migrations                                |
  |                                                             |
  |  [api_events]     [service_identities]   [security_audit]   |
  |  (Activity Logs)  (Authorized Services)  (Security Audits)  |
  +-------------------------------------------------------------+
```

---

## 3. Data Flow and Ingestion Lifecycle

1. **Ingress**: An API client or integration pipeline sends a JSON payload representing API telemetry to `POST /api/v1/events`.
2. **Network & Size Boundary**: The `RequestSizeLimitMiddleware` inspects the `Content-Length`. If it exceeds 1 MB, the request is immediately aborted with HTTP 413.
3. **Pydantic Validation**:
   - Fields are stripped of whitespace.
   - Timestamps are converted from any timezone offset (e.g. `+05:30`) to standardized UTC.
   - `extra="forbid"` rejects any unrecognized fields to prevent payload tampering.
4. **Duplicate Detection**: The service checks whether `event_id` is already present in the database.
   - If present: logs a `DUPLICATE_EVENT_ATTEMPT` security audit and raises HTTP 409 Conflict.
5. **Sanitization**: All string identifiers and metadata (`endpoint`, `resource_id`, `approval_reference`) are scanned by `sanitizer.py`. Any credentials, bearer tokens, or full bank account numbers are redacted or masked before reaching database memory.
6. **Integrity Hashing**: A deterministic SHA-256 hash of the canonicalized event payload is computed and stored alongside the event as `payload_hash`.
7. **Storage**: The event is committed to the PostgreSQL `api_events` table.
8. **Egress**: Returns HTTP 201 Created with `{ "status": "accepted", "event_id": "...", "received_at": "..." }`.

---

## 4. Database Indexing Strategy
To support real-time querying without scanning table partitions, the following indexes are maintained:
- **`ix_api_events_event_id`**: Unique B-tree index on UUID `event_id` for instant deduplication lookups.
- **`ix_api_events_timestamp`**: Temporal B-tree index for range queries and chronological windowing.
- **`ix_api_events_source_system`**: Filter index by source (LedgerOne, HelpDeskr, TallyBridge).
- **`ix_api_events_service_identity`**: Filter index for caller service identity.
- **`ix_api_events_endpoint`**: Lookup index for requested API URI paths.
- **`ix_api_events_ts_source`**: Composite index `(timestamp, source_system)` for system-specific temporal feeds.
- **`ix_api_events_service_endpoint`**: Composite index `(service_identity, endpoint)` for baseline deviation queries.
- **`ix_api_events_auth_action`**: Composite index `(auth_identity, action)` for user behavioral queries.
