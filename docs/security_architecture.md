# SENTINEL Security Architecture & Threat Model

## 1. Threat Modeling & Controls (Phase 1)

| Threat Vector | Risk Description | Phase 1 Mitigation Implemented |
| :--- | :--- | :--- |
| **Denial of Service (DoS)** | Attacker floods the event endpoint with multi-gigabyte payloads to crash the server or exhaust memory. | `RequestSizeLimitMiddleware` inspects `Content-Length` and rejects any payload > 1 MB with HTTP 413. Max logical field limits in Pydantic. |
| **Parameter Pollution & Injection** | Malicious client submits unauthorized fields to manipulate backend ORM or inject arbitrary properties. | `ConfigDict(extra="forbid")` rejects any payload with undeclared fields with HTTP 422. Input sanitized. |
| **Event Replay / Duplicate Collision** | An attacker replays previously captured events or attempts to overwrite historical logs. | Unique B-tree index on `event_id` in PostgreSQL. Active check in `event_service` that rejects duplicates with HTTP 409 Conflict and records an internal audit log. |
| **Credential & Secret Leakage** | Monitored systems inadvertently include API tokens, passwords, or full bank account numbers in audit trails. | Dedicated `sanitizer.py` scans all strings. Replaces tokens/passwords with `[REDACTED_SECRET]`, masks full bank accounts preserving only last 4 digits (`***masked***1234`), and redacts Luhn-valid credit card numbers. |
| **Rogue Service Impersonation** | Compromised or decommissioned service identities submit false telemetry. | Registry table `service_identities`. Rejects suspended services with HTTP 403 Forbidden and alerts on unknown service IDs. |
| **Tamper-Evident Records** | Malicious database administrator alters stored records undetected. | Canonical SHA-256 payload integrity hash calculated and stored with every event record as `payload_hash`. |
| **Information Disclosure via Errors** | Database stack traces or connection strings returned in HTTP responses. | Centralized FastAPI exception handlers sanitize all 422, 409, 404, and 500 error bodies into uniform JSON without stack traces. |
| **Network Exposure** | Unauthenticated local services inadvertently listen on public network interfaces. | Configuration validator explicitly prevents local development servers from binding to `0.0.0.0`; requires `127.0.0.1`. |

---

## 2. Hardening Headers
All HTTP responses carry the following defensive headers via `SecurityHeadersMiddleware`:
- `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing attacks.
- `X-Frame-Options: DENY`: Prevents UI redressing / clickjacking.
- `Content-Security-Policy: default-src 'self'`: Disallows loading unauthorized external scripts.
- `Referrer-Policy: no-referrer`: Prevents leaking paths across domain boundaries.
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`: Disables all invasive client device features.

---

## 3. Safe Logging Policy
- **No Passwords or Secrets**: Log formatters and audit records strictly omit authorization headers, passwords, and private keys.
- **No Raw Financial Identifiers**: Financial account numbers are masked before reaching log buffers.
- **Traceable Identifiers**: Ingestion anomalies are tagged with `audit_id` and `event_id` for security operations correlation.
