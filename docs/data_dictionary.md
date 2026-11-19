# SENTINEL Data Dictionary

## Table 1: `api_events`
Stores normalized API telemetry collected from LedgerOne, HelpDeskr, and TallyBridge.

| Column Name | SQL Type | Nullable | Indexed | Description |
| :--- | :--- | :---: | :---: | :--- |
| `id` | BigInteger / Integer | No | PK | Auto-incrementing database primary key |
| `event_id` | String(64) | No | Yes (Unique) | Globally unique UUID assigned to the event |
| `timestamp` | DateTime(tz=True) | No | Yes | UTC timestamp when the API call occurred on the originating system |
| `received_at` | DateTime(tz=True) | No | Yes | UTC timestamp when SENTINEL accepted the event |
| `source_system` | String(50) | No | Yes | System name (`LedgerOne`, `HelpDeskr`, `TallyBridge`) |
| `service_identity` | String(100) | No | Yes | Client identifier or service account (e.g. `srv-tallybridge-sync`) |
| `endpoint` | String(255) | No | Yes | API route called (must start with `/`, e.g. `/api/v1/vendors`) |
| `http_method` | String(10) | No | Yes | Standard HTTP verb (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, etc.) |
| `http_status_code` | Integer | No | Yes | Response HTTP code (100-599) |
| `request_size_bytes`| Integer | No | No | Request body size in bytes |
| `response_size_bytes`| Integer | No | No | Response body size in bytes |
| `source_ip` | String(45) | No | Yes | Client IPv4 or IPv6 address |
| `auth_identity` | String(100) | No | Yes | Principal identity executing the action (e.g. `usr_fin_882`) |
| `action` | String(100) | No | Yes | High-level operational action (e.g. `READ_VENDOR_RECORD`) |
| `resource_type` | String(100) | No | Yes | Target resource class (e.g. `VENDOR`, `PAYMENT`, `TICKET`) |
| `resource_id` | String(255) | Yes | No | Target entity ID (sanitized, masked if financial) |
| `approval_reference` | String(100) | Yes | No | Governance ticket reference (e.g. `APP-2026-9812`) |
| `payload_hash` | String(64) | Yes | No | SHA-256 hash of canonical event payload for tamper evidence |

---

## Table 2: `service_identities`
Registry of approved integration and client services allowed to interact with monitored APIs.

| Column Name | SQL Type | Nullable | Indexed | Description |
| :--- | :--- | :---: | :---: | :--- |
| `id` | Integer | No | PK | Auto-incrementing primary key |
| `service_id` | String(100) | No | Yes (Unique) | Unique identifier string (e.g. `srv-ledgerone-core`) |
| `service_name` | String(150) | No | No | Human-readable service description |
| `source_system` | String(50) | No | Yes | Parent platform (`LedgerOne`, `HelpDeskr`, `TallyBridge`) |
| `status` | String(20) | No | No | Operational status (`ACTIVE`, `SUSPENDED`, `DECOMMISSIONED`) |
| `allowed_ips` | String(500) | Yes | No | Permitted CIDR blocks or IP whitelist |
| `created_at` | DateTime(tz=True) | No | No | Registration timestamp |
| `updated_at` | DateTime(tz=True) | No | No | Last modification timestamp |

---

## Table 3: `security_audit_events`
Internal audit log of security violations, ingestion rejections, and anomalous behaviors observed by SENTINEL.

| Column Name | SQL Type | Nullable | Indexed | Description |
| :--- | :--- | :---: | :---: | :--- |
| `id` | Integer | No | PK | Auto-incrementing primary key |
| `audit_id` | String(64) | No | Yes (Unique) | Audit log UUID |
| `timestamp` | DateTime(tz=True) | No | Yes | Ingestion audit generation timestamp (UTC) |
| `severity` | String(20) | No | Yes | `INFO`, `WARNING`, `HIGH`, `CRITICAL` |
| `event_type` | String(100) | No | Yes | Classification (e.g. `DUPLICATE_EVENT_ATTEMPT`, `SENSITIVE_DATA_REDACTED`) |
| `source_ip` | String(45) | Yes | No | Calling client IP address |
| `event_id_referenced`| String(64) | Yes | Yes | Associated `event_id` under audit |
| `details` | Text | Yes | No | Safe contextual details (no sensitive secrets) |
| `error_message` | Text | Yes | No | System exception message or error reason |
