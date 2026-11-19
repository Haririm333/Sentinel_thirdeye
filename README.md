# SENTINEL: API Behaviour Monitoring & Suspicious Activity Detection System
## Phase 1: Foundation and API Event Collection

---

## 1. Project Overview
**SENTINEL** is an enterprise-grade security monitoring platform designed to ingest, validate, normalize, and store API activity events across business systems.

In Phase 1, SENTINEL establishes the resilient backend foundation to monitor three core systems:
1. **LedgerOne**: Finance and vendor payment management system.
2. **HelpDeskr**: Enterprise customer and vendor support system.
3. **TallyBridge**: Integration middleware connecting external accounting software to LedgerOne.

### Key Objectives Achieved in Phase 1:
- **Strict Ingestion**: High-throughput REST API endpoint (`POST /api/v1/events`) validating telemetry schemas using Pydantic v2.
- **Normalization**: Standardizes timestamps to UTC and enforces RFC-compliant IP address and UUID formats.
- **Sanitization**: Proactively redacts API tokens, passwords, and full bank account numbers before storage.
- **Tamper Evidence**: Calculates SHA-256 canonical integrity hashes for each event.
- **Anti-Replay Protection**: Identifies and rejects duplicate `event_id` submissions with HTTP 409 Conflict, logging them into a dedicated security audit log.
- **Persistent Storage**: Production PostgreSQL database with Alembic schema migrations and composite indexing.
- **Event Simulator**: Realistic Python client transmitting legitimate, anomalous, bulk, and fraudulent events.

---

## 2. Architecture & Design Decisions

### Clean Layered Architecture
```
sentinel/
├── .env.example                     # Environment template
├── .gitignore                       # Git ignore rules
├── README.md                        # Project documentation
├── backend/
│   ├── requirements.txt             # Pinned, tested dependencies
│   ├── alembic.ini                  # Alembic migration configuration
│   ├── alembic/                     # Database migrations
│   │   ├── env.py                   # Dynamic SQLAlchemy configuration
│   │   └── versions/
│   │       └── 20261120_0001_initial_schema.py # Initial migration
│   ├── app/
│   │   ├── main.py                  # FastAPI entry point & exception handlers
│   │   ├── config.py                # Pydantic Settings & security bindings
│   │   ├── database.py              # SQLAlchemy engine & session management
│   │   ├── models/                  # Database models
│   │   │   ├── base.py              # Declarative base
│   │   │   ├── api_event.py         # Ingested API telemetry
│   │   │   ├── service_identity.py  # Service registry
│   │   │   └── security_audit.py    # Internal security audit logs
│   │   ├── schemas/                 # Pydantic v2 schemas
│   │   │   ├── event.py             # Event validation & responses
│   │   │   ├── service.py           # Service registry schemas
│   │   │   └── audit.py             # Security audit schemas
│   │   ├── routes/                  # API endpoints
│   │   │   ├── health.py            # /health probe
│   │   │   └── events.py            # /api/v1/events endpoints
│   │   ├── services/                # Business logic
│   │   │   ├── event_service.py     # Ingestion, deduplication, & queries
│   │   │   ├── audit_service.py     # Safe audit log recorder
│   │   │   ├── sanitizer.py         # Secret & bank account redaction
│   │   │   └── seed_data.py         # Baseline service identities
│   │   └── middleware/              # Defensive middlewares
│   │       ├── request_size_limit.py# DoS mitigation (1 MB limit)
│   │       └── security_headers.py  # CSP, HSTS, nosniff, DENY
│   ├── simulator/
│   │   └── event_simulator.py       # Multi-scenario event generator
│   └── tests/                       # Automated Pytest suite
│       ├── conftest.py              # Test harness & fixtures
│       ├── test_events.py           # Ingestion & retrieval tests
│       ├── test_duplicate_handling.py # Anti-replay tests
│       ├── test_validation.py       # Schema validation tests
│       ├── test_sanitizer.py        # Sensitive data redaction tests
│       ├── test_health.py           # System readiness tests
│       └── test_middleware.py       # Security headers & size limits
└── docs/
    ├── architecture.md              # Technical architecture specification
    ├── data_dictionary.md           # Database tables and column definitions
    ├── security_architecture.md     # Threat model and defensive controls
    └── postgresql_setup_windows.md  # Windows 11 database installation guide
```

### Key Design Decisions:
1. **Pydantic v2 with `extra="forbid"`**: Strictly forbids undeclared attributes to prevent parameter injection and mass assignment vulnerabilities.
2. **Deterministic SHA-256 Ingestion Hash**: Guarantees non-repudiation and verification of historical logs.
3. **Dedicated `security_audit_events` Table**: Ingestion failures, duplicate attempts, and sanitized payloads generate independent security audits for SOC visibility.
4. **Localhost Binding Enforcement**: In development, `config.py` verifies that network bindings are restricted to `127.0.0.1` to prevent unintentional exposure on local subnets.

---

## 3. Windows 11 Installation & Setup

### Prerequisites:
- Windows 11 (64-bit)
- Python 3.10+ installed
- PowerShell 5.1 or PowerShell 7

### Step 1: Open PowerShell
Open Windows PowerShell in the project directory:
```powershell
cd "e:\project crimathon\drive-download-20261119T081747Z-1-001\pipeline buid"
```

### Step 2: Install Python Dependencies
```powershell
pip install -r sentinel\backend\requirements.txt
```

---

## 4. PostgreSQL Setup

### Option 1: Automated Portable PostgreSQL (Zero Admin Rights Needed)
SENTINEL includes an automated runner that sets up a local PostgreSQL 16 server in user space:
```powershell
python sentinel\setup_portable_postgres.py
```
This automatically initializes the database, creates the user `sentinel_user` with password `sentinel_secure_pass`, and creates the database `sentinel_db`.

### Option 2: Pre-existing PostgreSQL Service
If you already have PostgreSQL running:
1. Connect via `psql`:
```powershell
psql -U postgres -h 127.0.0.1 -p 5432
```
2. Execute setup commands:
```sql
CREATE ROLE sentinel_user WITH LOGIN PASSWORD 'sentinel_secure_pass';
CREATE DATABASE sentinel_db OWNER sentinel_user;
GRANT ALL PRIVILEGES ON DATABASE sentinel_db TO sentinel_user;
```

---

## 5. Environment Configuration

Copy the `.env.example` file to create your local `.env`:
```powershell
Copy-Item sentinel\.env.example sentinel\backend\.env
```

Default `.env` configuration:
```ini
ENVIRONMENT=development
HOST=127.0.0.1
PORT=8000
DATABASE_URL=postgresql+psycopg://sentinel_user:sentinel_secure_pass@127.0.0.1:5432/sentinel_db
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30
MAX_REQUEST_SIZE_BYTES=1048576
LOG_LEVEL=INFO
ALLOWED_SOURCE_SYSTEMS=["LedgerOne","HelpDeskr","TallyBridge"]
```

---

## 6. Database Migrations

Apply Alembic migrations to set up tables and indexes:
```powershell
cd sentinel\backend
alembic upgrade head
cd ..\..
```

Seed initial service identities (LedgerOne, HelpDeskr, TallyBridge):
```powershell
python -m sentinel.backend.app.services.seed_data
```

---

## 7. How to Run the Backend

Launch the FastAPI application with Uvicorn:
```powershell
python -m uvicorn sentinel.backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Health Check**: `http://127.0.0.1:8000/health`
- **Interactive Swagger Documentation**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

---

## 8. How to Run the Test Suite

Execute the automated Pytest suite (21 unit and integration tests):
```powershell
cd sentinel\backend
pytest -v
cd ..\..
```

### Test Coverage Highlights:
- **Valid event submission**: Tests ingestion, normalization, and HTTP 201 response.
- **Duplicate handling**: Verifies HTTP 409 Conflict, non-silent rejection, and audit log creation.
- **Input validation**: Verifies HTTP 422 for missing required fields, bad UUIDs, invalid HTTP verbs, bad IP addresses, and negative byte sizes.
- **Data sanitization**: Verifies redaction of passwords, tokens, and masking of bank account numbers.
- **Pagination & filtering**: Verifies query filtering by system, service identity, HTTP status code, action, and timestamps.
- **Middleware**: Verifies HTTP 413 request size limits and defensive security headers.

---

## 9. How to Run the Event Simulator

The test simulator transmits realistic HTTP requests to the live running backend.

### Run All Scenarios (Default: 30 events with duplicate & malformed edge tests):
```powershell
python sentinel\backend\simulator\event_simulator.py --count 30 --test-duplicates --test-invalid
```

### Specific Simulation Scenarios:
- **Normal vendor reads**:
  ```powershell
  python sentinel\backend\simulator\event_simulator.py --scenario vendor_reads --count 15
  ```
- **Normal payment checks**:
  ```powershell
  python sentinel\backend\simulator\event_simulator.py --scenario payment_checks --count 15
  ```
- **Vendor profile updates**:
  ```powershell
  python sentinel\backend\simulator\event_simulator.py --scenario profile_updates --count 10
  ```
- **Unusual bulk data requests (Large payloads)**:
  ```powershell
  python sentinel\backend\simulator\event_simulator.py --scenario bulk_requests --count 5
  ```
- **Vendor bank account modification attempts**:
  ```powershell
  python sentinel\backend\simulator\event_simulator.py --scenario bank_modifications --count 5
  ```

---

## 10. API Specification & Example Requests

### A. Health Probe
**Request**:
```bash
curl -X GET "http://127.0.0.1:8000/health"
```
**Response (HTTP 200 OK)**:
```json
{
  "status": "healthy",
  "service": "SENTINEL API Activity Monitor",
  "version": "1.0.0",
  "environment": "development",
  "database": {
    "status": "connected",
    "latency_ms": 1.75
  },
  "timestamp": "2026-11-20T02:39:41.936081Z"
}
```

---

### B. Ingest API Event
**Request**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "7ee58955-fb69-49fb-8922-6fed56397dae",
    "timestamp": "2026-11-20T02:00:00Z",
    "source_system": "LedgerOne",
    "service_identity": "srv-ledgerone-core",
    "endpoint": "/api/v1/vendors/vnd_10482",
    "http_method": "GET",
    "http_status_code": 200,
    "request_size_bytes": 185,
    "response_size_bytes": 1580,
    "source_ip": "10.0.1.45",
    "auth_identity": "usr_fin_882",
    "action": "READ_VENDOR_RECORD",
    "resource_type": "VENDOR",
    "resource_id": "vnd_10482",
    "approval_reference": null
  }'
```
**Response (HTTP 201 Created)**:
```json
{
  "status": "accepted",
  "event_id": "7ee58955-fb69-49fb-8922-6fed56397dae",
  "received_at": "2026-11-20T02:39:42.100523Z"
}
```

---

### C. Duplicate Event Rejection
**Submitting the same `event_id` again:**
**Response (HTTP 409 Conflict)**:
```json
{
  "detail": {
    "error": "DuplicateEventError",
    "message": "An event with event_id '7ee58955-fb69-49fb-8922-6fed56397dae' has already been processed.",
    "event_id": "7ee58955-fb69-49fb-8922-6fed56397dae"
  }
}
```

---

### D. Query Events with Filtering & Pagination
**Request**:
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/events?source_system=LedgerOne&http_status_code=200&page=1&limit=2"
```
**Response (HTTP 200 OK)**:
```json
{
  "total": 24,
  "page": 1,
  "limit": 2,
  "pages": 12,
  "items": [
    {
      "event_id": "cb546a3c-5985-49f8-873d-55885824a213",
      "timestamp": "2026-11-19T21:09:44.601769Z",
      "source_system": "LedgerOne",
      "service_identity": "srv-ledgerone-core",
      "endpoint": "/api/v1/vendors/vnd_19283",
      "http_method": "GET",
      "http_status_code": 200,
      "request_size_bytes": 185,
      "response_size_bytes": 1580,
      "source_ip": "10.0.1.45",
      "auth_identity": "usr_sup_401",
      "action": "READ_VENDOR_RECORD",
      "resource_type": "VENDOR",
      "resource_id": "vnd_19283",
      "approval_reference": null,
      "id": 30,
      "received_at": "2026-11-20T02:39:44.612837Z",
      "payload_hash": "976c0bbc2d1daf622c99ef9c02809152ff3d8cb490ce99a24cb7008adf16844a"
    }
  ]
}
```

---

### E. Single Event Retrieval
**Request**:
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/events/cb546a3c-5985-49f8-873d-55885824a213"
```
**Response (HTTP 200 OK)**:
```json
{
  "event_id": "cb546a3c-5985-49f8-873d-55885824a213",
  "timestamp": "2026-11-19T21:09:44.601769Z",
  "source_system": "LedgerOne",
  "service_identity": "srv-ledgerone-core",
  "endpoint": "/api/v1/vendors/vnd_19283",
  "http_method": "GET",
  "http_status_code": 200,
  "request_size_bytes": 185,
  "response_size_bytes": 1580,
  "source_ip": "10.0.1.45",
  "auth_identity": "usr_sup_401",
  "action": "READ_VENDOR_RECORD",
  "resource_type": "VENDOR",
  "resource_id": "vnd_19283",
  "approval_reference": null,
  "id": 30,
  "received_at": "2026-11-20T02:39:44.612837Z",
  "payload_hash": "976c0bbc2d1daf622c99ef9c02809152ff3d8cb490ce99a24cb7008adf16844a"
}
```

---

## 11. Known Limitations (Phase 1)
1. **Synchronous Ingestion Model**: In Phase 1, events are written synchronously to PostgreSQL. For multi-thousand events/sec ingestion in future phases, an asynchronous message queue (e.g. Kafka/Redis) or asynchronous worker pool can be integrated.
2. **Rule-Based Sanitization**: Sanitizer employs deterministic regex and Luhn checks; contextual natural language entity recognition will be added in Phase 2.
3. **Localhost Single Node**: Phase 1 is optimized for a single-node Windows 11 development workstation (16 GB RAM). Clustered PostgreSQL and multi-region deployment are planned for future AWS deployment.

---

## 12. Recommended Phase 2 Roadmap
- **Phase 2A: Statistical Baseline & Anomaly Rules Engine**: Rule-based detection flags for unusual bulk data requests, off-hours administrative access, and velocity violations without full ML.
- **Phase 2B: API Authentication & Service Identity Mutual TLS**: Client token verification (JWT) and role-based access control (RBAC).
- **Phase 2C: High-Velocity Batch Ingestion Endpoint**: `POST /api/v1/events/batch` accepting batches of events in a single transactional write.
