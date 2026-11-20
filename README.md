# SENTINEL: API Behaviour Monitoring & Suspicious Activity Detection System
## Phases 1–7: Foundation, Deterministic Rules, Isolation Forest ML, LSTM Sequential Anomaly Detection, Two-Person Bank Change Enforcement, Unified Detection Integration, and SOC Security Monitoring Dashboard

---

## 1. Project Overview
**SENTINEL** is an enterprise-grade cybersecurity monitoring and transaction authorization platform that continuously analyzes API telemetry from three interconnected enterprise systems:
1. **LedgerOne**: Core financial management and vendor disbursement platform.
2. **HelpDeskr**: Enterprise customer and vendor ticketing support system.
3. **TallyBridge**: Integration software synchronizing accounting and financial data with LedgerOne.

- In **Phase 1**, SENTINEL established high-throughput event ingestion, schema enforcement, sensitive data sanitization, cryptographic integrity hashing, and PostgreSQL storage.
- In **Phase 2**, SENTINEL added an inline, modular, deterministic security detection engine that evaluates every incoming API event against configurable security rules, generating explainable security incidents with severity bands, risk scores (0–100), and structured evidence.
- In **Phase 3**, SENTINEL integrated an unsupervised machine learning anomaly detection subsystem using **Scikit-learn Isolation Forest**. The ML engine extracts 15 numerical behavioral features across sliding observation windows, calibrates anomaly thresholds against service-specific baselines, enforces data sufficiency guards, ranks feature deviations via Z-scores, and generates correlated `ML-ANOMALY-ISOFOR-001` incidents.
- In **Phase 4**, SENTINEL added deep learning **sequential anomaly detection** using a PyTorch **LSTM Autoencoder** (13,695 parameters). It models chronological sequences of 20 API events per service, extracts 15 compatible sequential features without PII, normalizes features on training sequences only, calculates reconstruction Mean Squared Error (MSE), attributes feature-level errors, and generates correlated `ML-ANOMALY-LSTM-001` incidents.
- In **Phase 5**, SENTINEL implements **Two-Person Approval and Atomic Bank Change Enforcement** for sensitive vendor bank accounts. No vendor account update activates without two distinct human approvals. Requesters cannot self-approve, approvers cannot sign off twice, requests are cryptographically bound via SHA-256 canonical fingerprints, sensitive account details are Fernet-encrypted at rest and masked in responses (`ACC-***masked***1048`), and atomic row locks ensure zero race conditions. AI detection operates strictly as analytical observation and never authorizes bank modifications.
- In **Phase 6**, SENTINEL unifies all detection subsystems into an integrated security assessment engine. It computes synergistic risk scores across deterministic rules, Isolation Forest, and LSTM sequential autoencoders using a deterministic hard floor and multi-tier compounding boosts (never blind averaging). It surfaces security incident warnings and risk snapshots directly to authorized finance personnel during bank change requests, while strictly upholding the non-bypass invariant: **AI risk scores never replace human approvals**.

---

## 2. Architecture & Design Decisions

### Clean Layered Architecture
```
sentinel/
├── .env.example                               # Environment template
├── .gitignore                                 # Git ignore rules
├── README.md                                  # Complete developer onboarding & runbook
├── verify_sentinel.py                         # Automated system verification & health harness
├── setup_portable_postgres.py                 # Automated zero-privilege PostgreSQL 16 runner
├── setup_db.py                                # Role & database initialization script
├── backend/
│   ├── requirements.txt                       # Pinned, tested dependencies
│   ├── alembic.ini                            # Alembic migration configuration
│   ├── alembic/                               # Database migrations
│   │   ├── env.py                             # Dynamic SQLAlchemy configuration
│   │   └── versions/
│   │       ├── 20261120_0001_initial_schema.py             # Phase 1: api_events, services, audit
│   │       ├── 20261120_0002_add_incidents_and_rules.py    # Phase 2: incidents, detection_rules
│   │       ├── 20261120_0003_add_bank_approvals.py          # Phase 5: two-person bank approvals
│   │       ├── 20261120_0004_add_unified_assessment_fields.py # Phase 6: risk snapshots
│   │       └── 20261120_0005_audit_log_immutability.py     # Phase 2 QA: audit trigger immutability
│   ├── app/
│   │   ├── main.py                            # FastAPI entry point, lifespan, & exception handlers
│   │   ├── config.py                          # Pydantic Settings & network binding rules
│   │   ├── database.py                        # SQLAlchemy engine, session pool, & health probe
│   │   ├── models/                            # Database models
│   │   │   ├── base.py                        # Declarative base
│   │   │   ├── api_event.py                   # Ingested API telemetry
│   │   │   ├── service_identity.py            # Service registry
│   │   │   ├── security_audit.py              # Internal security audit logs
│   │   │   ├── incident.py                    # Security incidents model
│   │   │   ├── detection_rule.py              # Detection rule model
│   │   │   └── bank_approval.py               # Vendor bank accounts, requests, approvals, audit logs
│   │   ├── schemas/                           # Pydantic v2 schemas
│   │   │   ├── event.py                       # Event validation & responses
│   │   │   ├── service.py                     # Service registry schemas
│   │   │   ├── audit.py                       # Security audit schemas
│   │   │   ├── incident.py                    # Incident and summary schemas
│   │   │   └── bank_approval.py               # Masked bank change & approval schemas
│   │   ├── routes/                            # API endpoints
│   │   │   ├── health.py                      # GET /api/v1/health probe
│   │   │   ├── events.py                      # /api/v1/events endpoints
│   │   │   ├── incidents.py                   # /api/v1/incidents & /api/v1/detection endpoints
│   │   │   ├── bank_approvals.py              # /api/v1/bank-changes endpoints (CRUD, approve, reject, cancel)
│   │   │   ├── assessment.py                  # /api/v1/assessment & risk-assessment endpoints
│   │   │   └── ml.py                          # /api/v1/ml & /api/v1/lstm endpoints
│   │   ├── services/                          # Business logic
│   │   │   ├── event_service.py               # Ingestion, deduplication, & detection trigger
│   │   │   ├── incident_service.py            # Incident creation, deduplication, triage
│   │   │   ├── risk_service.py                # Explainable 0-100 risk scoring
│   │   │   ├── audit_service.py               # Safe audit log recorder
│   │   │   ├── sanitizer.py                   # Secret & bank account redaction
│   │   │   ├── seed_data.py                   # Baseline service identities
│   │   │   ├── bank_approval_service.py       # Two-person bank approval enforcement engine
│   │   │   └── unified_assessment_service.py  # Multi-tier risk aggregation engine
│   │   ├── security/                          # Security & Cryptography
│   │   │   ├── auth.py                        # Development authentication & RBAC adapter
│   │   │   └── bank_crypto.py                 # Fernet AES encryption & SHA-256 fingerprinting
│   │   ├── detection/                         # Deterministic Detection Engine
│   │   │   ├── config.py                      # Central configurable thresholds & service scopes
│   │   │   ├── base_rule.py                   # Abstract BaseDetectionRule & DetectionResult
│   │   │   ├── engine.py                      # Orchestrator & fault-tolerant execution
│   │   │   ├── rule_registry.py               # Rule discovery and registry
│   │   │   └── rules/                         # Individual Detection Rules
│   │   │       ├── request_rate_rule.py       # Rule 1: Excessive Request Rate
│   │   │       ├── bulk_access_rule.py        # Rule 2: Bulk Vendor Data Access
│   │   │       ├── ip_anomaly_rule.py         # Rule 3: Unexpected Source IP
│   │   │       ├── privilege_violation_rule.py# Rule 4: Privilege & Scope Violation
│   │   │       ├── bank_change_rule.py        # Rule 5: Sensitive Bank Account Change
│   │   │       └── missing_approval_rule.py   # Rule 6: Missing Approval Reference
│   │   ├── ml/                                # Machine Learning Subsystems
│   │   │   ├── features.py                    # 15-dimensional behavioral feature pipeline
│   │   │   ├── detector.py                    # Isolation Forest anomaly detector
│   │   │   ├── lstm_autoencoder.py            # PyTorch sequential LSTM autoencoder model
│   │   │   └── lstm_pipeline.py               # Chronological sequence builder & normalization
│   │   └── middleware/                        # Defensive middlewares
│   │       ├── request_size_limit.py          # DoS mitigation (1 MB limit)
│   │       └── security_headers.py            # CSP, HSTS, nosniff, DENY
│   ├── simulator/
│   │   └── event_simulator.py                 # Multi-scenario event generator
│   └── tests/                                 # Automated Pytest suite (117 tests passing)
│       ├── conftest.py                        # Test harness & fixtures
│       ├── test_events.py                     # Ingestion & retrieval tests
│       ├── test_duplicate_handling.py         # Anti-replay tests
│       ├── test_validation.py                 # Schema validation tests
│       ├── test_sanitizer.py                  # Sensitive data redaction tests
│       ├── test_health.py                     # System readiness tests
│       ├── test_middleware.py                 # Security headers & size limits
│       ├── test_detection_rules.py            # Comprehensive tests for all 6 rules
│       ├── test_risk_scoring.py               # Risk scoring & severity bands tests
│       ├── test_incidents_api.py              # Incidents API, triage, & deduplication tests
│       ├── test_ml_features.py                # ML feature extraction tests
│       ├── test_ml_detector.py                # Isolation Forest training and inference tests
│       ├── test_ml_incident_integration.py    # ML incident correlation tests
│       ├── test_ml_api.py                     # ML REST endpoints tests
│       ├── test_lstm_autoencoder.py           # LSTM PyTorch model & tensor tests
│       ├── test_lstm_sequence_pipeline.py     # LSTM sequence generation & isolation tests
│       ├── test_lstm_detector.py              # LSTM thresholding & incident tests
│       ├── test_lstm_api.py                   # LSTM REST endpoints tests
│       ├── test_bank_approval_workflow.py     # Two-person bank approval lifecycle tests
│       ├── test_bank_approval_qa.py           # Bank approval priority QA tests (Items a-n)
│       └── test_unified_assessment.py         # Multi-tier risk aggregation tests
├── frontend/                                  # React 19 + TypeScript SOC Dashboard
│   ├── src/
│   │   ├── api/client.ts                      # Axios API client with RBAC persona switcher
│   │   ├── components/                        # SOC Dashboard module components
│   │   └── context/AuthContext.tsx            # Persona simulation provider
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
└── docs/
    ├── architecture.md                        # Technical architecture specification
    ├── detection_engine.md                    # Detailed detection engine & rules guide
    ├── risk_scoring.md                        # Explainable risk scoring documentation
    ├── data_dictionary.md                     # Database tables and column definitions
    ├── security_architecture.md               # Threat model and defensive controls
    ├── postgresql_setup_windows.md            # Windows 11 database installation guide
    └── qa/                                    # QA & Verification Audit Documentation
        ├── 00_baseline.md                     # Baseline status report
        ├── 01_bank_approvals_qa.md            # Phase 2 Bank Approvals priority audit
        └── 02_system_audit_report.md          # Complete system audit & real case analysis
```

---

## 3. The Six Security Detection Rules

| Rule ID | Rule Name | Severity | Base Score | Core Detection Criteria |
| :--- | :--- | :---: | :---: | :--- |
| `SEC-RULE-RATE-001` | **Excessive API Request Rate** | `MEDIUM` | 45 | Flags requests exceeding threshold (default: 20 reqs / 60s) for a single service identity. |
| `SEC-RULE-BULK-001` | **Bulk Vendor Data Access** | `MEDIUM` | 50 | Flags single downloads >= 5 MB or repeated cumulative vendor record queries (>= 10 records / >= 15 MB in 300s). |
| `SEC-RULE-IP-001` | **Unexpected Source IP** | `HIGH` | 65 | Flags activity from outside a service's sanctioned network perimeter. Unconfigured services are treated as untrusted. |
| `SEC-RULE-PRIV-001` | **Privilege & Scope Violation** | `HIGH` | 75 | Flags read-only services attempting mutations, out-of-scope endpoint requests, or unauthorized bank alterations. |
| `SEC-RULE-BANK-001` | **Sensitive Bank Account Modification** | `CRITICAL` | 80 | Flags all state-changing modifications to vendor bank accounts. Elevates if unapproved or from unexpected IP. Full bank accounts are masked. |
| `SEC-RULE-APPR-001` | **Missing Approval Reference** | `HIGH` | 60 | Flags sensitive actions (`MODIFY_VENDOR_BANK_ACCOUNT`, `UPDATE_VENDOR_PROFILE`, `BULK_DATA_EXPORT`) lacking a valid ticket matching `^APP-\d{4}-\d{4,}$`. |

---

## 4. Transparent Risk Scoring Framework

All incidents receive an explainable integer score between `0` and `100`:
- **80 – 100: CRITICAL** (Sensitive bank modifications, privilege escalation, unauthorized overrides)
- **60 – 79: HIGH** (Unexpected external IPs, out-of-scope endpoint access, missing approvals)
- **30 – 59: MEDIUM** (High request rates, bulk data extractions)
- **0 – 29: LOW** (Informational baseline deviations)

Every incident evidence dictionary records an audit breakdown (`base_score`, `modifiers`, `final_score`, `severity`).

---

## 5. Event Pipeline Processing Sequence

```
1. Receive Event   -> HTTP POST /api/v1/events (JSON)
2. Validate Event  -> Pydantic schema validation, UUID check, UTC normalization
3. Sanitize Event  -> Credential & bank account masking (sanitizer.py)
4. Persist Event   -> Committed to PostgreSQL (api_events)
5. Run Detection   -> DetectionEngine evaluates active rules against persisted event
6. Incident Action -> If triggered, incident is created or correlated into an existing incident
7. Return Response -> Returns HTTP 201 Created with { status: "accepted", event_id, received_at }
```

**Fault Isolation**: If any detection rule raises an unexpected exception, it is caught, logged to `security_audit_events` with severity `HIGH`, and the persisted event is **never lost or rolled back**.

---

## 6. Windows 11 PowerShell Setup & Execution

### Step 1: Install Dependencies
```powershell
pip install -r sentinel\backend\requirements.txt
```

### Step 2: Ensure PostgreSQL is Running & Run Migrations
```powershell
# Automated portable PostgreSQL runner (if not already running)
python sentinel\setup_portable_postgres.py

# Apply Alembic database migrations
cd sentinel\backend
alembic upgrade head
cd ..\..

# Seed baseline service identities
python -m sentinel.backend.app.services.seed_data
```

### Step 3: Run the FastAPI Backend Server
```powershell
python -m uvicorn sentinel.backend.app.main:app --host 127.0.0.1 --port 8000
```
* **Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Health Probe**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
* **Incidents Endpoint**: [http://127.0.0.1:8000/api/v1/incidents](http://127.0.0.1:8000/api/v1/incidents)
* **Detection Summary**: [http://127.0.0.1:8000/api/v1/detection/summary](http://127.0.0.1:8000/api/v1/detection/summary)

---

## 7. How to Run the Automated Test Suite

Execute the complete test suite (39 passing unit and integration tests):
```powershell
cd sentinel\backend
pytest -v
cd ..\..
```

---

## 8. How to Run the Event Simulator

Send simulated HTTP requests to the running backend to demonstrate detection and incident generation:
```powershell
# Send 30 mixed events with duplicate & malformed edge tests:
python sentinel\backend\simulator\event_simulator.py --count 30 --test-duplicates --test-invalid

# Target specific scenarios:
python sentinel\backend\simulator\event_simulator.py --scenario bank_modifications --count 5
python sentinel\backend\simulator\event_simulator.py --scenario bulk_requests --count 5
python sentinel\backend\simulator\event_simulator.py --scenario profile_updates --count 5
```

---

## 9. API Specification & Example Requests

### A. Query Security Incidents with Filters & Pagination
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/incidents?severity=CRITICAL&status=OPEN&limit=5"
```
**Response (HTTP 200 OK)**:
```json
{
  "total": 1,
  "page": 1,
  "limit": 5,
  "pages": 1,
  "items": [
    {
      "id": 1,
      "incident_id": "13e99847-015a-4ffe-86fe-14b757827157",
      "rule_id": "SEC-RULE-BANK-001",
      "rule_name": "Sensitive Bank Account Modification",
      "severity": "CRITICAL",
      "risk_score": 95,
      "status": "OPEN",
      "service_identity": "srv-ledgerone-core",
      "related_event_ids": [
        "79f5c3dd-2d88-4bda-89ce-5db7fdb38a4a"
      ],
      "resource_type": "BANK_ACCOUNT",
      "resource_id": "ACC-***masked***0719",
      "explanation": "Sensitive vendor bank account modification attempted by service 'srv-ledgerone-core' for resource 'ACC-***masked***0719'. Approval Status: UNAPPROVED / INVALID.",
      "evidence": {
        "service_identity": "srv-ledgerone-core",
        "action": "MODIFY_VENDOR_BANK_ACCOUNT",
        "endpoint": "/api/v1/vendors/vnd_20491/bank-account",
        "resource_id": "ACC-***masked***0719",
        "source_ip": "10.0.1.45",
        "is_approval_valid": false,
        "occurrence_count": 1,
        "scoring_breakdown": {
          "base_score": 80,
          "modifiers": [
            {
              "factor": "unverified_or_missing_approval",
              "points": 15,
              "reason": "Bank modification attempted with invalid/missing approval"
            }
          ],
          "final_score": 95,
          "severity": "CRITICAL"
        }
      },
      "created_at": "2026-11-20T02:54:27.260350Z",
      "updated_at": "2026-11-20T02:54:27.260350Z"
    }
  ]
}
```

---

### B. Update Incident Triage Status
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/incidents/13e99847-015a-4ffe-86fe-14b757827157/status" `
  -Method Patch -ContentType "application/json" `
  -Body '{"status":"INVESTIGATING","notes":"SOC analyst triaging unapproved override"}'
```

**Lifecycle Transition Rules**:
- `OPEN` -> `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`
- `INVESTIGATING` -> `RESOLVED`, `FALSE_POSITIVE`, `OPEN`
- `RESOLVED` -> `OPEN` (re-open)
- `FALSE_POSITIVE` -> `OPEN` (re-open)

---

### C. Inspect Registered Detection Rules
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/detection/rules"
```

---

### D. Detection Summary
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/detection/summary"
```

---

## 10. Phase 3: Machine Learning Behavioral Anomaly Detection

### Architecture & Capabilities
- **Model**: Scikit-learn `IsolationForest` ($N=100$ estimators, contamination $0.05$, random state $42$).
- **Features**: 15 numerical behavioral features extracted over sliding 300-second windows without PII/secrets.
- **Sufficiency Guard**: Requires at least 20 training observations (`MIN_SAMPLES_FOR_BASELINE = 20`) to establish a service baseline; otherwise returns `INSUFFICIENT_BASELINE`.
- **Sigmoid Calibration**: Calibrates raw negative score samples into $[0.0, 1.0]$ space. Events with score $\ge 0.65$ raise an anomaly.
- **Explainability**: Statistical Z-score calculation ranks strongest contributing deviating features.
- **Incident Engine Integration**: Dispatches to the incident engine as `ML-ANOMALY-ISOFOR-001` with correlated deduplication.
- **Fault-Tolerant Non-Blocking Ingestion**: ML failures never abort event persistence to PostgreSQL.

---

## 11. Machine Learning API Endpoints & PowerShell Commands

### A. Check ML Operational Status & Baselines
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/status" -Method Get | ConvertTo-Json -Depth 4
```

### B. Explicitly Train / Calibrate a Service Baseline
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/train" `
  -Method Post -ContentType "application/json" `
  -Body '{"service_identity": "srv-ledgerone-core", "num_samples": 60, "version": "1.0.0"}' | ConvertTo-Json -Depth 4
```

### C. List Saved Model Artifacts & Baselines
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/models" -Method Get | ConvertTo-Json -Depth 4
```

### D. Run Statistical Benchmark Evaluation Report
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/evaluation?service_identity=srv-ledgerone-core" -Method Get | ConvertTo-Json -Depth 4
```

### E. Query ML-Detected Behavioral Anomalies
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/anomalies" -Method Get | ConvertTo-Json -Depth 6
```

---

## 12. Phase 4: LSTM Autoencoder Sequential Anomaly Detection

### Architecture & Capabilities
- **Model**: PyTorch `LSTMAutoencoder` (Encoder: 1-layer LSTM hidden 32 -> latent 16; Decoder: 1-layer LSTM hidden 32 -> 15 features; 13,695 parameters).
- **Sequential Input**: Shape $(B, 20, 15)$ representing 20 consecutive chronological events for a specific service identity.
- **Normalization**: `StandardScaler` fitted strictly on normal training sequences (no future leakage).
- **Reconstruction Loss**: Mean Squared Error (MSE). Normal sequences reconstruct with $\text{MSE} \approx 0.15 - 0.40$; anomalous sequences spike to $\text{MSE} \gg 1.0$.
- **Sigmoid Calibration**: Calibrated relative overshoot mapping into $[0.0, 1.0]$. Sequences scoring $\ge 0.65$ generate incidents.
- **Explainability**: Granular per-feature reconstruction error ratio identifying specific anomalous steps.
- **Incident Engine Integration**: Dispatches to the incident engine as `ML-ANOMALY-LSTM-001` with correlated deduplication.
- **Fault-Tolerant Non-Blocking Ingestion**: Handled with independent try-except boundaries so core telemetry is never lost.

---

## 13. LSTM REST API Endpoints & PowerShell Commands

### A. Check LSTM Subsystem Status & Baselines
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/lstm/status" -Method Get | ConvertTo-Json -Depth 4
```

### B. Explicitly Train / Calibrate an LSTM Service Baseline
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/lstm/train" `
  -Method Post -ContentType "application/json" `
  -Body '{"service_identity": "srv-ledgerone-core", "epochs": 25, "batch_size": 16, "version": "1.0.0"}' | ConvertTo-Json -Depth 4
```

### C. List Saved PyTorch Models & Manifests
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/lstm/models" -Method Get | ConvertTo-Json -Depth 4
```

### D. Run Benchmark Evaluation & Isolation Forest Comparison
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/lstm/evaluation?service_identity=srv-ledgerone-core" -Method Get | ConvertTo-Json -Depth 5
```

### E. Query LSTM-Detected Sequential Anomalies
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ml/lstm/anomalies" -Method Get | ConvertTo-Json -Depth 6
```

---

## 14. Phase 5: Two-Person Bank Change Approval Engine

### Core Enforcement Principles
1. **Strict Two-Person Rule**: No bank change can commit until two distinct authorized human approvers sign off.
2. **Anti-Self-Approval**: The requester cannot approve their own request (`403 SelfApprovalProhibited`).
3. **Anti-Duplicate Approval**: The same approver cannot sign off twice (`400 DuplicateApprovalProhibited`).
4. **Old Account Invariance**: The existing active bank account remains active until Step 8 of the second approval commits.
5. **Cryptographic Binding**: All approvals are bound to a canonical SHA-256 fingerprint; modifications invalidate prior approvals and reset status.
6. **Encryption & Masking**: Proposed details are Fernet-encrypted at rest (AES-128-CBC + HMAC-SHA256); API responses only expose masked references (`ACC-***masked***1048`).
7. **Concurrency Safety**: Atomic row-level locks (`SELECT ... FOR UPDATE`) prevent race conditions during approvals and commits.
8. **Deterministic Enforcement**: ML anomaly scores never authorize bank changes; authorization is purely deterministic.

### Live PowerShell Verification Commands

#### A. Submit Bank Change Request (as Requester Sarah)
```powershell
$createPayload = @{
    vendor_id = "vnd_10482"
    proposed_account_number = "998877665544"
    proposed_bank_name = "Citibank NA"
    proposed_routing_number = "021000089"
    request_reason = "Vendor annual corporate treasury account migration"
} | ConvertTo-Json

$req = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/bank-changes" `
  -Method Post -ContentType "application/json" `
  -Headers @{ "X-User-Id" = "usr_req_sarah" } `
  -Body $createPayload

$req | ConvertTo-Json -Depth 4
$requestId = $req.request_id
```

#### B. First Approval (Approver Elena)
```powershell
$appr1 = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/bank-changes/$requestId/approve" `
  -Method Post -ContentType "application/json" `
  -Headers @{ "X-User-Id" = "usr_appr_elena" } `
  -Body '{"comment": "Verified bank authorization letter with vendor CFO"}'

$appr1 | ConvertTo-Json -Depth 4
# Status: PARTIALLY_APPROVED | approval_count: 1
```

#### C. Second Independent Approval (Approver David) -> Commits Change Atomically
```powershell
$appr2 = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/bank-changes/$requestId/approve" `
  -Method Post -ContentType "application/json" `
  -Headers @{ "X-User-Id" = "usr_appr_david" } `
  -Body '{"comment": "Confirmed phone verification callback with treasury officer"}'

$appr2 | ConvertTo-Json -Depth 4
# Status: COMMITTED | approval_count: 2 | Active vendor account updated!
```

#### D. Verify Active Vendor Bank Account
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/vendors/vnd_10482/bank-account" `
  -Method Get -Headers @{ "X-User-Id" = "usr_audit_rachel" } | ConvertTo-Json -Depth 4
```

#### E. Inspect Complete Immutable Audit Trail
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/bank-changes/$requestId/audit" `
  -Method Get -Headers @{ "X-User-Id" = "usr_audit_rachel" } | ConvertTo-Json -Depth 5
```

---

## 15. Phase 6: Unified Risk Assessment & Detection Integration

### Synergistic Risk Aggregation Formula
1. **Deterministic Hard Floor**: $S_{\text{base}} = \max(S_{\text{rule}}, S_{\text{if}}, S_{\text{lstm}})$
2. **Missing Model Invariant**: If a model is `UNAVAILABLE` or `INSUFFICIENT_DATA`, it has `evaluated=False` and is explicitly reported (never assumed normal).
3. **Cross-Tier Synergy Boosts**:
   - Dual confirmation (Rule + ML or IF + LSTM): $+10$ points
   - Triple confirmation (Rule + IF + LSTM): $+15$ points
4. **Clamping**: $\text{Final Risk Score} = \min(100, \max(0, S_{\text{base}} + \text{boost}))$
5. **AI Non-Bypass Invariant**: AI risk scores never authorize bank changes; two distinct human approvals remain mandatory.

### Live PowerShell Verification Commands

#### A. Unified Assessment for an Event
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/assessment/events/<event_id>" `
  -Method Get -Headers @{ "X-User-Id" = "usr_audit_rachel" } | ConvertTo-Json -Depth 6
```

#### B. Unified Detection Analytics & System Readiness Summary
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/assessment/summary" `
  -Method Get -Headers @{ "X-User-Id" = "usr_audit_rachel" } | ConvertTo-Json -Depth 5
```

#### C. Combined Incident Assessment Details
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/incidents/<incident_id>/assessment" `
  -Method Get -Headers @{ "X-User-Id" = "usr_audit_rachel" } | ConvertTo-Json -Depth 6
```

#### D. Bank Change Linked Security Risk Assessment & Warnings
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/bank-changes/<request_id>/risk-assessment" `
  -Method Get -Headers @{ "X-User-Id" = "usr_appr_elena" } | ConvertTo-Json -Depth 6
```

---

## 16. Automated Test Suite (117 Passing Tests)

Run the complete test suite verifying Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, and Phase 6:
```powershell
cd sentinel/backend
pytest -v
```

**Test Coverage Summary (117 Tests Total)**:
- **Phase 1 Foundation (21 tests)**: Ingestion, schema validation, duplicate collision rejection, PII/bank redaction, size limits, health probes.
- **Phase 2 Deterministic Rules (18 tests)**: 6 security detection rules (`SEC-RULE-*`), risk scoring, incident correlation & deduplication, triage status lifecycle (`PATCH /api/v1/incidents/{incident_id}`).
- **Phase 3 Isolation Forest (18 tests)**: 15-feature extraction, empty/missing event tolerance, model training & Joblib persistence roundtrip, normal vs anomalous scoring, baseline sufficiency enforcement, ML incident integration, and ML REST API.
- **Phase 4 LSTM Autoencoder (22 tests)**: Sequence generation, chronological ordering, service isolation, train-only normalization, PyTorch forward pass, reconstruction loss, safe state_dict persistence/loading, normal sequence reconstruction, multi-step attack sequence detection, ML-ANOMALY-LSTM-001 incident generation, deduplication, fault tolerance, and LSTM REST API.
- **Phase 5 Two-Person Bank Approval (28 tests)**: Strict two-person rule, anti-self-approval rejection (`403 SelfApprovalProhibited`), anti-duplicate approver rejection (`400 DuplicateApprovalProhibited`), non-approver rejection (`403 AccessDenied`), active account invariance until commit, atomic commit with row-locking (`SELECT ... FOR UPDATE`), rejection workflow, cancellation workflow, expiration handling, tamper detection via cryptographic fingerprint mismatch (`409 FingerprintMismatch`), modify route (`PUT /api/v1/bank-changes/{id}`), real PostgreSQL concurrency safety with `ThreadPoolExecutor`, Fernet encryption at rest, audit trail append-only immutability enforced by DB triggers and ORM listeners, sensitive data masking guarantee, and SEC-RULE-BANK-001 incident correlation.
- **Phase 6 Unified Assessment & Detection Integration (10 tests)**: Synergistic risk aggregation, missing model handling (never assumed normal), deterministic hard floor, multi-tier compounding boosts, on-demand evaluation API, combined incident assessment, unified detection analytics summary, bank change risk association with security warnings, AI non-bypass invariant, and sensitive data masking in assessments.

---

## 17. Architecture Verification & Health Harness

SENTINEL includes an automated self-verification script:
```powershell
python verify_sentinel.py --pytest "sentinel/backend" --report "sentinel/docs/qa/verify_report.json"
```
This tests:
1. System Health Probe (`/api/v1/health`)
2. Security Detection Rules (all 6 active)
3. Isolation Forest Model Status
4. PyTorch LSTM Autoencoder Model Status
5. Bank Change Approval Listing
6. Unified Multi-Tier Analytics Summary
7. Pytest Test Suite Execution (117/117 passing)

---

## 18. Phase 7: SOC Security Monitoring Dashboard

### Overview
Phase 7 provides a modern, responsive, dark navy Security Operations Center (SOC) web console built with **React 19**, **TypeScript**, **Vite**, and **Tailwind CSS**. It connects directly to the FastAPI backend and visualizes all analytical subsystems.

### Features & Modules
1. **Security Overview**: Live metrics, incident severity distribution chart (Recharts), detection component triggers, and recent suspicious events table.
2. **Live API Monitoring**: Streamed API event table with auto-refresh/pause controls, search filters, and an interactive slide-over drawer with on-demand multi-tier AI evaluation.
3. **Incident Management**: Multi-filter triage table (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) with detailed forensic modal and real-time status transitions (`PATCH /api/v1/incidents/{incident_id}`).
4. **AI Detection Subsystems**: Status overview and calibration metrics for Isolation Forest and PyTorch LSTM Autoencoder, highlighting the 15-dimensional feature schema and fail-safe missing model handling.
5. **Two-Person Bank Change Approval**: 4-step dual-human separation-of-duties visualization, strictly masked financial details (`ACC-***masked***XXXX`), linked security incident warnings, and anti-self-approval / anti-duplicate-approver UI guards.
6. **Immutable Audit Trail**: Read-only chronological audit log of all financial modifications and approvals with client IP and forensic state snapshots.
7. **Simulated Identity Switcher**: Header control to switch between Sarah Jenkins (Requester), Elena Rostova (Approver 1), David Sterling (Approver 2), Alex Vance (Admin), and Rachel Thorne (Auditor) to interactively verify RBAC enforcement.

### Running the Full System (Backend + Frontend)

#### Terminal 1: FastAPI Backend
```powershell
python -m uvicorn sentinel.backend.app.main:app --host 127.0.0.1 --port 8000
```

#### Terminal 2: React SOC Dashboard
```powershell
cd sentinel/frontend
npm run dev
```
Navigate to `http://127.0.0.1:5173` in your browser.

---

## 19. Known Limitations & Hardening Recommendations

1. **Development Authentication Adapter**: The `X-User-Id` header mechanism is designed for development and automated testing. Production deployment requires an enterprise OpenID Connect (OIDC) / SAML 2.0 Identity Provider with Multi-Factor Authentication (MFA) and cryptographic JWT validation.
2. **Approval Reference Pattern Compatibility**: The standard governance ticket pattern is configured as `^APP-\d{4}-\d{4,}$`. When integrating legacy systems utilizing `APR-XXXX` or batch `BULK-XXXX` conventions, configure `VALID_APPROVAL_REGEX` in `detection/config.py` accordingly.
3. **Sequence Length Context Requirement**: A minimum sequence of 20 consecutive events for a single service identity is required before evaluating LSTM sequential patterns.
4. **Passive Monitoring vs. Active Blocking**: Detection tiers operate as analytical observers and incident generators; they do not terminate active client connections. AI detection scores never authorize or commit sensitive financial transactions.
5. **Distributed Worker Caching**: In high-throughput distributed deployments (>10,000 req/s), fronting sliding window aggregations with Redis will minimize PostgreSQL query load.
