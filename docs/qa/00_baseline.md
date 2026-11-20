# QA Baseline Audit Report (Phase 1 Baseline)

**Date**: 2026-11-20  
**Harness Executed**: `python verify_sentinel.py --train --pytest "sentinel/backend"`  
**Target Environment**: Windows 11, Local PostgreSQL 16 (`127.0.0.1:5432`), FastAPI (`127.0.0.1:8000`)

---

## 1. Executive Summary

| Total Checks | Passed | Failed | Warnings | Skipped |
|---|---|---|---|---|
| **7** | **7** | **0** | **0** | **0** |

- **Backend PyTest Suite**: **103 passed**, 0 failed, 1 warning (deprecation warning regarding Starlette `HTTP_422_UNPROCESSABLE_ENTITY` alias) in 35.78s.
- **Service Identities**: Successfully seeded 4 service identities into PostgreSQL (`srv-ledgerone-core`, `srv-ledgerone-paygate`, `srv-helpdeskr-agent`, `srv-tallybridge-sync`).
- **Alembic Migrations**: Up to date at head (`20261120_0002_add_incidents_and_rules`).

---

## 2. Baseline Check Matrix

| Check Name | Target / Subsystem | Status | Duration | Response / Details |
|---|---|---|---|---|
| **System Health Probe** | `GET /health` | **PASS** | 0.034s | `{"status": "healthy", "service": "SENTINEL API Activity Monitor", "version": "1.0.0", "environment": "development", "database": {"status": "connected", "latency_ms": 1.68}}` |
| **Security Detection Rules** | `GET /api/v1/detection/rules` | **PASS** | 0.013s | Registered 6 rules: `SEC-RULE-RATE-001`, `SEC-RULE-BULK-001`, `SEC-RULE-IP-001`, `SEC-RULE-PRIV-001`, `SEC-RULE-BANK-001`, `SEC-RULE-APPR-001` |
| **Isolation Forest Anomaly Detector** | `POST /api/v1/ml/train` & `GET /api/v1/ml/status` | **PASS** | 2.585s | Status: `operational`. Baselines trained and calibrated across all 4 service identities. |
| **PyTorch LSTM Sequential Autoencoder** | `POST /api/v1/ml/lstm/train` & `GET /api/v1/ml/lstm/status` | **PASS** | 16.447s | Subsystem: `operational`, Device: `cpu`, Window: 5 steps. Baselines calibrated for all 4 services. |
| **Bank Change Approval Listing** | `GET /api/v1/bank-changes` | **PASS** | 0.021s | Status: `200 OK`. Authenticated query by `usr_audit_rachel`. |
| **Unified Multi-Tier Analytics Summary** | `GET /api/v1/assessment/summary` | **PASS** | 0.019s | Status: `200 OK`. Multi-tier telemetry: `total_assessed_events: 81`, `total_incidents: 23`, `average_risk_score: 72.13`. |
| **Pytest Backend Test Suite** | `sentinel/backend` | **PASS** | 35.78s | `103 passed, 1 warning in 35.78s`. 100% test pass rate across all test modules. |

---

## 3. Discovered Warnings & Deprecations

1. `StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated. Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead`:
   - Emitted from Starlette HTTP status code definitions in `test_incidents_api.py`.
   - Behavior is functional and non-breaking.

---

## 4. Next Phase: Phase 2 Bank Change Approval Audit & Fixes
Proceeding to test and prove claims a–n from the Phase 2 specification.
