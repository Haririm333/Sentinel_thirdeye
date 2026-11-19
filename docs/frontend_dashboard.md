# SENTINEL Phase 7: Security Operations Center (SOC) Monitoring Dashboard

## Overview
Phase 7 introduces the enterprise web frontend for **SENTINEL: API Behaviour Monitoring & Suspicious Activity Detection System**. Built with React 19, TypeScript, Vite, Tailwind CSS, Recharts, and Axios, this dashboard provides cybersecurity analysts, SOC operators, and financial controllers with real-time visibility and enforceable governance over multi-tier API activity.

---

## Architecture & Technology Stack

- **Framework**: React 19 + TypeScript + Vite
- **Styling**: Tailwind CSS with custom Dark Navy SOC color palette:
  - Deep Dark Navy Canvas (`#070C1E`, `#0B132B`)
  - Elevated Card Panels (`#1C2541`)
  - Accents & Cyan Highlights (`#48E5C2`, `#5BC0BE`)
  - Alert Severities: Critical (`#EF4444`), High (`#F97316`), Medium (`#F59E0B`), Low (`#10B981`)
- **Visual Analytics**: Recharts responsive charts (Severity breakdown, Subsystem triggers)
- **Networking**: Axios with request interceptors for role-based persona header injection (`X-User-Id`)
- **Backend API Integration**: Connects seamlessly to FastAPI on `http://127.0.0.1:8000`

---

## Implemented Dashboard Modules

### 1. Security Overview Module (`OverviewModule.tsx`)
- **Executive Metric Cards**: Total Ingested Events, Active Security Incidents (with Critical/High counters), AI Anomalies Triggered, and Multi-Tier Average Risk Score.
- **Incident Severity Distribution**: Dynamic bar chart visualizing incident counts grouped by `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.
- **Detection Component Triggers**: Visual breakdown comparing detections from Deterministic Rules, Isolation Forest Point Detector, PyTorch LSTM Sequential Autoencoder, and Multi-Tier Correlated incidents.
- **Recent Suspicious Activity Table**: High-priority alert table with one-click "Inspect" deep-dive into detailed forensic telemetry.

### 2. Live API Monitoring Module (`LiveMonitoringModule.tsx`)
- **Stream Ingestion Table**: Controlled polling stream (with configurable intervals and streaming pause/resume toggle).
- **Comprehensive Event Metadata**: Timestamp, Source System (`LedgerOne`, `HelpDeskr`, `TallyBridge`), Service Identity, HTTP Method (color-coded badges), Endpoint, Source IP (with visual alerting on external/unapproved IPs), Status Code, and Cryptographic SHA-256 payload hash.
- **Event Telemetry Drawer**: Slide-over forensic drawer showing full sanitized payload attributes.
- **On-Demand AI Risk Evaluation**: Direct trigger to run multi-tier risk evaluation (`POST /api/v1/assessment/evaluate/{event_id}`) with live subsystem score breakdown.

### 3. Incident Management Module (`IncidentManagementModule.tsx`, `IncidentDetailModal.tsx`)
- **Multi-Filter Triage**: Filter incidents dynamically by severity (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and status (`ALL`, `OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- **Forensic Detail Modal**: Displays incident title, rule ID, risk score, human-readable detection explanations, and structured evidence.
- **Unified Assessment Link**: Renders unified risk assessment correlation and detector findings.
- **Lifecycle Status Updates**: Live interactive status transitions (`PATCH /api/v1/incidents/{incident_id}`) between `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`.

### 4. AI Detection Subsystems Module (`AIDetectionModule.tsx`)
- **Isolation Forest Point Anomaly Detector**: Real-time status, 15-dimensional feature schema, per-service baselines, and calibrated anomaly score thresholds.
- **PyTorch LSTM Sequential Autoencoder**: Subsystem operational status, CPU inference device, 5-step sequence temporal window, and calibrated reconstruction error thresholds.
- **Fail-Safe Security Guarantee Banner**: Explains that AI detection strictly complements deterministic rules; missing, untrained, or calibrating models are never treated as normal activity.
- **15-Dimensional Feature Schema**: Explanations for all temporal, payload, frequency, behavioral, and network features.

### 5. Bank Change Approval & Enforcement Module (`BankApprovalModule.tsx`, `NewBankChangeModal.tsx`)
- **Dual-Human Separation of Duties Visual Tracker**: Visual 4-step workflow indicator (Step 1: Requester Initiated $\to$ Step 2: Approver 1 $\to$ Step 3: Approver 2 $\to$ Committed to Active Ledger).
- **Masked Financial Data Display**: Strictly displays masked account coordinates (`ACC-***masked***XXXX`, `ROUT-***masked***XXXX`). Plaintext numbers are never rendered in the UI or logs.
- **Linked Security Warnings Banner**: Surfaces linked critical/high security incidents and risk warnings from `risk_assessment_snapshot`.
- **Strict Anti-Self-Approval Enforcement**:
  - If the active user matches `requester_id`, the Approve button is automatically disabled with an explanatory security banner.
  - If the active user has already provided the first approval, the second approval cannot be granted by the same person.
- **Interactive Actions**: Submit new change request, provide Approval Step 1, provide Final Approval Step 2 (committing atomically), or Reject change with mandatory justification.

### 6. SOC Forensic Audit Trail Module (`AuditTrailModule.tsx`)
- **Read-Only Immutable Audit Log**: Chronological view of all state changes (`CREATED`, `FIRST_APPROVAL`, `SECOND_APPROVAL`, `REJECTED`, `CANCELLED`).
- **Audit Attributes**: Timestamp, Action, Actor Identity, Role, Target Request ID, Client IP, and Structured Evidence Snapshot.

### 7. Header & Role-Based Identity Switcher (`Header.tsx`, `AuthContext.tsx`)
- Allows instant simulation of authenticated users to test RBAC and separation of duties:
  - `Sarah Jenkins (usr_req_sarah)`: Procurement Specialist (REQUESTER)
  - `Elena Rostova (usr_appr_elena)`: Finance Controller (FINANCE_APPROVER)
  - `David Sterling (usr_appr_david)`: VP of Financial Ops (FINANCE_APPROVER)
  - `Alex Vance (usr_admin_alex)`: Security & System Admin (FINANCE_ADMIN)
  - `Rachel Thorne (usr_audit_rachel)`: Senior Cyber Auditor (AUDITOR)

---

## Running the Dashboard

### 1. Start the FastAPI Backend
```bash
python -m uvicorn sentinel.backend.app.main:app --host 127.0.0.1 --port 8000
```

### 2. Start the Vite React Frontend
```bash
cd sentinel/frontend
npm run dev
```
Access the dashboard at `http://127.0.0.1:5173`.
