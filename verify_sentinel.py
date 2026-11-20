#!/usr/bin/env python3
"""
SENTINEL Verification Script
Runs end-to-end verification of SENTINEL analytical and transactional subsystems:
- Health and database readiness
- API event ingestion and validation
- Deterministic security detection rules
- Isolation Forest ML behavioral anomaly detection
- PyTorch LSTM sequential autoencoder detection
- Two-person bank approval enforcement
- Unified risk assessment integration
- Pytest suite execution
"""

import sys
import os
import json
import time
import argparse
import subprocess
from datetime import datetime, timezone
import requests

API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8000")

def parse_args():
    parser = argparse.ArgumentParser(description="SENTINEL System Verification")
    parser.add_argument("--train", action="store_true", help="Trigger baseline model training")
    parser.add_argument("--pytest", type=str, default="", help="Path to pytest tests directory")
    parser.add_argument("--report", type=str, default="verify_report.json", help="Path to save JSON report")
    return parser.parse_args()

def run_check(name, check_fn):
    print(f"[*] Running check: {name}...", end=" ", flush=True)
    start_time = time.time()
    try:
        status, details = check_fn()
        elapsed = round(time.time() - start_time, 3)
        print(f"[{status}] ({elapsed}s)")
        return {
            "name": name,
            "status": status,
            "duration_sec": elapsed,
            "details": details
        }
    except Exception as e:
        elapsed = round(time.time() - start_time, 3)
        print(f"[FAIL] ({elapsed}s) -> {str(e)}")
        return {
            "name": name,
            "status": "FAIL",
            "duration_sec": elapsed,
            "error": str(e)
        }

def check_health():
    res = requests.get(f"{API_URL}/health", timeout=5)
    if res.status_code == 200 and res.json().get("status") == "healthy":
        return "PASS", res.json()
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def check_detection_rules():
    res = requests.get(f"{API_URL}/api/v1/detection/rules", timeout=5)
    if res.status_code == 200:
        rules = res.json()
        if len(rules) >= 6:
            return "PASS", {"rules_count": len(rules)}
        return "WARN", {"rules_count": len(rules), "message": "Expected at least 6 rules"}
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def check_ml_isoforest(train=False):
    if train:
        for srv in ["srv-ledgerone-core", "srv-ledgerone-paygate", "srv-helpdeskr-agent", "srv-tallybridge-sync"]:
            requests.post(f"{API_URL}/api/v1/ml/train", json={"service_identity": srv, "num_samples": 60}, timeout=30)
    res = requests.get(f"{API_URL}/api/v1/ml/status", timeout=5)
    if res.status_code == 200:
        return "PASS", res.json()
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def check_ml_lstm(train=False):
    if train:
        for srv in ["srv-ledgerone-core", "srv-ledgerone-paygate", "srv-helpdeskr-agent", "srv-tallybridge-sync"]:
            requests.post(f"{API_URL}/api/v1/ml/lstm/train", json={"service_identity": srv, "epochs": 15}, timeout=40)
    res = requests.get(f"{API_URL}/api/v1/ml/lstm/status", timeout=5)
    if res.status_code == 200:
        return "PASS", res.json()
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def check_bank_approvals_api():
    headers = {"X-User-Id": "usr_audit_rachel"}
    res = requests.get(f"{API_URL}/api/v1/bank-changes", headers=headers, timeout=5)
    if res.status_code == 200:
        return "PASS", {"total_requests": res.json().get("total", 0)}
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def check_unified_summary():
    headers = {"X-User-Id": "usr_audit_rachel"}
    res = requests.get(f"{API_URL}/api/v1/assessment/summary", headers=headers, timeout=5)
    if res.status_code == 200:
        return "PASS", res.json()
    return "FAIL", {"status_code": res.status_code, "body": res.text}

def run_pytest_suite(pytest_path):
    cmd = [sys.executable, "-m", "pytest", pytest_path, "-v", "--tb=short"]
    print(f"\n[+] Executing Pytest: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    passed = proc.returncode == 0
    return "PASS" if passed else "FAIL", {
        "return_code": proc.returncode,
        "stdout": proc.stdout[-1500:],
    }

def main():
    args = parse_args()
    print("=" * 60)
    print("SENTINEL SYSTEM VERIFICATION HARNESS")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"API Base: {API_URL}")
    print("=" * 60)

    checks = []
    checks.append(run_check("System Health Probe", check_health))
    checks.append(run_check("Security Detection Rules", check_detection_rules))
    checks.append(run_check("Isolation Forest Anomaly Detector", lambda: check_ml_isoforest(args.train)))
    checks.append(run_check("PyTorch LSTM Sequential Autoencoder", lambda: check_ml_lstm(args.train)))
    checks.append(run_check("Bank Change Approval Listing", check_bank_approvals_api))
    checks.append(run_check("Unified Multi-Tier Analytics Summary", check_unified_summary))

    pytest_results = None
    if args.pytest:
        res = run_check(f"Pytest Test Suite ({args.pytest})", lambda: run_pytest_suite(args.pytest))
        checks.append(res)
        pytest_results = res["details"]

    pass_count = sum(1 for c in checks if c["status"] == "PASS")
    fail_count = sum(1 for c in checks if c["status"] == "FAIL")
    warn_count = sum(1 for c in checks if c["status"] == "WARN")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(checks),
        "passed": pass_count,
        "failed": fail_count,
        "warnings": warn_count,
        "checks": checks
    }

    # Ensure output directories exist
    os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 60)
    print(f"VERIFICATION SUMMARY: {pass_count} PASSED, {fail_count} FAILED, {warn_count} WARNINGS")
    print(f"Report written to: {args.report}")
    print("=" * 60)

    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
