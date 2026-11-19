"""
SENTINEL API Activity Event Simulator
Generates and transmits authentic simulated API events to the SENTINEL ingestion endpoint.

Supported scenarios:
1. Normal vendor record reads (LedgerOne)
2. Normal payment status checks (LedgerOne)
3. Vendor profile updates (HelpDeskr / LedgerOne)
4. Unusual bulk data requests (LedgerOne / TallyBridge)
5. Vendor bank account modification attempts (High-risk activity)
6. Duplicate and invalid edge-case verification
"""

import argparse
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
import requests

# Base data pools for generating realistic business events
VENDOR_IDS = [f"vnd_{i:05d}" for i in [10482, 10483, 11094, 12389, 14002, 19283, 20491]]
PAYMENT_IDS = [f"pay_{i:06d}" for i in [882910, 882911, 883012, 883015, 883100, 884920]]
USER_ACCOUNTS = [
    "usr_fin_882", "usr_fin_104", "usr_ap_330", "usr_sup_401",
    "usr_admin_09", "usr_audit_02", "service_tally_batch"
]
CORPORATE_IPS = ["10.0.1.45", "10.0.1.78", "10.0.2.110", "10.0.3.15", "192.168.10.50"]
EXTERNAL_SUSPICIOUS_IPS = ["198.51.100.23", "203.0.113.88", "185.220.101.5", "45.154.255.8"]


def generate_normal_vendor_read() -> dict:
    """Scenario 1: Routine query for vendor metadata."""
    vendor_id = random.choice(VENDOR_IDS)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "LedgerOne",
        "service_identity": "srv-ledgerone-core",
        "endpoint": f"/api/v1/vendors/{vendor_id}",
        "http_method": "GET",
        "http_status_code": 200,
        "request_size_bytes": random.randint(120, 240),
        "response_size_bytes": random.randint(1500, 4200),
        "source_ip": random.choice(CORPORATE_IPS),
        "auth_identity": random.choice(["usr_fin_882", "usr_ap_330", "usr_sup_401"]),
        "action": "READ_VENDOR_RECORD",
        "resource_type": "VENDOR",
        "resource_id": vendor_id,
        "approval_reference": None
    }


def generate_normal_payment_check() -> dict:
    """Scenario 2: Routine payment verification status query."""
    payment_id = random.choice(PAYMENT_IDS)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "LedgerOne",
        "service_identity": "srv-ledgerone-paygate",
        "endpoint": f"/api/v1/payments/{payment_id}/status",
        "http_method": "GET",
        "http_status_code": 200,
        "request_size_bytes": random.randint(100, 200),
        "response_size_bytes": random.randint(800, 1600),
        "source_ip": random.choice(CORPORATE_IPS),
        "auth_identity": random.choice(["usr_fin_104", "usr_ap_330"]),
        "action": "CHECK_PAYMENT_STATUS",
        "resource_type": "PAYMENT",
        "resource_id": payment_id,
        "approval_reference": None
    }


def generate_vendor_profile_update() -> dict:
    """Scenario 3: Authorized update of vendor demographic or address details."""
    vendor_id = random.choice(VENDOR_IDS)
    approval_ticket = f"APP-{random.randint(2026, 2027)}-{random.randint(1000, 9999)}"
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "HelpDeskr",
        "service_identity": "srv-helpdeskr-agent",
        "endpoint": f"/api/v1/vendors/{vendor_id}/profile",
        "http_method": "PUT",
        "http_status_code": 200,
        "request_size_bytes": random.randint(1200, 3500),
        "response_size_bytes": random.randint(500, 900),
        "source_ip": random.choice(CORPORATE_IPS),
        "auth_identity": random.choice(["usr_sup_401", "usr_admin_09"]),
        "action": "UPDATE_VENDOR_PROFILE",
        "resource_type": "VENDOR",
        "resource_id": vendor_id,
        "approval_reference": approval_ticket
    }


def generate_unusual_bulk_data_request() -> dict:
    """Scenario 4: High-volume bulk export request (anomalous data transfer)."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "LedgerOne",
        "service_identity": "srv-tallybridge-sync",
        "endpoint": "/api/v1/vendors/export/full",
        "http_method": "POST",
        "http_status_code": 200,
        "request_size_bytes": 1024,
        "response_size_bytes": random.randint(15_000_000, 48_000_000),  # 15-48 MB payload
        "source_ip": random.choice(EXTERNAL_SUSPICIOUS_IPS),
        "auth_identity": "service_tally_batch",
        "action": "BULK_DATA_EXPORT",
        "resource_type": "VENDOR_DATABASE",
        "resource_id": "all_vendors_dump",
        "approval_reference": None
    }


def generate_bank_account_modification_attempt() -> dict:
    """Scenario 5: High-risk bank account modification (potential fraud)."""
    vendor_id = random.choice(VENDOR_IDS)
    # Target bank account containing sensitive credentials that should be masked
    raw_acc_num = f"ACC-{random.randint(1000000000, 9999999999)}"
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_system": "LedgerOne",
        "service_identity": "srv-ledgerone-core",
        "endpoint": f"/api/v1/vendors/{vendor_id}/bank-account",
        "http_method": "PATCH",
        "http_status_code": random.choice([200, 403]),
        "request_size_bytes": random.randint(450, 850),
        "response_size_bytes": random.randint(200, 500),
        "source_ip": random.choice(EXTERNAL_SUSPICIOUS_IPS),
        "auth_identity": "usr_fin_882",
        "action": "MODIFY_VENDOR_BANK_ACCOUNT",
        "resource_type": "BANK_ACCOUNT",
        "resource_id": raw_acc_num,
        "approval_reference": "EMERGENCY_OVERRIDE_NO_TICKET"
    }


def send_event(target_url: str, event_data: dict) -> dict:
    """Send an event payload via HTTP POST to the SENTINEL endpoint."""
    t0 = time.perf_counter()
    endpoint = f"{target_url.rstrip('/')}/api/v1/events"
    try:
        resp = requests.post(endpoint, json=event_data, timeout=5)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "status_code": resp.status_code,
            "latency_ms": latency_ms,
            "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
            "event_id": event_data.get("event_id"),
            "action": event_data.get("action"),
            "system": event_data.get("source_system")
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "status_code": 0,
            "latency_ms": latency_ms,
            "error": str(exc),
            "event_id": event_data.get("event_id"),
            "action": event_data.get("action"),
            "system": event_data.get("source_system")
        }


def run_simulator():
    parser = argparse.ArgumentParser(description="SENTINEL API Activity Event Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL of SENTINEL backend")
    parser.add_argument("--count", type=int, default=25, help="Number of events to generate")
    parser.add_argument(
        "--scenario",
        choices=["all", "vendor_reads", "payment_checks", "profile_updates", "bulk_requests", "bank_modifications"],
        default="all",
        help="Specific scenario to simulate"
    )
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between requests in seconds")
    parser.add_argument("--test-duplicates", action="store_true", help="Include duplicate event submission tests")
    parser.add_argument("--test-invalid", action="store_true", help="Include malformed/invalid events")
    args = parser.parse_args()

    print("=" * 80)
    print(f"SENTINEL Event Simulator Starting")
    print(f"Target URL: {args.url}")
    print(f"Total Events: {args.count}")
    print(f"Scenario: {args.scenario}")
    print("=" * 80)

    # First check health
    try:
        health_res = requests.get(f"{args.url.rstrip('/')}/health", timeout=3)
        if health_res.status_code == 200:
            print(f"[OK] Backend health check verified: {health_res.json()}")
        else:
            print(f"[WARN] Health check returned HTTP {health_res.status_code}: {health_res.text}")
    except Exception as exc:
        print(f"[ERROR] Could not connect to SENTINEL at {args.url}: {exc}")
        print("Please ensure the FastAPI backend is running before launching the simulator.")
        return

    scenario_generators = {
        "vendor_reads": generate_normal_vendor_read,
        "payment_checks": generate_normal_payment_check,
        "profile_updates": generate_vendor_profile_update,
        "bulk_requests": generate_unusual_bulk_data_request,
        "bank_modifications": generate_bank_account_modification_attempt,
    }

    results = []
    sent_events = []

    print("\n--- Transmitting Events ---")
    for i in range(1, args.count + 1):
        if args.scenario == "all":
            # Weighted distribution: 40% reads, 30% payments, 15% updates, 10% bulk, 5% bank changes
            gen_func = random.choices(
                [
                    generate_normal_vendor_read,
                    generate_normal_payment_check,
                    generate_vendor_profile_update,
                    generate_unusual_bulk_data_request,
                    generate_bank_account_modification_attempt,
                ],
                weights=[40, 30, 15, 10, 5],
                k=1
            )[0]
        else:
            gen_func = scenario_generators[args.scenario]

        event_payload = gen_func()
        res = send_event(args.url, event_payload)
        results.append(res)
        sent_events.append(event_payload)

        status_flag = "[ACCEPTED 201]" if res["status_code"] == 201 else f"[HTTP {res['status_code']}]"
        print(f"[{i:03d}/{args.count:03d}] {status_flag} {res['system']:<10} | {res['action']:<30} | {res['latency_ms']:>6.1f} ms | ID: {res['event_id']}")
        
        if args.delay > 0:
            time.sleep(args.delay)

    # Duplicate testing if requested
    if args.test_duplicates and sent_events:
        print("\n--- Submitting Duplicate Events (Anti-Replay Verification) ---")
        dup_sample = random.sample(sent_events, min(3, len(sent_events)))
        for dup in dup_sample:
            res = send_event(args.url, dup)
            results.append(res)
            expected = "[REJECTED 409 CONFLICT]" if res["status_code"] == 409 else f"[HTTP {res['status_code']}]"
            print(f"[DUP TEST] {expected} {dup['event_id']} - Handled Safely!")

    # Invalid event testing if requested
    if args.test_invalid:
        print("\n--- Submitting Malformed Events (Validation Verification) ---")
        malformed = [
            {"event_id": "not-uuid", "action": "BAD_DATA"},
            {"event_id": str(uuid.uuid4()), "http_method": "INVALID", "source_system": "LedgerOne"},
        ]
        for bad in malformed:
            res = send_event(args.url, bad)
            results.append(res)
            expected = "[REJECTED 422 VALIDATION]" if res["status_code"] == 422 else f"[HTTP {res['status_code']}]"
            print(f"[BAD TEST] {expected} Payload: {bad}")

    # Summary report
    total_sent = len(results)
    accepted = sum(1 for r in results if r["status_code"] == 201)
    duplicates = sum(1 for r in results if r["status_code"] == 409)
    validation_errs = sum(1 for r in results if r["status_code"] == 422)
    other_errs = sum(1 for r in results if r["status_code"] not in (201, 409, 422))
    avg_latency = sum(r["latency_ms"] for r in results) / total_sent if total_sent > 0 else 0

    print("\n" + "=" * 80)
    print("SIMULATOR RUN SUMMARY")
    print("=" * 80)
    print(f"Total Requests Sent:        {total_sent}")
    print(f"Accepted (201 Created):     {accepted}")
    print(f"Duplicate Conflicts (409):  {duplicates}")
    print(f"Validation Rejections (422):{validation_errs}")
    print(f"Other Statuses:             {other_errs}")
    print(f"Average Roundtrip Latency:  {avg_latency:.2f} ms")
    print("=" * 80)


if __name__ == "__main__":
    run_simulator()
