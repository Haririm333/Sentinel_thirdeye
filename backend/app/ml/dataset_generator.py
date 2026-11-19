"""
Synthetic Dataset Generator for SENTINEL API Anomaly Detection
Generates realistic baseline training data and labeled evaluation scenarios
for LedgerOne, HelpDeskr, and TallyBridge.

IMPORTANT: All data produced here is SYNTHETIC DEVELOPMENT DATA.
Attack labels are preserved strictly for evaluation benchmarking and are never
exposed to the unsupervised Isolation Forest training phase.
"""

import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
import pandas as pd

from sentinel.backend.app.ml.features import extract_window_features, dataframe_from_feature_dicts

# Base resource dictionaries
VENDORS = [f"vnd_{i:05d}" for i in [10482, 10483, 11094, 12389, 14002, 19283, 20491, 30122, 40192, 50123]]
PAYMENTS = [f"pay_{i:06d}" for i in [882910, 882911, 883012, 883015, 883100, 884920, 991200]]
CORPORATE_IPS = {
    "srv-ledgerone-core": ["10.0.1.15", "10.0.1.45", "10.0.1.80"],
    "srv-ledgerone-paygate": ["10.0.1.20", "10.0.1.22"],
    "srv-helpdeskr-agent": ["10.0.3.10", "10.0.3.15", "10.0.3.25"],
    "srv-tallybridge-sync": ["10.0.2.5", "10.0.2.12", "10.0.2.18"]
}
EXTERNAL_ANOMALOUS_IPS = ["198.51.100.23", "203.0.113.88", "185.220.101.5", "45.154.255.8"]


def _generate_normal_event(service_identity: str, current_time: datetime, rng: random.Random) -> Dict[str, Any]:
    """Generate a single legitimate, routine API event matching service profile."""
    ips = CORPORATE_IPS.get(service_identity, ["10.0.1.50"])
    source_ip = rng.choice(ips)
    
    if service_identity == "srv-ledgerone-core":
        vendor = rng.choice(VENDORS)
        return {
            "service_identity": service_identity,
            "endpoint": f"/api/v1/vendors/{vendor}",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": rng.randint(120, 240),
            "response_size_bytes": rng.randint(1200, 3500),
            "source_ip": source_ip,
            "resource_type": "VENDOR",
            "resource_id": vendor,
            "action": "READ_VENDOR_RECORD",
            "timestamp": current_time.isoformat()
        }
    elif service_identity == "srv-ledgerone-paygate":
        pay_id = rng.choice(PAYMENTS)
        return {
            "service_identity": service_identity,
            "endpoint": f"/api/v1/payments/{pay_id}/status",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": rng.randint(100, 200),
            "response_size_bytes": rng.randint(800, 1600),
            "source_ip": source_ip,
            "resource_type": "PAYMENT",
            "resource_id": pay_id,
            "action": "CHECK_PAYMENT_STATUS",
            "timestamp": current_time.isoformat()
        }
    elif service_identity == "srv-helpdeskr-agent":
        vendor = rng.choice(VENDORS)
        return {
            "service_identity": service_identity,
            "endpoint": f"/api/v1/vendors/{vendor}/profile",
            "http_method": "GET" if rng.random() > 0.15 else "PUT",
            "http_status_code": 200,
            "request_size_bytes": rng.randint(150, 400),
            "response_size_bytes": rng.randint(900, 2200),
            "source_ip": source_ip,
            "resource_type": "VENDOR",
            "resource_id": vendor,
            "action": "READ_VENDOR_PROFILE",
            "timestamp": current_time.isoformat()
        }
    else:  # srv-tallybridge-sync
        return {
            "service_identity": service_identity,
            "endpoint": "/api/v1/sync/vendors",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": rng.randint(200, 350),
            "response_size_bytes": rng.randint(2000, 5000),
            "source_ip": source_ip,
            "resource_type": "SYNC",
            "resource_id": "sync_batch_01",
            "action": "SYNC_POLL",
            "timestamp": current_time.isoformat()
        }


def _generate_anomalous_window_events(
    service_identity: str,
    window_start: datetime,
    scenario: str,
    rng: random.Random
) -> List[Dict[str, Any]]:
    """Generate events for a specified anomalous behavioural pattern."""
    events = []
    
    if scenario == "high_request_volume":
        # Sudden velocity spike: 80 to 150 events in 5 minutes
        num_events = rng.randint(80, 150)
        for i in range(num_events):
            t = window_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            events.append(ev)

    elif scenario == "bulk_vendor_access":
        # Massive exfiltration response sizes and multiple vendor dumps
        num_events = rng.randint(12, 25)
        for i in range(num_events):
            t = window_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            ev["endpoint"] = "/api/v1/vendors/export"
            ev["action"] = "BULK_DATA_EXPORT"
            ev["resource_type"] = "VENDOR_DATABASE"
            ev["response_size_bytes"] = rng.randint(8_000_000, 25_000_000)  # 8-25 MB
            events.append(ev)

    elif scenario == "unexpected_access_times":
        # Off-hours execution: at 02:15 UTC (deep night)
        off_hours_start = window_start.replace(hour=2, minute=15)
        num_events = rng.randint(10, 20)
        for i in range(num_events):
            t = off_hours_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            events.append(ev)

    elif scenario == "new_endpoint_usage":
        # Accessing non-baseline internal/admin endpoints
        num_events = rng.randint(6, 15)
        for i in range(num_events):
            t = window_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            ev["endpoint"] = rng.choice([
                "/api/v1/internal/admin/config",
                "/api/v1/internal/debug/memory",
                "/api/v1/system/backup/dump"
            ])
            ev["http_status_code"] = rng.choice([200, 403, 404])
            events.append(ev)

    elif scenario == "unusual_write_activity":
        # Excessive mutation operations (POST/PUT/DELETE)
        num_events = rng.randint(15, 30)
        for i in range(num_events):
            t = window_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            ev["http_method"] = rng.choice(["POST", "PUT", "DELETE"])
            ev["action"] = "MUTATE_CONFIG"
            events.append(ev)

    else:  # combined_suspicious
        # Off-hours bulk dump from an unknown external IP
        off_hours_start = window_start.replace(hour=3, minute=30)
        num_events = rng.randint(20, 40)
        anomalous_ip = rng.choice(EXTERNAL_ANOMALOUS_IPS)
        for i in range(num_events):
            t = off_hours_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            ev["source_ip"] = anomalous_ip
            ev["endpoint"] = "/api/v1/vendors/export/full"
            ev["response_size_bytes"] = rng.randint(10_000_000, 30_000_000)
            events.append(ev)

    return events


def generate_baseline_dataset(
    service_identity: str,
    num_windows: int = 60,
    random_seed: int = 42
) -> pd.DataFrame:
    """
    Generate 100% legitimate, normal API activity windows for baseline model training.
    """
    rng = random.Random(random_seed)
    base_time = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)  # Start during business hours
    
    feature_rows = []
    known_endpoints = set()
    known_ips = set(CORPORATE_IPS.get(service_identity, []))

    for w in range(num_windows):
        window_start = base_time + timedelta(minutes=5 * w)
        # Advance day if past business hours (09:00 - 18:00)
        if window_start.hour >= 18:
            base_time = base_time + timedelta(days=1)
            window_start = base_time.replace(hour=9, minute=0)

        # Generate 4 to 12 normal requests per 5-minute window
        req_count = rng.randint(4, 12)
        window_events = []
        for _ in range(req_count):
            t = window_start + timedelta(seconds=rng.uniform(0, 290))
            ev = _generate_normal_event(service_identity, t, rng)
            window_events.append(ev)
            known_endpoints.add(ev["endpoint"])

        feats = extract_window_features(
            events=window_events,
            service_identity=service_identity,
            baseline_endpoints=known_endpoints,
            baseline_ips=known_ips
        )
        feature_rows.append(feats)

    return dataframe_from_feature_dicts(feature_rows)


def generate_evaluation_dataset(
    service_identity: str,
    num_windows: int = 50,
    anomaly_ratio: float = 0.2,
    random_seed: int = 99
) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Generate labeled test dataset combining normal behavior and specific attack scenarios.
    
    Returns:
        (features_df, ground_truth_labels_series, scenario_labels_list)
        where label 1 = anomaly, 0 = normal.
    """
    rng = random.Random(random_seed)
    base_time = datetime(2026, 11, 15, 9, 0, 0, tzinfo=timezone.utc)
    
    scenarios = [
        "high_request_volume",
        "bulk_vendor_access",
        "unexpected_access_times",
        "new_endpoint_usage",
        "unusual_write_activity",
        "combined_suspicious"
    ]

    feature_rows = []
    labels = []
    scenario_tags = []

    known_endpoints = {f"/api/v1/vendors/{v}" for v in VENDORS}
    known_endpoints.update({f"/api/v1/payments/{p}/status" for p in PAYMENTS})
    known_endpoints.add("/api/v1/sync/vendors")
    known_ips = set(CORPORATE_IPS.get(service_identity, []))

    for w in range(num_windows):
        window_start = base_time + timedelta(minutes=5 * w)
        is_anom = rng.random() < anomaly_ratio

        if is_anom:
            chosen_scenario = rng.choice(scenarios)
            events = _generate_anomalous_window_events(service_identity, window_start, chosen_scenario, rng)
            labels.append(1)
            scenario_tags.append(chosen_scenario)
        else:
            req_count = rng.randint(4, 12)
            events = []
            for _ in range(req_count):
                t = window_start + timedelta(seconds=rng.uniform(0, 290))
                events.append(_generate_normal_event(service_identity, t, rng))
            labels.append(0)
            scenario_tags.append("normal")

        feats = extract_window_features(
            events=events,
            service_identity=service_identity,
            baseline_endpoints=known_endpoints,
            baseline_ips=known_ips
        )
        feature_rows.append(feats)

    df = dataframe_from_feature_dicts(feature_rows)
    return df, pd.Series(labels, name="is_anomaly"), scenario_tags
