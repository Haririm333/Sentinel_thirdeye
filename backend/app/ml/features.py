"""
Feature Engineering Module for SENTINEL Anomaly Detection
Transforms raw API telemetry events into a standardized 15-dimensional behavioural feature vector.
Strictly excludes sensitive identifiers (passwords, tokens, bank accounts, event IDs).
"""

import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Union, Set
import numpy as np
import pandas as pd

from sentinel.backend.app.ml.config import FEATURE_NAMES, ml_settings
from sentinel.backend.app.detection.config import SIMULATED_SERVICE_POLICIES


def extract_window_features(
    events: List[Any],
    service_identity: str,
    baseline_endpoints: Set[str] = None,
    baseline_ips: Set[str] = None
) -> Dict[str, float]:
    """
    Extract standardized 15-dimensional numerical feature dictionary from a list of events
    occurring within an observation window for a specific service identity.
    
    Args:
        events: List of ApiEvent models or dictionaries representing events in the window.
        service_identity: Service identity under observation.
        baseline_endpoints: Set of historical/sanctioned endpoints for novelty checking.
        baseline_ips: Set of sanctioned/historical IPs for novelty checking.
        
    Returns:
        Dictionary mapping feature names to float values.
    """
    if not events:
        # Safe fallback for empty window
        return {name: 0.0 for name in FEATURE_NAMES}

    total_requests = len(events)
    
    # 1. Size & Transfer Aggregations
    req_sizes = []
    resp_sizes = []
    endpoints = []
    vendors = set()
    read_count = 0
    write_count = 0
    failed_count = 0
    unusual_method_count = 0
    sensitive_count = 0
    timestamps = []
    source_ips = []
    permission_violations = 0

    # Policy for service
    policy = SIMULATED_SERVICE_POLICIES.get(service_identity, {})
    allowed_methods = set(policy.get("allowed_methods", ["GET"]))
    allowed_ips = set(policy.get("allowed_ips", []))
    if baseline_ips:
        allowed_ips.update(baseline_ips)

    for ev in events:
        # Safely extract fields handling both ORM object and dict, with complete None-safety
        if isinstance(ev, dict):
            endpoint = str(ev.get("endpoint") or "")
            raw_method = ev.get("http_method") or "GET"
            method = str(raw_method).upper() if raw_method else "GET"
            raw_status = ev.get("http_status_code")
            try:
                status_code = int(raw_status) if raw_status is not None else 200
            except (ValueError, TypeError):
                status_code = 200
            req_size = ev.get("request_size_bytes") or 0
            resp_size = ev.get("response_size_bytes") or 0
            source_ip = str(ev.get("source_ip") or "")
            raw_res = ev.get("resource_type") or ""
            res_type = str(raw_res).upper() if raw_res else ""
            res_id = str(ev.get("resource_id") or "")
            raw_act = ev.get("action") or ""
            action = str(raw_act).upper() if raw_act else ""
            ts = ev.get("timestamp")
        else:
            endpoint = str(getattr(ev, "endpoint", None) or "")
            raw_method = getattr(ev, "http_method", None) or "GET"
            method = str(raw_method).upper() if raw_method else "GET"
            raw_status = getattr(ev, "http_status_code", None)
            try:
                status_code = int(raw_status) if raw_status is not None else 200
            except (ValueError, TypeError):
                status_code = 200
            req_size = getattr(ev, "request_size_bytes", None) or 0
            resp_size = getattr(ev, "response_size_bytes", None) or 0
            source_ip = str(getattr(ev, "source_ip", None) or "")
            raw_res = getattr(ev, "resource_type", None) or ""
            res_type = str(raw_res).upper() if raw_res else ""
            res_id = str(getattr(ev, "resource_id", None) or "")
            raw_act = getattr(ev, "action", None) or ""
            action = str(raw_act).upper() if raw_act else ""
            ts = getattr(ev, "timestamp", None)

        try:
            req_sizes.append(float(req_size or 0))
        except (ValueError, TypeError):
            req_sizes.append(0.0)

        try:
            resp_sizes.append(float(resp_size or 0))
        except (ValueError, TypeError):
            resp_sizes.append(0.0)

        endpoints.append(endpoint)
        source_ips.append(source_ip)

        # Vendor record tracking
        if res_type in ("VENDOR", "VENDOR_RECORD") and res_id:
            vendors.add(res_id)
        elif "/vendors/vnd_" in endpoint.lower():
            # Extract vendor id substring from endpoint if available
            parts = endpoint.split("/")
            for p in parts:
                if p.startswith("vnd_"):
                    vendors.add(p)

        # Read vs Write
        if method in ("GET", "HEAD", "OPTIONS"):
            read_count += 1
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            write_count += 1

        # Status code failure check
        if status_code >= 400:
            failed_count += 1

        # Unusual method check
        if method in ("PATCH", "DELETE", "OPTIONS", "HEAD"):
            unusual_method_count += 1

        # Sensitive resource access
        is_sensitive = (
            res_type == "BANK_ACCOUNT" or 
            "/bank-account" in endpoint.lower() or 
            "/export" in endpoint.lower() or
            "BANK" in action or
            "EXPORT" in action
        )
        if is_sensitive:
            sensitive_count += 1

        # Policy deviation count
        if method not in allowed_methods:
            permission_violations += 1

        # Parse timestamp for temporal metrics
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                timestamps.append(dt)
            except Exception:
                pass
        elif isinstance(ts, datetime):
            timestamps.append(ts)

    # 2. Computations
    avg_req_size = float(np.mean(req_sizes)) if req_sizes else 0.0
    avg_resp_size = float(np.mean(resp_sizes)) if resp_sizes else 0.0
    total_bytes = float(sum(req_sizes) + sum(resp_sizes))
    unique_endpoints = float(len(set(endpoints)))
    unique_vendors = float(len(vendors))

    read_to_write_ratio = float(read_count) / float(write_count + 1.0)
    failed_request_ratio = float(failed_count) / float(total_requests)
    unusual_method_freq = float(unusual_method_count) / float(total_requests)
    sensitive_resource_freq = float(sensitive_count) / float(total_requests)

    # Time of Day Deviation (0.0 = completely within 08:00-19:00 UTC, 1.0 = deep night off-hours)
    time_deviations = []
    for dt in timestamps:
        hour = dt.hour + (dt.minute / 60.0)
        if ml_settings.BUSINESS_HOURS_START <= hour <= ml_settings.BUSINESS_HOURS_END:
            time_deviations.append(0.0)
        else:
            # Distance from nearest business hour boundary
            dist_morning = abs(hour - ml_settings.BUSINESS_HOURS_START)
            dist_evening = abs(hour - ml_settings.BUSINESS_HOURS_END)
            min_dist = min(dist_morning, dist_evening)
            # Max possible distance is ~6.5 hours away, normalize to [0, 1]
            time_deviations.append(min(1.0, min_dist / 6.0))
    time_of_day_dev = float(np.mean(time_deviations)) if time_deviations else 0.0

    # Inter-request time variance
    if len(timestamps) > 1:
        timestamps_sorted = sorted(timestamps)
        diffs = [
            (t2 - t1).total_seconds() 
            for t1, t2 in zip(timestamps_sorted[:-1], timestamps_sorted[1:])
        ]
        inter_request_var = float(np.var(diffs)) if len(diffs) > 1 else 0.0
    else:
        inter_request_var = 0.0

    # New Endpoint Ratio
    if baseline_endpoints:
        new_ep_count = sum(1 for ep in endpoints if ep not in baseline_endpoints)
        new_endpoint_ratio = float(new_ep_count) / float(total_requests)
    else:
        new_endpoint_ratio = 0.0

    # Source IP Novelty
    if allowed_ips:
        unseen_ip_count = sum(1 for ip in source_ips if ip not in allowed_ips)
        source_ip_novelty = float(unseen_ip_count) / float(total_requests)
    else:
        source_ip_novelty = 0.0

    features = {
        "requests_count": float(total_requests),
        "avg_request_size": avg_req_size,
        "avg_response_size": avg_resp_size,
        "total_bytes_transferred": total_bytes,
        "unique_endpoints_count": unique_endpoints,
        "unique_vendors_count": unique_vendors,
        "read_to_write_ratio": read_to_write_ratio,
        "failed_request_ratio": failed_request_ratio,
        "unusual_method_frequency": unusual_method_freq,
        "time_of_day_deviation": time_of_day_dev,
        "inter_request_time_variance": inter_request_var,
        "new_endpoint_ratio": new_endpoint_ratio,
        "source_ip_novelty": source_ip_novelty,
        "sensitive_resource_frequency": sensitive_resource_freq,
        "permission_deviation_count": float(permission_violations)
    }

    # Verify every feature is finite
    for k in features:
        if math.isnan(features[k]) or math.isinf(features[k]):
            features[k] = 0.0

    return features


def features_to_vector(features: Dict[str, float]) -> np.ndarray:
    """Convert feature dictionary into ordered NumPy vector matching FEATURE_NAMES."""
    return np.array([features.get(name, 0.0) for name in FEATURE_NAMES], dtype=np.float64)


def dataframe_from_feature_dicts(feature_dicts: List[Dict[str, float]]) -> pd.DataFrame:
    """Create structured Pandas DataFrame with guaranteed column order."""
    df = pd.DataFrame(feature_dicts)
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0.0
    return df[FEATURE_NAMES]
