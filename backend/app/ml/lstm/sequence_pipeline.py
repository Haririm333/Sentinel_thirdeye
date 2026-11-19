"""
Sequence Data Pipeline for SENTINEL LSTM Autoencoder
Converts raw API events into chronological sequences of 15 compatible numerical features.
Guarantees:
- Chronological ordering per sequence.
- Strict isolation by service identity (never mixed).
- Feature normalization using training data only (StandardScaler).
- Zero PII / raw secret exposure.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
import numpy as np
from sklearn.preprocessing import StandardScaler

from sentinel.backend.app.ml.lstm.config import LSTM_FEATURE_NAMES, lstm_settings
from sentinel.backend.app.ml.config import ml_settings
from sentinel.backend.app.detection.config import SIMULATED_SERVICE_POLICIES


def extract_event_features(
    event: Any,
    prev_event: Optional[Any] = None,
    baseline_endpoints: Optional[Set[str]] = None,
    baseline_ips: Optional[Set[str]] = None
) -> Dict[str, float]:
    """
    Extract a 15-dimensional numerical feature representation from a single API event.
    Reuses compatible behavioral concepts from Phase 3.
    """
    if isinstance(event, dict):
        endpoint = str(event.get("endpoint") or "")
        raw_method = event.get("http_method") or "GET"
        method = str(raw_method).upper() if raw_method else "GET"
        raw_status = event.get("http_status_code")
        try:
            status_code = int(raw_status) if raw_status is not None else 200
        except (ValueError, TypeError):
            status_code = 200
        req_size = float(event.get("request_size_bytes") or 0)
        resp_size = float(event.get("response_size_bytes") or 0)
        source_ip = str(event.get("source_ip") or "")
        raw_res = event.get("resource_type") or ""
        res_type = str(raw_res).upper() if raw_res else ""
        res_id = str(event.get("resource_id") or "")
        raw_act = event.get("action") or ""
        action = str(raw_act).upper() if raw_act else ""
        service_id = str(event.get("service_identity") or "")
        ts = event.get("timestamp")
    else:
        endpoint = str(getattr(event, "endpoint", None) or "")
        raw_method = getattr(event, "http_method", None) or "GET"
        method = str(raw_method).upper() if raw_method else "GET"
        raw_status = getattr(event, "http_status_code", None)
        try:
            status_code = int(raw_status) if raw_status is not None else 200
        except (ValueError, TypeError):
            status_code = 200
        req_size = float(getattr(event, "request_size_bytes", None) or 0)
        resp_size = float(getattr(event, "response_size_bytes", None) or 0)
        source_ip = str(getattr(event, "source_ip", None) or "")
        raw_res = getattr(event, "resource_type", None) or ""
        res_type = str(raw_res).upper() if raw_res else ""
        res_id = str(getattr(event, "resource_id", None) or "")
        raw_act = getattr(event, "action", None) or ""
        action = str(raw_act).upper() if raw_act else ""
        service_id = str(getattr(event, "service_identity", None) or "")
        ts = getattr(event, "timestamp", None)

    # 1. Total bytes
    total_bytes = req_size + resp_size

    # 2. Method classifications
    is_write = 1.0 if method in ("POST", "PUT", "PATCH", "DELETE") else 0.0
    is_read = 1.0 if method in ("GET", "HEAD", "OPTIONS") else 0.0
    is_unusual_method = 1.0 if method in ("PATCH", "DELETE", "OPTIONS", "HEAD") else 0.0

    # 3. HTTP status failure
    is_failed = 1.0 if status_code >= 400 else 0.0

    # 4. Parse timestamp
    dt = None
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
    elif isinstance(ts, datetime):
        dt = ts
    else:
        dt = datetime.now(timezone.utc)

    # 5. Time of day deviation (0.0 = business hours 08:00-19:00, 1.0 = deep night)
    hour = dt.hour + (dt.minute / 60.0)
    if ml_settings.BUSINESS_HOURS_START <= hour <= ml_settings.BUSINESS_HOURS_END:
        time_dev = 0.0
    else:
        dist_morning = abs(hour - ml_settings.BUSINESS_HOURS_START)
        dist_evening = abs(hour - ml_settings.BUSINESS_HOURS_END)
        time_dev = min(1.0, min(dist_morning, dist_evening) / 6.0)

    # 6. Inter-event time delta (rhythm)
    time_delta = 0.0
    if prev_event is not None:
        prev_ts = prev_event.get("timestamp") if isinstance(prev_event, dict) else getattr(prev_event, "timestamp", None)
        if isinstance(prev_ts, str):
            try:
                prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                time_delta = max(0.0, (dt - prev_dt).total_seconds())
            except Exception:
                time_delta = 0.0
        elif isinstance(prev_ts, datetime):
            time_delta = max(0.0, (dt - prev_ts).total_seconds())

    # 7. Vendor record access indicator
    is_vendor = 1.0 if (res_type in ("VENDOR", "VENDOR_RECORD") or "/vendors" in endpoint.lower()) else 0.0

    # 8. Policy permissions and novelty
    policy = SIMULATED_SERVICE_POLICIES.get(service_id, {})
    allowed_methods = set(policy.get("allowed_methods", ["GET"]))
    allowed_ips = set(policy.get("allowed_ips", []))
    if baseline_ips:
        allowed_ips.update(baseline_ips)

    is_perm_violation = 1.0 if method not in allowed_methods else 0.0
    is_ip_novel = 1.0 if (allowed_ips and source_ip not in allowed_ips) else 0.0

    is_new_ep = 1.0 if (baseline_endpoints and endpoint not in baseline_endpoints) else 0.0

    # 9. Sensitive resource indicator
    is_sensitive = 1.0 if (
        res_type == "BANK_ACCOUNT" or
        "/bank-account" in endpoint.lower() or
        "/export" in endpoint.lower() or
        "/dump" in endpoint.lower() or
        "BANK" in action or
        "EXPORT" in action
    ) else 0.0

    # 10. Normalized endpoint ordinal
    # Deterministic pseudo-ordinal based on path segments
    ep_ordinal = (float(abs(hash(endpoint)) % 100)) / 100.0

    return {
        "request_size_bytes": req_size,
        "response_size_bytes": resp_size,
        "total_bytes": total_bytes,
        "is_write": is_write,
        "is_read": is_read,
        "is_failed": is_failed,
        "is_unusual_method": is_unusual_method,
        "time_of_day_deviation": round(time_dev, 4),
        "time_delta_seconds": min(3600.0, round(time_delta, 2)),
        "is_vendor_access": is_vendor,
        "is_new_endpoint": is_new_ep,
        "source_ip_novelty": is_ip_novel,
        "is_sensitive_resource": is_sensitive,
        "is_permission_violation": is_perm_violation,
        "endpoint_ordinal": ep_ordinal
    }


def parse_event_timestamp(ev: Any) -> datetime:
    """Safely parse datetime from event object or dictionary."""
    ts = ev.get("timestamp") if isinstance(ev, dict) else getattr(ev, "timestamp", None)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)
    elif isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def build_sequences_from_events(
    events: List[Any],
    service_identity: str,
    seq_len: int = 20,
    stride: int = 1,
    baseline_endpoints: Optional[Set[str]] = None,
    baseline_ips: Optional[Set[str]] = None
) -> np.ndarray:
    """
    Construct chronological 3D tensor of shape (N, seq_len, 15) for a given service.
    
    Guarantees:
    - Events filtered strictly to service_identity.
    - Chronologically sorted by event timestamp.
    - Zero data leakage between past and future.
    """
    # 1. Filter strictly by service identity
    service_events = []
    for ev in events:
        sid = ev.get("service_identity") if isinstance(ev, dict) else getattr(ev, "service_identity", None)
        if sid == service_identity:
            service_events.append(ev)

    if len(service_events) < seq_len:
        # Not enough events to form even one complete sequence
        return np.empty((0, seq_len, len(LSTM_FEATURE_NAMES)), dtype=np.float32)

    # 2. Sort chronologically
    service_events.sort(key=parse_event_timestamp)

    # 3. Extract feature vectors step by step
    feat_vectors = []
    prev_ev = None
    for ev in service_events:
        feats = extract_event_features(
            event=ev,
            prev_event=prev_ev,
            baseline_endpoints=baseline_endpoints,
            baseline_ips=baseline_ips
        )
        vec = [feats[name] for name in LSTM_FEATURE_NAMES]
        feat_vectors.append(vec)
        prev_ev = ev

    feat_matrix = np.array(feat_vectors, dtype=np.float32)  # shape (Total_Events, 15)

    # 4. Construct sliding windows
    sequences = []
    num_events = len(feat_matrix)
    for start_idx in range(0, num_events - seq_len + 1, stride):
        seq = feat_matrix[start_idx : start_idx + seq_len]
        sequences.append(seq)

    return np.array(sequences, dtype=np.float32) if sequences else np.empty((0, seq_len, len(LSTM_FEATURE_NAMES)), dtype=np.float32)


def fit_scaler(sequences: np.ndarray) -> StandardScaler:
    """
    Fit a StandardScaler on training sequences only.
    Input shape: (N, seq_len, D) -> reshapes to (N * seq_len, D) to learn per-feature mean and std.
    """
    if len(sequences) == 0:
        raise ValueError("Cannot fit scaler on empty sequence array.")
    
    N, T, D = sequences.shape
    reshaped = sequences.reshape(-1, D)
    scaler = StandardScaler()
    scaler.fit(reshaped)
    return scaler


def transform_sequences(sequences: np.ndarray, scaler: StandardScaler) -> np.ndarray:
    """
    Normalize sequences using a fitted StandardScaler.
    Preserves 3D shape (N, seq_len, D).
    """
    if len(sequences) == 0:
        return sequences
    N, T, D = sequences.shape
    reshaped = sequences.reshape(-1, D)
    scaled_reshaped = scaler.transform(reshaped)
    return scaled_reshaped.reshape(N, T, D).astype(np.float32)
