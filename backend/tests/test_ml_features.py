"""
Tests for ML Feature Engineering, Normalization, and Missing Field Handling
"""

from datetime import datetime, timezone
import numpy as np
from sentinel.backend.app.ml.config import FEATURE_NAMES
from sentinel.backend.app.ml.features import (
    extract_window_features,
    features_to_vector,
    dataframe_from_feature_dicts
)


def test_feature_extraction_all_15_features():
    """Verify that feature extraction produces all 15 expected keys with finite values."""
    mock_events = [
        {
            "endpoint": "/api/v1/vendors/vnd_10482",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": 150,
            "response_size_bytes": 2200,
            "source_ip": "10.0.1.45",
            "resource_type": "VENDOR",
            "resource_id": "vnd_10482",
            "action": "READ_VENDOR_RECORD",
            "timestamp": "2026-11-20T10:00:00Z"
        },
        {
            "endpoint": "/api/v1/vendors/vnd_10483",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": 160,
            "response_size_bytes": 2400,
            "source_ip": "10.0.1.45",
            "resource_type": "VENDOR",
            "resource_id": "vnd_10483",
            "action": "READ_VENDOR_RECORD",
            "timestamp": "2026-11-20T10:01:30Z"
        }
    ]

    features = extract_window_features(mock_events, service_identity="srv-ledgerone-core")
    
    assert len(features) == len(FEATURE_NAMES)
    for col in FEATURE_NAMES:
        assert col in features
        assert not np.isnan(features[col])
        assert not np.isinf(features[col])

    assert features["requests_count"] == 2.0
    assert features["unique_vendors_count"] == 2.0
    assert features["unique_endpoints_count"] == 2.0
    assert features["failed_request_ratio"] == 0.0
    assert features["time_of_day_deviation"] == 0.0  # 10:00 UTC is normal business hours


def test_missing_and_empty_events_handling():
    """Empty event lists or events with missing attributes must handle safely."""
    # 1. Completely empty window
    empty_features = extract_window_features([], service_identity="srv-ledgerone-core")
    assert len(empty_features) == len(FEATURE_NAMES)
    for col in FEATURE_NAMES:
        assert empty_features[col] == 0.0

    # 2. Events with None/null values
    sparse_events = [
        {
            "endpoint": None,
            "http_method": None,
            "http_status_code": None,
            "request_size_bytes": None,
            "response_size_bytes": None,
            "timestamp": None
        }
    ]
    sparse_features = extract_window_features(sparse_events, service_identity="srv-ledgerone-core")
    assert sparse_features["requests_count"] == 1.0
    assert sparse_features["avg_request_size"] == 0.0
    assert sparse_features["avg_response_size"] == 0.0


def test_time_of_day_deviation_business_vs_off_hours():
    """Verify that off-hours events yield elevated time_of_day_deviation."""
    # 1. Normal business hours: 14:00 UTC
    event_day = [{
        "endpoint": "/api/v1/vendors",
        "http_method": "GET",
        "timestamp": "2026-11-20T14:00:00Z"
    }]
    feats_day = extract_window_features(event_day, service_identity="srv-ledgerone-core")
    assert feats_day["time_of_day_deviation"] == 0.0

    # 2. Deep off-hours: 02:00 UTC (6 hours away from 08:00)
    event_night = [{
        "endpoint": "/api/v1/vendors",
        "http_method": "GET",
        "timestamp": "2026-11-20T02:00:00Z"
    }]
    feats_night = extract_window_features(event_night, service_identity="srv-ledgerone-core")
    assert feats_night["time_of_day_deviation"] > 0.5


def test_features_to_vector_and_dataframe():
    """Verify deterministic conversion to numpy vectors and pandas DataFrames."""
    sample_feats = {name: float(i) for i, name in enumerate(FEATURE_NAMES)}
    vec = features_to_vector(sample_feats)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (15,)
    assert vec[0] == sample_feats[FEATURE_NAMES[0]]

    df = dataframe_from_feature_dicts([sample_feats, sample_feats])
    assert df.shape == (2, 15)
    assert list(df.columns) == FEATURE_NAMES
