"""
Unit Tests for LSTM Sequence Generation, Chronological Ordering, and Feature Normalization
Tests:
- 15-dimensional event feature extraction
- Handling missing/null/empty event attributes safely
- Sequence generation with exact (N, 20, 15) shape
- Strict chronological ordering enforcement
- Service identity isolation (events from different services never mixed)
- Feature normalization strictly fitted on training sequences
"""

from datetime import datetime, timezone, timedelta
import numpy as np
import pytest

from sentinel.backend.app.ml.lstm.config import LSTM_FEATURE_NAMES, lstm_settings
from sentinel.backend.app.ml.lstm.sequence_pipeline import (
    extract_event_features,
    build_sequences_from_events,
    fit_scaler,
    transform_sequences
)


def test_event_feature_extraction_all_15_features():
    """Verify single event transforms into 15 valid numerical features."""
    event = {
        "event_id": "test-ev-1",
        "service_identity": "srv-ledgerone-core",
        "endpoint": "/api/v1/vendors/vnd_10482",
        "http_method": "GET",
        "http_status_code": 200,
        "request_size_bytes": 150,
        "response_size_bytes": 2200,
        "source_ip": "10.0.1.15",
        "resource_type": "VENDOR",
        "resource_id": "vnd_10482",
        "action": "READ_VENDOR",
        "timestamp": "2026-11-20T14:30:00Z"
    }
    feats = extract_event_features(event)

    assert len(feats) == len(LSTM_FEATURE_NAMES)
    for col in LSTM_FEATURE_NAMES:
        assert col in feats
        assert isinstance(feats[col], (int, float))
        assert not np.isnan(feats[col])

    assert feats["request_size_bytes"] == 150.0
    assert feats["response_size_bytes"] == 2200.0
    assert feats["total_bytes"] == 2350.0
    assert feats["is_read"] == 1.0
    assert feats["is_write"] == 0.0
    assert feats["is_failed"] == 0.0
    assert feats["is_vendor_access"] == 1.0
    assert feats["time_of_day_deviation"] == 0.0  # Business hours


def test_missing_and_null_event_attributes_handling():
    """Sparse events with None/null values must extract safely with sensible defaults."""
    sparse_event = {
        "service_identity": "srv-ledgerone-core",
        "endpoint": None,
        "http_method": None,
        "http_status_code": None,
        "request_size_bytes": None,
        "response_size_bytes": None,
        "source_ip": None,
        "resource_type": None,
        "action": None,
        "timestamp": None
    }
    feats = extract_event_features(sparse_event)

    assert len(feats) == len(LSTM_FEATURE_NAMES)
    for col in LSTM_FEATURE_NAMES:
        assert isinstance(feats[col], (int, float))
        assert not np.isnan(feats[col])

    assert feats["request_size_bytes"] == 0.0
    assert feats["is_failed"] == 0.0
    assert feats["time_delta_seconds"] == 0.0


def test_sequence_generation_shape_and_stride():
    """Verify build_sequences_from_events produces correct (N, seq_len, 15) tensor."""
    service_id = "srv-ledgerone-core"
    base_t = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    
    # Create 35 chronological events
    events = []
    for i in range(35):
        events.append({
            "service_identity": service_id,
            "endpoint": f"/api/v1/vendors/vnd_{i}",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": 120 + i,
            "response_size_bytes": 1500,
            "source_ip": "10.0.1.15",
            "timestamp": (base_t + timedelta(seconds=i * 10)).isoformat()
        })

    # With seq_len=20, stride=5: (35 - 20) // 5 + 1 = 4 sequences
    seqs = build_sequences_from_events(events, service_id, seq_len=20, stride=5)
    assert seqs.shape == (4, 20, 15)
    assert seqs.dtype == np.float32


def test_strict_chronological_ordering_enforcement():
    """Out-of-order events must be strictly sorted by timestamp before slicing."""
    service_id = "srv-ledgerone-core"
    base_t = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # Create events in intentionally scrambled order
    timestamps = [base_t + timedelta(seconds=sec) for sec in [50, 10, 40, 20, 30, 0] + list(range(60, 200, 10))]
    scrambled_events = []
    for idx, ts in enumerate(timestamps):
        scrambled_events.append({
            "service_identity": service_id,
            "endpoint": "/api/v1/vendors",
            "http_method": "GET",
            "http_status_code": 200,
            "request_size_bytes": 100,
            "response_size_bytes": 1000,
            "timestamp": ts.isoformat()
        })

    seqs = build_sequences_from_events(scrambled_events, service_id, seq_len=20, stride=1)
    assert len(seqs) >= 1

    # In the extracted sequence, time_delta_seconds must be non-negative
    delta_idx = LSTM_FEATURE_NAMES.index("time_delta_seconds")
    deltas = seqs[0, :, delta_idx]
    for d in deltas:
        assert d >= 0.0


def test_service_identity_isolation_never_mixed():
    """Events belonging to different services must never be co-mingled into one sequence."""
    base_t = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    
    # Interleaved events from two services
    mixed_events = []
    for i in range(40):
        srv = "srv-ledgerone-core" if i % 2 == 0 else "srv-helpdeskr-agent"
        mixed_events.append({
            "service_identity": srv,
            "endpoint": "/api/v1/test",
            "http_method": "GET",
            "timestamp": (base_t + timedelta(seconds=i * 5)).isoformat()
        })

    # Total events for srv-ledgerone-core is 20
    seqs_core = build_sequences_from_events(mixed_events, "srv-ledgerone-core", seq_len=20)
    assert len(seqs_core) == 1
    assert seqs_core.shape == (1, 20, 15)

    # Requesting a service with fewer than 20 events returns empty array
    few_events = mixed_events[:10]
    seqs_few = build_sequences_from_events(few_events, "srv-ledgerone-core", seq_len=20)
    assert seqs_few.shape == (0, 20, 15)


def test_feature_normalization_train_only():
    """StandardScaler must fit on training data only and correctly normalize test sequences."""
    # 2 training sequences of (20, 15)
    train_seqs = np.random.uniform(10.0, 50.0, size=(2, 20, 15)).astype(np.float32)
    scaler = fit_scaler(train_seqs)

    normalized_train = transform_sequences(train_seqs, scaler)
    assert normalized_train.shape == train_seqs.shape

    # Mean of normalized training data should be close to 0.0, std close to 1.0
    reshaped = normalized_train.reshape(-1, 15)
    assert np.allclose(reshaped.mean(axis=0), 0.0, atol=1e-5)
    assert np.allclose(reshaped.std(axis=0), 1.0, atol=1e-5)

    # Empty array handling
    empty_trans = transform_sequences(np.empty((0, 20, 15)), scaler)
    assert empty_trans.shape == (0, 20, 15)
