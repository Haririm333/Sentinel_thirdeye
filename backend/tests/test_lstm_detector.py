"""
Unit Tests for LSTM Sequence Anomaly Detector
Tests:
- Normal sequence evaluation and low reconstruction error
- Multi-step attack sequence detection and elevated reconstruction error
- Explainability via top feature-level reconstruction errors
- Safe handling of un-baselined or untrained services
"""

import numpy as np
import pytest

from sentinel.backend.app.ml.lstm.config import lstm_settings, LSTM_FEATURE_NAMES
from sentinel.backend.app.ml.lstm.baseline_manager import LSTMBaselineManager
from sentinel.backend.app.ml.lstm.detector import LSTMSequenceDetector
from sentinel.backend.app.ml.lstm.model_store import LSTMModelStore
from sentinel.backend.app.ml.lstm.dataset_generator import (
    generate_lstm_training_dataset,
    generate_anomalous_event_sequence
)
from sentinel.backend.app.ml.lstm.sequence_pipeline import build_sequences_from_events
from datetime import datetime, timezone


@pytest.fixture
def isolated_lstm_store(tmp_path):
    return LSTMModelStore(base_dir=tmp_path)


@pytest.fixture
def isolated_lstm_manager(isolated_lstm_store):
    return LSTMBaselineManager(store=isolated_lstm_store)


@pytest.fixture
def isolated_lstm_detector(isolated_lstm_manager):
    return LSTMSequenceDetector(manager=isolated_lstm_manager)


def test_normal_sequence_reconstruction_scoring(isolated_lstm_manager, isolated_lstm_detector):
    """Routine conforming sequence must yield reconstruction error below threshold and is_anomaly=False."""
    service_id = "srv-ledgerone-core"
    
    # Train lightweight baseline
    train_seqs = generate_lstm_training_dataset(service_id, num_events=180, seq_len=20, random_seed=42)
    isolated_lstm_manager.train_service_baseline(service_id, training_sequences=train_seqs, epochs=15)

    # Normal sequence from baseline distribution
    normal_seq = train_seqs[0]
    result = isolated_lstm_detector.score_sequence(normal_seq, service_id)

    assert result["service_identity"] == service_id
    assert result["model_status"] == "READY"
    assert result["is_anomaly"] is False
    assert result["anomaly_score"] < lstm_settings.ANOMALY_THRESHOLD
    assert "conforms to learned operational rhythm" in result["explanation"]


def test_anomalous_sequence_detection_and_explainability(isolated_lstm_manager, isolated_lstm_detector):
    """
    Simulated multi-step attack sequence (off-hours bulk exfiltration from external IP)
    must produce elevated reconstruction error, score >= 0.65, and explain top features.
    """
    service_id = "srv-ledgerone-core"
    
    # Train lightweight baseline
    train_seqs = generate_lstm_training_dataset(service_id, num_events=180, seq_len=20, random_seed=42)
    isolated_lstm_manager.train_service_baseline(service_id, training_sequences=train_seqs, epochs=15)

    # Generate an off-hours bulk exfiltration attack sequence
    start_t = datetime(2026, 11, 20, 3, 30, 0, tzinfo=timezone.utc)
    attack_events = generate_anomalous_event_sequence(
        service_identity=service_id,
        scenario="off_hours_bulk_exfiltration",
        start_time=start_t,
        seq_len=20,
        random_seed=77
    )
    attack_seqs = build_sequences_from_events(attack_events, service_id, seq_len=20)
    assert len(attack_seqs) == 1

    result = isolated_lstm_detector.score_sequence(attack_seqs[0], service_id)

    assert result["is_anomaly"] is True
    assert result["anomaly_score"] >= lstm_settings.ANOMALY_THRESHOLD
    assert "Sequential behavioral anomaly detected" in result["explanation"]

    # Verify explainability ranking
    top_devs = result["top_deviations"]
    assert len(top_devs) > 0
    # Top deviation should have an error ratio > 1.5x
    assert top_devs[0]["error_ratio"] > 1.2


def test_untrained_service_handling(isolated_lstm_detector):
    """Scoring an untrained service must return safe UNTRAINED status without throwing an unhandled exception."""
    unregistered = "srv-unknown-new-connector"
    dummy_seq = np.zeros((20, 15), dtype=np.float32)

    result = isolated_lstm_detector.score_sequence(dummy_seq, unregistered)

    assert result["service_identity"] == unregistered
    assert result["model_status"] == "UNTRAINED"
    assert result["is_anomaly"] is False
    assert result["anomaly_score"] == 0.0
    assert "Insufficient data" in result["explanation"]
