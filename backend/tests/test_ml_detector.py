"""
Unit Tests for SENTINEL Isolation Forest ML Anomaly Detector and Baseline Manager
Tests baseline loading, normal vs anomalous detection, threshold calibration,
insufficient baseline enforcement, and Joblib model persistence integrity.
"""

import tempfile
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

from sentinel.backend.app.ml.config import FEATURE_NAMES, ml_settings
from sentinel.backend.app.ml.model_store import ModelStore
from sentinel.backend.app.ml.baseline_manager import BaselineManager
from sentinel.backend.app.ml.detector import AnomalyDetector
from sentinel.backend.app.ml.dataset_generator import generate_baseline_dataset


@pytest.fixture
def temp_model_store(tmp_path):
    """Provide an isolated ModelStore in a temporary directory."""
    return ModelStore(base_dir=tmp_path)


@pytest.fixture
def test_baseline_manager(temp_model_store):
    """Provide a BaselineManager backed by isolated temporary storage."""
    return BaselineManager(store=temp_model_store)


@pytest.fixture
def test_detector(test_baseline_manager):
    """Provide an AnomalyDetector instance backed by isolated manager."""
    return AnomalyDetector(manager=test_baseline_manager)


def test_insufficient_baseline_data_rejection(test_baseline_manager):
    """Services with fewer than MIN_SAMPLES_FOR_BASELINE must reject training with clear error."""
    # Create insufficient dataset (< 20 samples)
    small_df = pd.DataFrame(
        np.zeros((10, len(FEATURE_NAMES))),
        columns=FEATURE_NAMES
    )
    
    with pytest.raises(ValueError) as exc_info:
        test_baseline_manager.train_service_baseline(
            service_identity="srv-insufficient-test",
            training_df=small_df
        )
    
    assert "Insufficient baseline data" in str(exc_info.value)
    assert "Requires at least" in str(exc_info.value)


def test_baseline_training_and_persistence_roundtrip(test_baseline_manager, temp_model_store):
    """Verify explicit training creates Joblib file and metadata JSON with correct schema."""
    service_id = "srv-test-vendor"
    
    # Train model on synthetic baseline
    meta = test_baseline_manager.train_service_baseline(service_id, version="1.0.0")
    
    assert meta["service_identity"] == service_id
    assert meta["model_version"] == "1.0.0"
    assert meta["training_sample_count"] >= ml_settings.MIN_SAMPLES_FOR_BASELINE
    assert meta["feature_count"] == 15
    assert "calibrated_threshold" in meta
    assert isinstance(meta["calibrated_threshold"], float)

    # Verify files exist in storage
    model_path = temp_model_store.base_dir / f"isoforest_{service_id}_v1.0.0.joblib"
    meta_path = temp_model_store.base_dir / f"isoforest_{service_id}_v1.0.0.json"
    assert model_path.exists()
    assert meta_path.exists()

    # Verify loading back from disk
    loaded_model, loaded_meta = temp_model_store.load_model(service_id, "1.0.0")
    assert isinstance(loaded_model, IsolationForest)
    assert loaded_meta["model_id"] == meta["model_id"]


def test_normal_activity_scoring(test_baseline_manager, test_detector):
    """Routine conforming activity must yield anomaly score below ANOMALY_THRESHOLD."""
    service_id = "srv-ledgerone-core"
    test_baseline_manager.train_service_baseline(service_id, version="1.0.0")

    # Generate a normal feature vector matching the learned baseline
    normal_df = generate_baseline_dataset(service_id, num_windows=5, random_seed=123)
    normal_features = normal_df.iloc[0].to_dict()

    result = test_detector.score_features(normal_features, service_id)

    assert result["service_identity"] == service_id
    assert result["model_status"] == "READY"
    assert result["is_anomaly"] is False
    assert result["anomaly_score"] < ml_settings.ANOMALY_THRESHOLD
    assert "conforms to learned baseline" in result["explanation"]


def test_anomalous_activity_scoring_and_explanations(test_baseline_manager, test_detector):
    """Extreme deviation (bulk data exfiltration at off hours) must trigger anomaly and top deviation ranking."""
    service_id = "srv-anom-test"
    test_baseline_manager.train_service_baseline(service_id, version="1.0.0")

    # Anomalous features: massive data transfer, off-hours, high write, unknown IP
    anomalous_features = {
        "requests_count": 85.0,
        "avg_request_size": 2500.0,
        "avg_response_size": 15_000_000.0,
        "total_bytes_transferred": 1_275_000_000.0,
        "unique_endpoints_count": 18.0,
        "unique_vendors_count": 85.0,
        "read_to_write_ratio": 0.1,
        "failed_request_ratio": 0.45,
        "unusual_method_frequency": 0.35,
        "time_of_day_deviation": 1.0,  # Deep night
        "inter_request_time_variance": 0.05,
        "new_endpoint_ratio": 0.8,
        "source_ip_novelty": 1.0,
        "sensitive_resource_frequency": 0.9,
        "permission_deviation_count": 15.0
    }

    result = test_detector.score_features(anomalous_features, service_id)

    assert result["is_anomaly"] is True
    assert result["anomaly_score"] >= ml_settings.ANOMALY_THRESHOLD
    assert "Behavioural anomaly detected" in result["explanation"]
    
    # Verify top deviations breakdown
    top_devs = result["top_deviations"]
    assert len(top_devs) > 0
    # Top deviation should have significant Z-score
    assert top_devs[0]["z_score"] > 2.0


def test_unregistered_or_untrained_service_handling(test_detector):
    """Scoring an un-baselined service must safely report UNTRAINED without guessing."""
    unregistered_service = "srv-unknown-new-connector"
    features = {col: 10.0 for col in FEATURE_NAMES}

    result = test_detector.score_features(features, unregistered_service)

    assert result["service_identity"] == unregistered_service
    assert result["model_status"] == "UNTRAINED"
    assert result["is_anomaly"] is False
    assert result["anomaly_score"] == 0.0
    assert "Insufficient data" in result["explanation"]
