"""
API Tests for SENTINEL Machine Learning Subsystem Routes
Tests:
- GET /api/v1/ml/status
- POST /api/v1/ml/train
- GET /api/v1/ml/models
- GET /api/v1/ml/evaluation
- GET /api/v1/ml/anomalies
"""

from fastapi import status


def test_get_ml_status_endpoint(client):
    """GET /api/v1/ml/status must return subsystem operational status and baseline statuses."""
    res = client.get("/api/v1/ml/status")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "operational"
    assert data["feature_schema_version"] == "1.0.0"
    assert "service_baselines" in data
    assert isinstance(data["service_baselines"], dict)


def test_post_ml_train_endpoint_success(client):
    """POST /api/v1/ml/train must explicitly train an Isolation Forest model and return metadata."""
    payload = {
        "service_identity": "srv-ledgerone-paygate",
        "num_samples": 60,
        "version": "1.0.0",
        "contamination": 0.05
    }
    res = client.post("/api/v1/ml/train", json=payload)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["status"] == "success"
    assert "Isolation Forest baseline successfully trained" in data["message"]
    
    meta = data["model_metadata"]
    assert meta["service_identity"] == "srv-ledgerone-paygate"
    assert meta["model_version"] == "1.0.0"
    assert "calibrated_threshold" in meta
    assert meta["feature_count"] == 15


def test_post_ml_train_validation_error(client):
    """POST /api/v1/ml/train with num_samples < 20 must be rejected with HTTP 422."""
    payload = {
        "service_identity": "srv-ledgerone-core",
        "num_samples": 5  # Below ge=20 constraint
    }
    res = client.post("/api/v1/ml/train", json=payload)
    assert res.status_code == 422


def test_get_ml_models_endpoint(client):
    """GET /api/v1/ml/models must list serialized model artifacts."""
    res = client.get("/api/v1/ml/models")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert "count" in data
    assert "models" in data
    assert isinstance(data["models"], list)
    assert data["count"] >= 1


def test_get_ml_evaluation_endpoint(client):
    """GET /api/v1/ml/evaluation must return comprehensive benchmark metrics."""
    res = client.get("/api/v1/ml/evaluation?service_identity=srv-ledgerone-core")
    assert res.status_code == status.HTTP_200_OK
    report = res.json()
    
    assert report["service_identity"] == "srv-ledgerone-core"
    assert "metrics" in report
    metrics = report["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "false_positive_rate" in metrics

    assert "confusion_matrix" in report
    cm = report["confusion_matrix"]
    assert "true_positives" in cm
    assert "false_positives" in cm
    assert "true_negatives" in cm
    assert "false_negatives" in cm
    
    assert "scenario_detection_rates" in report
    scenarios = report["scenario_detection_rates"]
    assert len(scenarios) >= 3
    for sc_name, sc_data in scenarios.items():
        assert "tested_samples" in sc_data
        assert "detected_samples" in sc_data
        assert "detection_rate" in sc_data
    
    assert "limitations_note" in report
    assert len(report["limitations_note"]) > 0


def test_get_ml_anomalies_endpoint(client):
    """GET /api/v1/ml/anomalies must return paginated ML-detected incidents."""
    res = client.get("/api/v1/ml/anomalies?page=1&limit=10")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert "pages" in data
    assert "items" in data
    assert isinstance(data["items"], list)
