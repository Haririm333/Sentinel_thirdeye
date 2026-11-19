"""
Unit Tests for LSTM Autoencoder Architecture, Training, Persistence, and Schema Safety
Tests:
- Encoder and Decoder forward pass dimensions
- Reconstruction MSE loss computation
- Per-feature error decomposition
- Safe state_dict and scaler persistence roundtrip
- Model loading schema validation
- Insufficient training data rejection (< MIN_SEQUENCES_FOR_BASELINE)
"""

import pytest
import numpy as np
import torch

from sentinel.backend.app.ml.lstm.config import lstm_settings, LSTM_FEATURE_NAMES
from sentinel.backend.app.ml.lstm.model import LSTMAutoencoder
from sentinel.backend.app.ml.lstm.model_store import LSTMModelStore
from sentinel.backend.app.ml.lstm.baseline_manager import LSTMBaselineManager
from sentinel.backend.app.ml.lstm.sequence_pipeline import fit_scaler


@pytest.fixture
def temp_lstm_store(tmp_path):
    """Provide isolated temporary LSTMModelStore."""
    return LSTMModelStore(base_dir=tmp_path)


@pytest.fixture
def temp_lstm_manager(temp_lstm_store):
    """Provide isolated LSTMBaselineManager backed by temporary storage."""
    return LSTMBaselineManager(store=temp_lstm_store)


def test_lstm_forward_pass_and_tensor_shapes():
    """Verify Encoder produces (B, latent_dim) and Decoder reconstructs (B, seq_len, D)."""
    batch_size = 4
    seq_len = 20
    input_dim = 15
    latent_dim = 16
    hidden_dim = 32

    model = LSTMAutoencoder(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        latent_dim=latent_dim,
        seq_len=seq_len
    )

    x = torch.randn(batch_size, seq_len, input_dim)
    reconstructed, z = model(x)

    assert z.shape == (batch_size, latent_dim), f"Expected ({batch_size}, {latent_dim}), got {z.shape}"
    assert reconstructed.shape == (batch_size, seq_len, input_dim), f"Expected ({batch_size}, {seq_len}, {input_dim}), got {reconstructed.shape}"


def test_reconstruction_loss_and_per_feature_errors():
    """Verify MSE loss calculation and per-feature error decomposition across 15 features."""
    model = LSTMAutoencoder(input_dim=15, seq_len=20)
    x = torch.ones(2, 20, 15)
    recon = torch.zeros(2, 20, 15)

    loss = model.compute_reconstruction_loss(x, recon)
    # Since x=1 and recon=0, MSE should be 1.0
    assert abs(loss.item() - 1.0) < 1e-5

    feat_errors = model.compute_per_feature_error(x, recon)
    assert len(feat_errors) == 15
    for feat_name, err in feat_errors.items():
        assert feat_name in LSTM_FEATURE_NAMES
        assert abs(err - 1.0) < 1e-5


def test_model_persistence_and_safe_loading_roundtrip(temp_lstm_store):
    """Verify saving model state_dict, scaler, and JSON manifest, and reloading safely."""
    service_id = "srv-test-lstm"
    version = "1.0.0"

    model = LSTMAutoencoder(input_dim=15, seq_len=20)
    raw_data = np.random.randn(20, 20, 15).astype(np.float32)
    scaler = fit_scaler(raw_data)

    feat_baselines = {name: {"mean_error": 0.05, "std_error": 0.02} for name in LSTM_FEATURE_NAMES}

    meta = temp_lstm_store.save_model(
        model=model,
        scaler=scaler,
        service_identity=service_id,
        version=version,
        calibrated_threshold=0.25,
        training_sequence_count=20,
        feature_error_baselines=feat_baselines
    )

    assert meta["model_id"] == f"lstm_{service_id}_v{version}"
    assert meta["feature_count"] == 15

    # Verify loading back from disk
    loaded_model, loaded_scaler, loaded_meta = temp_lstm_store.load_model(service_id, version)
    assert isinstance(loaded_model, LSTMAutoencoder)
    assert loaded_meta["model_id"] == meta["model_id"]
    assert loaded_meta["calibrated_threshold"] == 0.25

    # Test inference with loaded model
    test_tensor = torch.randn(1, 20, 15)
    with torch.no_grad():
        recon, z = loaded_model(test_tensor)
    assert recon.shape == (1, 20, 15)


def test_insufficient_baseline_data_rejection(temp_lstm_manager):
    """Training with fewer than MIN_SEQUENCES_FOR_BASELINE sequences must raise ValueError."""
    service_id = "srv-insufficient-lstm"
    # Only 5 sequences (threshold is 15)
    few_seqs = np.zeros((5, 20, 15), dtype=np.float32)

    with pytest.raises(ValueError) as exc_info:
        temp_lstm_manager.train_service_baseline(
            service_identity=service_id,
            training_sequences=few_seqs
        )

    assert "Insufficient baseline data" in str(exc_info.value)
    assert "Requires at least" in str(exc_info.value)
