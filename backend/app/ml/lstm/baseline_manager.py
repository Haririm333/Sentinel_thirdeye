"""
LSTM Service Baseline Manager and Training Pipeline
Orchestrates:
- Chronological sequence data generation and train/val splitting.
- StandardScaler fitting on training sequences only (no data leakage).
- PyTorch training loop on CPU using Adam optimizer and MSE reconstruction loss.
- Threshold calibration against validation error distributions.
- Strict sufficiency enforcement (MIN_SEQUENCES_FOR_BASELINE >= 15).
"""

import logging
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
import torch
from torch.utils.data import TensorDataset, DataLoader

from sentinel.backend.app.ml.lstm.config import (
    lstm_settings, LSTM_FEATURE_NAMES
)
from sentinel.backend.app.ml.lstm.model import LSTMAutoencoder
from sentinel.backend.app.ml.lstm.sequence_pipeline import (
    fit_scaler, transform_sequences
)
from sentinel.backend.app.ml.lstm.model_store import lstm_model_store, LSTMModelStore
from sentinel.backend.app.ml.lstm.dataset_generator import generate_lstm_training_dataset

logger = logging.getLogger("sentinel.ml.lstm.baseline_manager")


class LSTMBaselineManager:
    """Manages service baselines and LSTM Autoencoder training, loading, and status."""
    def __init__(self, store: LSTMModelStore = lstm_model_store):
        self.store = store
        self._active_models: Dict[str, Tuple[LSTMAutoencoder, Any, Dict[str, Any]]] = {}
        self._service_statuses: Dict[str, str] = {}  # READY, INSUFFICIENT_BASELINE, UNTRAINED

    def train_service_baseline(
        self,
        service_identity: str,
        training_sequences: Optional[np.ndarray] = None,
        version: str = "1.0.0",
        epochs: Optional[int] = None,
        batch_size: Optional[int] = None,
        learning_rate: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Explicitly train an LSTM Autoencoder for a service on normal sequences.
        
        Args:
            service_identity: Target service identity.
            training_sequences: Optional pre-constructed sequences array of shape (N, 20, 15).
            version: Target version string.
            epochs: Optional epoch override.
            batch_size: Optional batch size override.
            learning_rate: Optional learning rate override.
            
        Returns:
            Metadata dict summarizing the trained model.
        """
        n_epochs = epochs or lstm_settings.EPOCHS
        b_size = batch_size or lstm_settings.BATCH_SIZE
        lr = learning_rate or lstm_settings.LEARNING_RATE

        # 1. Acquire baseline sequences
        if training_sequences is None or len(training_sequences) == 0:
            logger.info("Generating synthetic normal sequence baseline for %s...", service_identity)
            training_sequences = generate_lstm_training_dataset(
                service_identity=service_identity,
                num_events=200,
                seq_len=lstm_settings.SEQUENCE_LENGTH,
                stride=2,
                random_seed=lstm_settings.RANDOM_STATE
            )

        # 2. Check sufficiency requirement
        seq_count = len(training_sequences)
        if seq_count < lstm_settings.MIN_SEQUENCES_FOR_BASELINE:
            self._service_statuses[service_identity] = "INSUFFICIENT_BASELINE"
            raise ValueError(
                f"Insufficient baseline data for service '{service_identity}'. "
                f"Requires at least {lstm_settings.MIN_SEQUENCES_FOR_BASELINE} sequences, got {seq_count}. "
                "System will not guess or claim sequential familiarity without adequate telemetry."
            )

        # 3. Train / Validation split (80% train, 20% validation)
        split_idx = max(int(seq_count * 0.8), lstm_settings.MIN_SEQUENCES_FOR_BASELINE - 5)
        raw_train = training_sequences[:split_idx]
        raw_val = training_sequences[split_idx:] if split_idx < seq_count else raw_train[-5:]

        # 4. Fit StandardScaler strictly on training data
        scaler = fit_scaler(raw_train)
        X_train_scaled = transform_sequences(raw_train, scaler)
        X_val_scaled = transform_sequences(raw_val, scaler)

        # 5. Build PyTorch model
        device = torch.device("cpu")
        model = LSTMAutoencoder(
            input_dim=len(LSTM_FEATURE_NAMES),
            hidden_dim=lstm_settings.HIDDEN_DIM,
            latent_dim=lstm_settings.LATENT_DIM,
            seq_len=lstm_settings.SEQUENCE_LENGTH,
            num_layers=lstm_settings.NUM_LAYERS
        ).to(device)

        # Prepare DataLoader
        train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
        dataset = TensorDataset(train_tensor)
        dataloader = DataLoader(dataset, batch_size=b_size, shuffle=True)

        optimizer = torch.optim.Adam(model.parameters(), lr=lr)

        # 6. Training Loop (CPU)
        model.train()
        for epoch in range(n_epochs):
            epoch_loss = 0.0
            for (batch_x,) in dataloader:
                batch_x = batch_x.to(device)
                optimizer.zero_grad()
                reconstructed, _ = model(batch_x)
                loss = model.compute_reconstruction_loss(batch_x, reconstructed)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch_x)
            
            avg_loss = epoch_loss / len(train_tensor)
            if (epoch + 1) % 10 == 0 or epoch == n_epochs - 1:
                logger.debug("[%s] Epoch %d/%d - Loss: %.5f", service_identity, epoch + 1, n_epochs, avg_loss)

        # 7. Validation & Threshold Calibration
        model.eval()
        val_tensor = torch.tensor(X_val_scaled, dtype=torch.float32).to(device)
        with torch.no_grad():
            val_recon, _ = model(val_tensor)
            val_sq_errors = ((val_tensor - val_recon) ** 2).mean(dim=(1, 2)).cpu().numpy()
            feature_errors = model.compute_per_feature_error(val_tensor, val_recon)

        # Calibrate threshold at statistical boundary (mean + 2.5 * std or 98th percentile * 1.15)
        mean_err = float(np.mean(val_sq_errors))
        std_err = float(np.std(val_sq_errors))
        calibrated_threshold = max(mean_err + 2.5 * std_err, float(np.percentile(val_sq_errors, 98.0) * 1.15))
        calibrated_threshold = max(calibrated_threshold, 0.15)

        # Feature error baselines for explainability
        feature_error_baselines = {}
        for feat_name, err_val in feature_errors.items():
            feature_error_baselines[feat_name] = {
                "mean_error": round(float(err_val), 4),
                "std_error": round(float(err_val * 0.4 + 0.01), 4)  # Estimated deviation band
            }

        # 8. Save artifacts
        meta = self.store.save_model(
            model=model,
            scaler=scaler,
            service_identity=service_identity,
            version=version,
            calibrated_threshold=calibrated_threshold,
            training_sequence_count=len(training_sequences),
            feature_error_baselines=feature_error_baselines,
            hyperparameters={
                "hidden_dim": lstm_settings.HIDDEN_DIM,
                "latent_dim": lstm_settings.LATENT_DIM,
                "seq_len": lstm_settings.SEQUENCE_LENGTH,
                "epochs": n_epochs,
                "batch_size": b_size,
                "learning_rate": lr
            }
        )

        self._active_models[service_identity] = (model, scaler, meta)
        self._service_statuses[service_identity] = "READY"
        logger.info(
            "Successfully established LSTM baseline for %s (threshold=%.4f)",
            service_identity, calibrated_threshold
        )
        return meta

    def get_service_model(
        self,
        service_identity: str,
        version: str = "1.0.0"
    ) -> Tuple[Optional[LSTMAutoencoder], Optional[Any], Dict[str, Any], str]:
        """
        Retrieve active model, scaler, metadata, and status.
        Loads from disk if not already in memory.
        """
        if service_identity in self._active_models:
            model, scaler, meta = self._active_models[service_identity]
            return model, scaler, meta, "READY"

        try:
            model, scaler, meta = self.store.load_model(service_identity, version)
            self._active_models[service_identity] = (model, scaler, meta)
            self._service_statuses[service_identity] = "READY"
            return model, scaler, meta, "READY"
        except FileNotFoundError:
            status = self._service_statuses.get(service_identity, "UNTRAINED")
            return None, None, {}, status
        except Exception as exc:
            logger.warning("Error loading LSTM model for %s: %s", service_identity, exc)
            return None, None, {}, "ERROR"

    def get_status_overview(self) -> Dict[str, Dict[str, Any]]:
        """Return operational status across known services."""
        known_services = [
            "srv-ledgerone-core",
            "srv-ledgerone-paygate",
            "srv-helpdeskr-agent",
            "srv-tallybridge-sync"
        ]
        statuses = {}
        for s_id in known_services:
            model, scaler, meta, status = self.get_service_model(s_id)
            statuses[s_id] = {
                "status": status,
                "model_id": meta.get("model_id"),
                "calibrated_threshold": meta.get("calibrated_threshold"),
                "trained_at": meta.get("created_at")
            }
        return statuses


lstm_baseline_manager = LSTMBaselineManager()
