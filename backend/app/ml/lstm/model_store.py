"""
Model Persistence and Safe Deserialization for LSTM Autoencoders
Persists:
- PyTorch state_dict (weights_only=True for safe deserialization)
- StandardScaler (joblib)
- JSON metadata manifest with feature schema validation
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List, Optional
import torch
import joblib
from sklearn.preprocessing import StandardScaler

from sentinel.backend.app.ml.lstm.config import LSTM_MODELS_STORE_DIR, LSTM_FEATURE_NAMES, lstm_settings
from sentinel.backend.app.ml.lstm.model import LSTMAutoencoder

logger = logging.getLogger("sentinel.ml.lstm.model_store")


class LSTMModelStore:
    """Manages saving, safe loading, and metadata tracking for LSTM Autoencoders."""
    def __init__(self, base_dir: Path = LSTM_MODELS_STORE_DIR):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_paths(self, service_identity: str, version: str) -> Tuple[Path, Path, Path]:
        """Generate safe, sanitized artifact paths for weights, scaler, and metadata."""
        safe_service = "".join(c for c in service_identity if c.isalnum() or c in ("-", "_"))
        safe_version = "".join(c for c in version if c.isalnum() or c in (".", "-", "_"))
        prefix = f"lstm_{safe_service}_v{safe_version}"
        weights_path = self.base_dir / f"{prefix}.pt"
        scaler_path = self.base_dir / f"{prefix}_scaler.joblib"
        meta_path = self.base_dir / f"{prefix}.json"
        return weights_path, scaler_path, meta_path

    def save_model(
        self,
        model: LSTMAutoencoder,
        scaler: StandardScaler,
        service_identity: str,
        version: str,
        calibrated_threshold: float,
        training_sequence_count: int,
        feature_error_baselines: Dict[str, Dict[str, float]],
        hyperparameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Save an LSTMAutoencoder model, fitted StandardScaler, and metadata manifest.
        """
        weights_path, scaler_path, meta_path = self._get_paths(service_identity, version)

        # 1. Save PyTorch model state_dict
        torch.save(model.state_dict(), weights_path)

        # 2. Save fitted StandardScaler via joblib
        joblib.dump(scaler, scaler_path, compress=3)

        # 3. Construct and write metadata manifest
        metadata = {
            "model_id": f"lstm_{service_identity}_v{version}",
            "model_version": version,
            "service_identity": service_identity,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "feature_schema_version": lstm_settings.FEATURE_SCHEMA_VERSION,
            "feature_names": LSTM_FEATURE_NAMES,
            "feature_count": len(LSTM_FEATURE_NAMES),
            "calibrated_threshold": float(calibrated_threshold),
            "training_sequence_count": int(training_sequence_count),
            "config": model.get_config(),
            "hyperparameters": hyperparameters or {
                "hidden_dim": lstm_settings.HIDDEN_DIM,
                "latent_dim": lstm_settings.LATENT_DIM,
                "seq_len": lstm_settings.SEQUENCE_LENGTH,
                "epochs": lstm_settings.EPOCHS,
                "batch_size": lstm_settings.BATCH_SIZE,
                "learning_rate": lstm_settings.LEARNING_RATE
            },
            "feature_error_baselines": feature_error_baselines,
            "model_status": "READY"
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info(
            "Successfully saved LSTM Autoencoder '%s' to %s",
            metadata["model_id"], weights_path
        )
        return metadata

    def load_model(
        self,
        service_identity: str,
        version: str = "1.0.0"
    ) -> Tuple[LSTMAutoencoder, StandardScaler, Dict[str, Any]]:
        """
        Safely load model weights, scaler, and verify schema compatibility.
        """
        weights_path, scaler_path, meta_path = self._get_paths(service_identity, version)

        if not meta_path.exists() or not weights_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(
                f"Model artifacts for service '{service_identity}' (v{version}) not found."
            )

        # 1. Read metadata manifest
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        # Verify schema version
        loaded_features = metadata.get("feature_names", [])
        if len(loaded_features) != len(LSTM_FEATURE_NAMES):
            raise ValueError(
                f"Feature specification mismatch for LSTM model {metadata.get('model_id')}. "
                f"Expected {len(LSTM_FEATURE_NAMES)} features, found {len(loaded_features)}."
            )

        # 2. Re-instantiate architecture from stored config
        cfg = metadata.get("config", {})
        model = LSTMAutoencoder(
            input_dim=cfg.get("input_dim", len(LSTM_FEATURE_NAMES)),
            hidden_dim=cfg.get("hidden_dim", lstm_settings.HIDDEN_DIM),
            latent_dim=cfg.get("latent_dim", lstm_settings.LATENT_DIM),
            seq_len=cfg.get("seq_len", lstm_settings.SEQUENCE_LENGTH),
            num_layers=cfg.get("num_layers", lstm_settings.NUM_LAYERS)
        )

        # 3. Safe weight loading (weights_only=True prevents code execution)
        state_dict = torch.load(weights_path, map_location="cpu", weights_only=True)
        model.load_state_dict(state_dict)
        model.eval()

        # 4. Load StandardScaler
        scaler = joblib.load(scaler_path)

        return model, scaler, metadata

    def list_saved_models(self) -> List[Dict[str, Any]]:
        """List all saved LSTM models in the models store."""
        models = []
        for meta_file in self.base_dir.glob("lstm_*.json"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    if "model_id" in meta and "calibrated_threshold" in meta:
                        models.append(meta)
            except Exception as e:
                logger.warning("Could not read LSTM model manifest %s: %s", meta_file, e)
        return sorted(models, key=lambda x: x.get("created_at", ""), reverse=True)


lstm_model_store = LSTMModelStore()
