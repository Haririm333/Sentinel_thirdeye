"""
Model Storage and Serialization for SENTINEL Machine Learning Artifacts
Uses Joblib with strict metadata verification and feature schema compatibility checks.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import joblib
from sklearn.ensemble import IsolationForest

from sentinel.backend.app.ml.config import MODELS_STORE_DIR, FEATURE_NAMES, ml_settings

logger = logging.getLogger("sentinel.ml.model_store")


class ModelStore:
    """Manages saving, loading, and metadata tracking for Isolation Forest models."""
    def __init__(self, base_dir: Path = MODELS_STORE_DIR):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_model_paths(self, service_identity: str, version: str) -> Tuple[Path, Path]:
        """Generate safe, sanitized artifact paths for model binary and metadata."""
        safe_service = "".join(c for c in service_identity if c.isalnum() or c in ("-", "_"))
        safe_version = "".join(c for c in version if c.isalnum() or c in (".", "-", "_"))
        model_filename = f"isoforest_{safe_service}_v{safe_version}.joblib"
        meta_filename = f"isoforest_{safe_service}_v{safe_version}.json"
        return self.base_dir / model_filename, self.base_dir / meta_filename

    def save_model(
        self,
        model: IsolationForest,
        service_identity: str,
        version: str,
        calibrated_threshold: float,
        training_sample_count: int,
        feature_baselines: Dict[str, Dict[str, float]],
        hyperparameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Save an IsolationForest model and its accompanying metadata.
        """
        model_path, meta_path = self._get_model_paths(service_identity, version)
        
        # 1. Serialize model binary via Joblib
        joblib.dump(model, model_path, compress=3)

        # 2. Construct metadata manifest
        metadata = {
            "model_id": f"isoforest_{service_identity}_v{version}",
            "model_version": version,
            "service_identity": service_identity,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "feature_schema_version": ml_settings.FEATURE_SCHEMA_VERSION,
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "calibrated_threshold": float(calibrated_threshold),
            "training_sample_count": int(training_sample_count),
            "hyperparameters": hyperparameters or {
                "n_estimators": ml_settings.N_ESTIMATORS,
                "contamination": ml_settings.CONTAMINATION,
                "random_state": ml_settings.RANDOM_STATE
            },
            "feature_baselines": feature_baselines,
            "model_status": "READY"
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info(
            "Successfully serialized model '%s' to %s",
            metadata["model_id"], model_path
        )
        return metadata

    def load_model(
        self,
        service_identity: str,
        version: str = "1.0.0"
    ) -> Tuple[IsolationForest, Dict[str, Any]]:
        """
        Load Isolation Forest model and verify feature schema compatibility.
        """
        model_path, meta_path = self._get_model_paths(service_identity, version)

        if not model_path.exists() or not meta_path.exists():
            raise FileNotFoundError(
                f"No saved model found for service '{service_identity}' version '{version}'."
            )

        # 1. Load and validate metadata manifest
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        # Validate schema version
        if metadata.get("feature_schema_version") != ml_settings.FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible feature schema version: model has '{metadata.get('feature_schema_version')}', "
                f"system requires '{ml_settings.FEATURE_SCHEMA_VERSION}'"
            )

        # Validate feature set completeness
        loaded_features = metadata.get("feature_names", [])
        if loaded_features != FEATURE_NAMES:
            raise ValueError(
                f"Feature specification mismatch for model {metadata.get('model_id')}. "
                f"Expected {len(FEATURE_NAMES)} features, found {len(loaded_features)}."
            )

        # 2. Load model binary
        model = joblib.load(model_path)
        if not isinstance(model, IsolationForest):
            raise TypeError("Deserialized artifact is not an instance of IsolationForest.")

        return model, metadata

    def list_saved_models(self) -> List[Dict[str, Any]]:
        """List all available models in the models store."""
        models = []
        for meta_file in self.base_dir.glob("isoforest_*.json"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    if "model_id" in meta and "calibrated_threshold" in meta:
                        models.append(meta)
            except Exception as e:
                logger.warning("Could not read model manifest %s: %s", meta_file, e)
        return sorted(models, key=lambda x: x.get("created_at", ""), reverse=True)


model_store = ModelStore()
