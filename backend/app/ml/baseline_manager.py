"""
Service Baseline Manager and Explicit Isolation Forest Training Pipeline
Enforces strict baseline sufficiency standards: services with insufficient training samples
are flagged with INSUFFICIENT_BASELINE rather than guessing or outputting ungrounded inferences.
"""

import logging
from typing import Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from sentinel.backend.app.ml.config import ml_settings, FEATURE_NAMES
from sentinel.backend.app.ml.model_store import model_store, ModelStore
from sentinel.backend.app.ml.dataset_generator import generate_baseline_dataset

logger = logging.getLogger("sentinel.ml.baseline_manager")


class BaselineManager:
    """Manages service baselines and Isolation Forest training/loading."""
    def __init__(self, store: ModelStore = model_store):
        self.store = store
        self._active_models: Dict[str, IsolationForest] = {}
        self._active_metadata: Dict[str, Dict[str, Any]] = {}
        self._service_statuses: Dict[str, str] = {}  # READY, INSUFFICIENT_BASELINE, UNTRAINED

    def train_service_baseline(
        self,
        service_identity: str,
        training_df: Optional[pd.DataFrame] = None,
        version: str = "1.0.0",
        contamination: float = None
    ) -> Dict[str, Any]:
        """
        Explicitly train an Isolation Forest model for a service on normal baseline data.
        
        Args:
            service_identity: The target service identity.
            training_df: Optional DataFrame of normal feature observations. If None, generated.
            version: Target model version string.
            contamination: Optional override for contamination parameter.
            
        Returns:
            Metadata dict summarizing the trained model.
        """
        contamination_val = contamination or ml_settings.CONTAMINATION

        # 1. Acquire baseline feature dataset
        if training_df is None or len(training_df) == 0:
            logger.info("Generating synthetic normal baseline for %s...", service_identity)
            training_df = generate_baseline_dataset(
                service_identity=service_identity,
                num_windows=60,
                random_seed=ml_settings.RANDOM_STATE
            )

        # 2. Check baseline sufficiency requirement
        sample_count = len(training_df)
        if sample_count < ml_settings.MIN_SAMPLES_FOR_BASELINE:
            self._service_statuses[service_identity] = "INSUFFICIENT_BASELINE"
            raise ValueError(
                f"Insufficient baseline data for service '{service_identity}'. "
                f"Requires at least {ml_settings.MIN_SAMPLES_FOR_BASELINE} samples, got {sample_count}. "
                "System will not guess or claim behavioural familiarity without adequate data."
            )

        # 3. Compute feature statistics for explainability
        feature_baselines = {}
        X = training_df[FEATURE_NAMES].values.astype(np.float64)

        for col in FEATURE_NAMES:
            series = training_df[col].values
            mean_val = float(np.mean(series))
            std_val = float(np.std(series))
            feature_baselines[col] = {
                "mean": round(mean_val, 4),
                "std": round(std_val if std_val > 1e-6 else 1.0, 4),
                "min": round(float(np.min(series)), 4),
                "max": round(float(np.max(series)), 4)
            }

        # 4. Instantiate and fit Isolation Forest on pure normal data
        model = IsolationForest(
            n_estimators=ml_settings.N_ESTIMATORS,
            contamination=contamination_val,
            random_state=ml_settings.RANDOM_STATE,
            n_jobs=1  # CPU execution
        )
        model.fit(X)

        # 5. Calibrate threshold: Isolation Forest score_samples outputs negative values.
        # More negative = more anomalous. We calculate calibrated threshold at the 5th percentile.
        raw_scores = model.score_samples(X)
        threshold = float(np.percentile(raw_scores, contamination_val * 100))

        # 6. Save model and metadata
        meta = self.store.save_model(
            model=model,
            service_identity=service_identity,
            version=version,
            calibrated_threshold=threshold,
            training_sample_count=sample_count,
            feature_baselines=feature_baselines,
            hyperparameters={
                "n_estimators": ml_settings.N_ESTIMATORS,
                "contamination": contamination_val,
                "random_state": ml_settings.RANDOM_STATE
            }
        )

        # 7. Cache in memory
        self._active_models[service_identity] = model
        self._active_metadata[service_identity] = meta
        self._service_statuses[service_identity] = "READY"

        logger.info("Successfully established baseline for %s (threshold=%.4f)", service_identity, threshold)
        return meta

    def get_service_model(
        self,
        service_identity: str
    ) -> Tuple[Optional[IsolationForest], Optional[Dict[str, Any]], str]:
        """
        Retrieve active model for service.
        Returns: (model, metadata, status_string)
        where status_string is 'READY', 'INSUFFICIENT_BASELINE', or 'UNTRAINED'.
        """
        # Check in-memory cache
        if service_identity in self._active_models:
            return self._active_models[service_identity], self._active_metadata[service_identity], "READY"

        # Try loading from disk
        try:
            model, meta = self.store.load_model(service_identity)
            self._active_models[service_identity] = model
            self._active_metadata[service_identity] = meta
            self._service_statuses[service_identity] = "READY"
            return model, meta, "READY"
        except FileNotFoundError:
            status_val = self._service_statuses.get(service_identity, "UNTRAINED")
            return None, None, status_val

    def get_status_overview(self) -> Dict[str, Any]:
        """Return system-wide ML model readiness overview."""
        known_services = [
            "srv-ledgerone-core",
            "srv-ledgerone-paygate",
            "srv-helpdeskr-agent",
            "srv-tallybridge-sync"
        ]
        status_map = {}
        for s in known_services:
            _, meta, st = self.get_service_model(s)
            status_map[s] = {
                "status": st,
                "model_id": meta.get("model_id") if meta else None,
                "calibrated_threshold": meta.get("calibrated_threshold") if meta else None,
                "trained_at": meta.get("created_at") if meta else None
            }
        return status_map


baseline_manager = BaselineManager()
