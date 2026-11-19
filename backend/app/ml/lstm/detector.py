"""
LSTM Sequence Anomaly Detector for SENTINEL
Computes sequence reconstruction errors, performs calibrated sigmoid scaling,
ranks feature-level error contributions, and dispatches findings to the Incident Management Engine.
"""

import math
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import torch
from sqlalchemy.orm import Session

from sentinel.backend.app.ml.lstm.config import (
    lstm_settings, LSTM_FEATURE_NAMES
)
from sentinel.backend.app.ml.lstm.baseline_manager import (
    lstm_baseline_manager, LSTMBaselineManager
)
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.detection.base_rule import DetectionResult
from sentinel.backend.app.services.incident_service import create_or_update_incident

logger = logging.getLogger("sentinel.ml.lstm.detector")


class LSTMSequenceDetector:
    """Evaluates chronological API event sequences for behavioral sequence anomalies."""
    def __init__(self, manager: LSTMBaselineManager = lstm_baseline_manager):
        self.manager = manager

    def _normalize_anomaly_score(self, reconstruction_error: float, threshold: float) -> float:
        """
        Calibrate raw reconstruction MSE into explainable [0.0, 1.0] scale.
        When error == threshold, score is ~0.50.
        When error significantly exceeds threshold, score scales >= 0.65.
        """
        safe_threshold = max(threshold, 1e-4)
        # Relative overshoot ratio
        rel_diff = (reconstruction_error - safe_threshold) / safe_threshold
        # Sigmoid steepness 6.0 gives smooth transition: 0.50 at rel_diff=0, 0.65 at rel_diff=0.10
        scaled = 1.0 / (1.0 + math.exp(-rel_diff * 6.0))
        return round(float(scaled), 4)

    def _explain_top_feature_errors(
        self,
        feature_errors: Dict[str, float],
        error_baselines: Dict[str, Dict[str, float]],
        top_k: int = 4
    ) -> List[Dict[str, Any]]:
        """
        Rank features by reconstruction error magnitude and deviation from baseline.
        """
        ranked = []
        for feat_name, err in feature_errors.items():
            base_stat = error_baselines.get(feat_name, {})
            mean_base = base_stat.get("mean_error", 0.05)
            ratio = err / max(mean_base, 1e-4)

            ranked.append({
                "feature": feat_name,
                "reconstruction_error": round(float(err), 4),
                "baseline_mean_error": round(float(mean_base), 4),
                "error_ratio": round(float(ratio), 2)
            })

        # Sort by largest error ratio first
        ranked.sort(key=lambda x: x["error_ratio"], reverse=True)
        return ranked[:top_k]

    def score_sequence(
        self,
        sequence: np.ndarray,
        service_identity: str
    ) -> Dict[str, Any]:
        """
        Compute reconstruction error and explainability breakdown for a (20, 15) sequence.
        
        Args:
            sequence: Raw unscaled sequence array of shape (20, 15) or (1, 20, 15).
            service_identity: Target service identity.
        """
        model, scaler, metadata, status = self.manager.get_service_model(service_identity)

        if status != "READY" or model is None or scaler is None:
            return {
                "service_identity": service_identity,
                "model_status": status,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "calibrated_threshold": 0.0,
                "explanation": f"Service baseline status is '{status}'. Insufficient data to evaluate LSTM sequential anomaly.",
                "feature_errors": {},
                "top_deviations": []
            }

        # Ensure 3D shape (1, seq_len, D)
        if sequence.ndim == 2:
            seq_3d = sequence[np.newaxis, :, :]
        else:
            seq_3d = sequence

        N, T, D = seq_3d.shape
        threshold = metadata.get("calibrated_threshold", 0.15)
        baselines = metadata.get("feature_error_baselines", {})

        # 1. Normalize with fitted StandardScaler
        reshaped = seq_3d.reshape(-1, D)
        scaled_reshaped = scaler.transform(reshaped)
        scaled_3d = scaled_reshaped.reshape(N, T, D).astype(np.float32)

        # 2. Forward pass through LSTM Autoencoder
        device = torch.device("cpu")
        tensor_x = torch.tensor(scaled_3d, dtype=torch.float32).to(device)

        model.eval()
        with torch.no_grad():
            reconstructed, _ = model(tensor_x)
            mse_loss = float(model.compute_reconstruction_loss(tensor_x, reconstructed).item())
            feature_errors = model.compute_per_feature_error(tensor_x, reconstructed)

        norm_score = self._normalize_anomaly_score(mse_loss, threshold)
        is_anomaly = norm_score >= lstm_settings.ANOMALY_THRESHOLD

        top_deviations = self._explain_top_feature_errors(feature_errors, baselines)

        if is_anomaly:
            dev_phrases = [
                f"{d['feature']} (err={d['reconstruction_error']}, ratio={d['error_ratio']}x)"
                for d in top_deviations[:2]
            ]
            explanation = (
                f"Sequential behavioral anomaly detected for '{service_identity}' by LSTM Autoencoder "
                f"(reconstruction error: {mse_loss:.4f}, threshold: {threshold:.4f}, score: {norm_score:.2f}). "
                f"Top reconstructing anomalies: {'; '.join(dev_phrases)}."
            )
        else:
            explanation = f"Sequence conforms to learned operational rhythm for '{service_identity}'."

        return {
            "service_identity": service_identity,
            "model_id": metadata.get("model_id"),
            "model_version": metadata.get("model_version"),
            "model_status": "READY",
            "reconstruction_error": round(mse_loss, 4),
            "calibrated_threshold": round(threshold, 4),
            "anomaly_score": norm_score,
            "is_anomaly": is_anomaly,
            "explanation": explanation,
            "feature_errors": feature_errors,
            "top_deviations": top_deviations
        }

    def evaluate_and_record_incident(
        self,
        sequence: np.ndarray,
        recent_events: List[Any],
        db: Session
    ) -> Optional[Incident]:
        """
        Evaluate an event sequence and dispatch to the incident engine if an anomaly is confirmed.
        """
        if not recent_events:
            return None

        last_event = recent_events[-1]
        service_id = getattr(last_event, "service_identity", None) or last_event.get("service_identity")

        scoring_result = self.score_sequence(sequence, service_id)

        if not scoring_result["is_anomaly"]:
            return None

        # Map LSTM anomaly score to incident severity and risk score
        norm_score = scoring_result["anomaly_score"]
        if norm_score >= 0.85:
            severity = "CRITICAL"
            risk_score = 90
        elif norm_score >= 0.75:
            severity = "HIGH"
            risk_score = 75
        else:
            severity = "MEDIUM"
            risk_score = 60

        # Create structured DetectionResult
        result = DetectionResult(
            triggered=True,
            rule_id="ML-ANOMALY-LSTM-001",
            rule_name="LSTM Sequential Behavioural Anomaly",
            severity=severity,
            risk_score=risk_score,
            explanation=scoring_result["explanation"],
            evidence={
                "service_identity": service_id,
                "model_id": scoring_result["model_id"],
                "model_version": scoring_result["model_version"],
                "sequence_length": lstm_settings.SEQUENCE_LENGTH,
                "reconstruction_error": scoring_result["reconstruction_error"],
                "calibrated_threshold": scoring_result["calibrated_threshold"],
                "anomaly_score": scoring_result["anomaly_score"],
                "top_deviations": scoring_result["top_deviations"],
                "scoring_breakdown": {
                    "base_score": risk_score,
                    "modifiers": [
                        {"factor": "lstm_reconstruction_error", "points": 0, "reason": f"Calibrated score {norm_score:.2f}"}
                    ],
                    "final_score": risk_score,
                    "severity": severity
                }
            },
            resource_type=getattr(last_event, "resource_type", None) or (last_event.get("resource_type") if isinstance(last_event, dict) else None),
            resource_id=getattr(last_event, "resource_id", None) or (last_event.get("resource_id") if isinstance(last_event, dict) else None)
        )

        incident = create_or_update_incident(db=db, result=result, event=last_event)
        logger.warning(
            "[LSTM ANOMALY DETECTED] Service: %s | Score: %.2f | Incident: %s",
            service_id, norm_score, incident.incident_id
        )
        return incident


lstm_detector = LSTMSequenceDetector()
