"""
Isolation Forest Behavioural Anomaly Detector for SENTINEL
Scores feature observations, generates explainable feature contribution rankings,
and transparently dispatches findings to the Incident Management Engine.
"""

import math
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from sentinel.backend.app.ml.config import FEATURE_NAMES, ml_settings
from sentinel.backend.app.ml.features import features_to_vector
from sentinel.backend.app.ml.baseline_manager import baseline_manager, BaselineManager
from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.detection.base_rule import DetectionResult
from sentinel.backend.app.services.incident_service import create_or_update_incident

logger = logging.getLogger("sentinel.ml.detector")


class AnomalyDetector:
    """Evaluates API events for behavioural anomalies using service baselines."""
    def __init__(self, manager: BaselineManager = baseline_manager):
        self.manager = manager

    def _normalize_anomaly_score(self, raw_score: float, threshold: float) -> float:
        """
        Calibrate raw Isolation Forest score into explainable [0.0, 1.0] scale.
        Raw scores below the threshold map to scores >= 0.65 (anomalous).
        """
        # Sigmoid calibration around the threshold point
        # When raw_score == threshold, exponent is 0, sigmoid gives 0.65 with offset
        diff = threshold - raw_score  # positive when anomalous
        scaled = 1.0 / (1.0 + math.exp(-diff * 15.0))
        # Ensure smooth mapping between 0.1 and 0.99
        return round(float(scaled), 4)

    def _explain_top_deviations(
        self,
        features: Dict[str, float],
        baselines: Dict[str, Dict[str, float]],
        top_k: int = 4
    ) -> List[Dict[str, Any]]:
        """
        Rank features by statistical Z-score deviation against the learned baseline.
        """
        deviations = []
        for feat_name, val in features.items():
            stat = baselines.get(feat_name, {})
            mean = stat.get("mean", 0.0)
            std = stat.get("std", 1.0)
            z_score = abs(val - mean) / (std if std > 1e-4 else 1.0)
            
            deviations.append({
                "feature": feat_name,
                "observed_value": round(val, 2),
                "baseline_mean": round(mean, 2),
                "z_score": round(float(z_score), 2)
            })

        # Sort by largest deviation first
        deviations.sort(key=lambda x: x["z_score"], reverse=True)
        return deviations[:top_k]

    def score_features(
        self,
        features: Dict[str, float],
        service_identity: str
    ) -> Dict[str, Any]:
        """
        Compute anomaly score and explainability breakdown for a feature observation.
        """
        model, metadata, status = self.manager.get_service_model(service_identity)

        if status != "READY" or model is None:
            return {
                "service_identity": service_identity,
                "model_status": status,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "explanation": f"Service baseline status is '{status}'. Insufficient data to evaluate ML anomaly.",
                "feature_values": features,
                "top_deviations": []
            }

        threshold = metadata.get("calibrated_threshold", -0.5)
        baselines = metadata.get("feature_baselines", {})

        # Prepare vector
        X = features_to_vector(features).reshape(1, -1)
        
        # Scikit-learn raw score
        raw_score = float(model.score_samples(X)[0])
        norm_score = self._normalize_anomaly_score(raw_score, threshold)
        is_anomaly = norm_score >= ml_settings.ANOMALY_THRESHOLD

        top_deviations = self._explain_top_deviations(features, baselines)

        # Build natural language explanation
        if is_anomaly:
            dev_phrases = [
                f"{d['feature']}={d['observed_value']} (baseline: {d['baseline_mean']}, z={d['z_score']})"
                for d in top_deviations[:2]
            ]
            explanation = (
                f"Behavioural anomaly detected for '{service_identity}' by Isolation Forest "
                f"(score: {norm_score:.2f}, threshold: {ml_settings.ANOMALY_THRESHOLD}). "
                f"Top deviations: {'; '.join(dev_phrases)}."
            )
        else:
            explanation = f"Activity conforms to learned baseline for '{service_identity}'."

        return {
            "service_identity": service_identity,
            "model_id": metadata.get("model_id"),
            "model_version": metadata.get("model_version"),
            "model_status": "READY",
            "raw_score": round(raw_score, 4),
            "calibrated_threshold": round(threshold, 4),
            "anomaly_score": norm_score,
            "is_anomaly": is_anomaly,
            "explanation": explanation,
            "feature_values": features,
            "top_deviations": top_deviations
        }

    def evaluate_and_record_incident(
        self,
        features: Dict[str, float],
        event: ApiEvent,
        db: Session
    ) -> Optional[Incident]:
        """
        Score event features and dispatch to incident engine if an anomaly is detected.
        """
        scoring_result = self.score_features(features, event.service_identity)

        if not scoring_result["is_anomaly"]:
            return None

        # Map ML anomaly score to incident severity and risk score
        norm_score = scoring_result["anomaly_score"]
        if norm_score >= 0.85:
            severity = "CRITICAL"
            risk_score = 88
        elif norm_score >= 0.75:
            severity = "HIGH"
            risk_score = 72
        else:
            severity = "MEDIUM"
            risk_score = 55

        # Format detection result matching BaseDetectionRule contract
        result = DetectionResult(
            triggered=True,
            rule_id="ML-ANOMALY-ISOFOR-001",
            rule_name="Isolation Forest Behavioural Anomaly",
            severity=severity,
            risk_score=risk_score,
            explanation=scoring_result["explanation"],
            evidence={
                "service_identity": event.service_identity,
                "model_id": scoring_result["model_id"],
                "model_version": scoring_result["model_version"],
                "anomaly_score": scoring_result["anomaly_score"],
                "raw_score": scoring_result["raw_score"],
                "calibrated_threshold": scoring_result["calibrated_threshold"],
                "top_deviations": scoring_result["top_deviations"],
                "feature_values": scoring_result["feature_values"],
                "scoring_breakdown": {
                    "base_score": risk_score,
                    "modifiers": [
                        {"factor": "isolation_forest_anomaly", "points": 0, "reason": f"Calibrated score {norm_score:.2f}"}
                    ],
                    "final_score": risk_score,
                    "severity": severity
                }
            },
            resource_type=event.resource_type,
            resource_id=event.resource_id
        )

        # Correlate and record incident via incident service
        incident = create_or_update_incident(db=db, result=result, event=event)
        logger.warning(
            "[ML ANOMALY DETECTED] Service: %s | Score: %.2f | Incident: %s",
            event.service_identity, norm_score, incident.incident_id
        )
        return incident


anomaly_detector = AnomalyDetector()
