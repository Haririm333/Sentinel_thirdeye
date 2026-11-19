"""
Model Evaluation and Benchmark Reporting for SENTINEL Anomaly Detection
Evaluates Isolation Forest on separate synthetic datasets using Precision, Recall,
F1-score, False Positive Rate (FPR), Confusion Matrix, and per-scenario detection rates.
"""

import json
import logging
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from sentinel.backend.app.ml.config import MODELS_STORE_DIR
from sentinel.backend.app.ml.baseline_manager import baseline_manager
from sentinel.backend.app.ml.dataset_generator import generate_baseline_dataset, generate_evaluation_dataset

logger = logging.getLogger("sentinel.ml.evaluator")


def evaluate_service_model(
    service_identity: str = "srv-ledgerone-core",
    test_windows: int = 60,
    anomaly_ratio: float = 0.25,
    random_seed: int = 101
) -> Dict[str, Any]:
    """
    Run comprehensive statistical evaluation for a service's Isolation Forest model.
    """
    # 1. Ensure baseline model is trained
    model, metadata, status = baseline_manager.get_service_model(service_identity)
    if status != "READY" or model is None:
        logger.info("Training baseline model for %s prior to evaluation...", service_identity)
        baseline_manager.train_service_baseline(service_identity)
        model, metadata, status = baseline_manager.get_service_model(service_identity)

    # 2. Generate held-out evaluation dataset (ground truth labeled)
    test_df, y_true, scenarios = generate_evaluation_dataset(
        service_identity=service_identity,
        num_windows=test_windows,
        anomaly_ratio=anomaly_ratio,
        random_seed=random_seed
    )

    # 3. Model inference
    threshold = metadata.get("calibrated_threshold", -0.5)
    X_test = test_df.values
    raw_scores = model.score_samples(X_test)
    y_pred = (raw_scores <= threshold).astype(int)

    # 4. Standard classification metrics
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # 5. Scenario-specific detection breakdown
    scenario_detection = {}
    for sc, yt, yp in zip(scenarios, y_true, y_pred):
        if yt == 1:  # Only evaluate attacks
            if sc not in scenario_detection:
                scenario_detection[sc] = {"total": 0, "detected": 0}
            scenario_detection[sc]["total"] += 1
            if yp == 1:
                scenario_detection[sc]["detected"] += 1

    scenario_rates = {}
    for sc, stats in scenario_detection.items():
        rate = float(stats["detected"] / stats["total"]) if stats["total"] > 0 else 0.0
        scenario_rates[sc] = {
            "tested_samples": stats["total"],
            "detected_samples": stats["detected"],
            "detection_rate": round(rate, 4)
        }

    report = {
        "service_identity": service_identity,
        "model_id": metadata.get("model_id"),
        "evaluation_samples": len(y_true),
        "metrics": {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4)
        },
        "confusion_matrix": {
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn)
        },
        "scenario_detection_rates": scenario_rates,
        "hyperparameters": metadata.get("hyperparameters", {}),
        "limitations_note": (
            "Evaluation conducted on synthetic development dataset. "
            "Real-world accuracy may vary based on deployment traffic diversity."
        )
    }

    # Save evaluation report artifact
    report_path = MODELS_STORE_DIR / f"evaluation_{service_identity}.json"
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        logger.warning("Could not write evaluation report file: %s", e)

    return report
