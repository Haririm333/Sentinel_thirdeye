"""
Initial Baseline Model Training Script for SENTINEL
Pre-trains and calibrates Isolation Forest models for standard services.
"""

from sentinel.backend.app.ml.baseline_manager import baseline_manager

SERVICES_TO_TRAIN = [
    "srv-ledgerone-core",
    "srv-ledgerone-paygate",
    "srv-helpdeskr-agent",
    "srv-tallybridge-sync"
]


def train_initial_baselines():
    """Train baseline Isolation Forest models for core services."""
    print("=" * 60)
    print("Training SENTINEL Phase 3 Baseline Models")
    print("=" * 60)
    for service_id in SERVICES_TO_TRAIN:
        print(f"Training Isolation Forest baseline for {service_id}...")
        meta = baseline_manager.train_service_baseline(service_id, version="1.0.0")
        print(f"  [OK] Model: {meta['model_id']} | Calibrated Threshold: {meta['calibrated_threshold']:.4f} | Samples: {meta['training_sample_count']}")
    print("=" * 60)
    print("Initial baseline training complete.")


if __name__ == "__main__":
    train_initial_baselines()
