"""
Initial LSTM Autoencoder Baseline Training Script for SENTINEL
Trains and calibrates PyTorch LSTM models for all core enterprise services.
"""

from sentinel.backend.app.ml.lstm.baseline_manager import lstm_baseline_manager

SERVICES_TO_TRAIN = [
    "srv-ledgerone-core",
    "srv-ledgerone-paygate",
    "srv-helpdeskr-agent",
    "srv-tallybridge-sync"
]


def train_initial_lstm_baselines():
    """Train baseline LSTM Autoencoder models for all core services."""
    print("=" * 65)
    print("Training SENTINEL Phase 4 LSTM Autoencoder Baselines")
    print("=" * 65)
    for service_id in SERVICES_TO_TRAIN:
        print(f"Training LSTM baseline for {service_id} (CPU)...")
        meta = lstm_baseline_manager.train_service_baseline(service_id, version="1.0.0")
        print(
            f"  [OK] Model: {meta['model_id']} | "
            f"Calibrated Threshold: {meta['calibrated_threshold']:.4f} | "
            f"Sequences: {meta['training_sequence_count']}"
        )
    print("=" * 65)
    print("Initial LSTM baseline training complete.")


if __name__ == "__main__":
    train_initial_lstm_baselines()
