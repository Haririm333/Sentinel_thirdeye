"""
SENTINEL Phase 4 - LSTM Autoencoder Configuration
Defines sequential hyperparameters, feature specifications, and storage directories.
"""

from pathlib import Path
from typing import List
from pydantic import BaseModel, Field

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent
LSTM_MODELS_STORE_DIR = BACKEND_DIR / "models_store" / "lstm"
LSTM_DATA_DIR = BACKEND_DIR / "data" / "lstm"

# Ensure directories exist
LSTM_MODELS_STORE_DIR.mkdir(parents=True, exist_ok=True)
LSTM_DATA_DIR.mkdir(parents=True, exist_ok=True)

# 15 compatible sequential features matching Phase 3 behavioral concepts
LSTM_FEATURE_NAMES: List[str] = [
    "request_size_bytes",          # Request payload magnitude
    "response_size_bytes",         # Response payload magnitude
    "total_bytes",                 # Aggregate payload bytes
    "is_write",                    # 1.0 if POST/PUT/PATCH/DELETE else 0.0
    "is_read",                     # 1.0 if GET/HEAD/OPTIONS else 0.0
    "is_failed",                   # 1.0 if status >= 400 else 0.0
    "is_unusual_method",           # 1.0 if PATCH/DELETE/OPTIONS/HEAD else 0.0
    "time_of_day_deviation",       # [0.0, 1.0] distance from 08:00-19:00 UTC
    "time_delta_seconds",          # Elapsed seconds since previous sequence event
    "is_vendor_access",            # 1.0 if accessing vendor record else 0.0
    "is_new_endpoint",             # 1.0 if endpoint not in service baseline
    "source_ip_novelty",           # 1.0 if source IP outside sanctioned list
    "is_sensitive_resource",       # 1.0 if bank/export/admin resource
    "is_permission_violation",     # 1.0 if method not in allowed methods
    "endpoint_ordinal"             # Normalized endpoint categorical index
]


class LSTMSettings(BaseModel):
    """Configurable hyperparameters for LSTM Autoencoder."""
    FEATURE_SCHEMA_VERSION: str = "1.0.0"

    # Sequence dimensions
    SEQUENCE_LENGTH: int = Field(default=20, ge=5, le=100, description="Number of consecutive events in a sequence.")
    FEATURE_COUNT: int = Field(default=15, description="Number of features per event timestep.")

    # Model architecture
    HIDDEN_DIM: int = Field(default=32, ge=8, le=128, description="LSTM hidden layer dimension.")
    LATENT_DIM: int = Field(default=16, ge=4, le=64, description="Bottleneck compressed latent representation.")
    NUM_LAYERS: int = Field(default=1, description="Number of stacked LSTM layers in encoder and decoder.")

    # Training parameters
    LEARNING_RATE: float = Field(default=0.005, description="Adam optimizer learning rate.")
    EPOCHS: int = Field(default=25, ge=5, le=100, description="Training epochs.")
    BATCH_SIZE: int = Field(default=16, ge=1, le=128, description="Batch size for gradient descent.")
    MIN_SEQUENCES_FOR_BASELINE: int = Field(default=15, description="Minimum training sequences to establish baseline.")
    RANDOM_STATE: int = Field(default=42, description="Random seed for reproducible training.")

    # Anomaly scoring and thresholds
    ANOMALY_THRESHOLD: float = Field(
        default=0.65,
        description="Calibrated sigmoid threshold above which a sequence is classified as anomalous."
    )
    PERCENTILE_THRESHOLD: float = Field(
        default=95.0,
        description="Percentile of normal reconstruction error used as base threshold."
    )

    # Operational
    DEVICE: str = Field(default="cpu", description="Execution device (CPU only for Windows 11 compliance).")


lstm_settings = LSTMSettings()
