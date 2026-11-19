"""
SENTINEL Machine Learning Subsystem Configuration
Central configuration for Isolation Forest hyperparameters, feature definitions,
and model persistence paths.
"""

from pathlib import Path
from typing import List
from pydantic import BaseModel, Field

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
MODELS_STORE_DIR = BACKEND_DIR / "models_store"
DATA_DIR = BACKEND_DIR / "data"

# Standard feature set specification (15 features)
FEATURE_NAMES: List[str] = [
    "requests_count",
    "avg_request_size",
    "avg_response_size",
    "total_bytes_transferred",
    "unique_endpoints_count",
    "unique_vendors_count",
    "read_to_write_ratio",
    "failed_request_ratio",
    "unusual_method_frequency",
    "time_of_day_deviation",
    "inter_request_time_variance",
    "new_endpoint_ratio",
    "source_ip_novelty",
    "sensitive_resource_frequency",
    "permission_deviation_count"
]


class MLSettings(BaseModel):
    """Configuration parameters for Isolation Forest and feature processing."""
    FEATURE_SCHEMA_VERSION: str = "1.0.0"
    
    # Model hyperparameters
    N_ESTIMATORS: int = Field(default=100, description="Number of isolation trees.")
    CONTAMINATION: float = Field(default=0.05, description="Expected baseline anomaly proportion.")
    RANDOM_STATE: int = Field(default=42, description="Seed for deterministic reproducibility.")
    
    # Observation windowing
    WINDOW_SECONDS: int = Field(default=300, description="Aggregation window for feature extraction (5 minutes).")
    MIN_EVENTS_PER_WINDOW: int = Field(default=3, description="Minimum events in observation window before evaluating behavioural anomaly.")
    MIN_SAMPLES_FOR_BASELINE: int = Field(default=20, description="Minimum samples to establish service baseline.")
    
    # Anomaly classification threshold
    ANOMALY_THRESHOLD: float = Field(
        default=0.65,
        description="Calibrated anomaly score threshold in [0, 1] above which an event is flagged."
    )
    
    # Temporal baselines (UTC)
    BUSINESS_HOURS_START: int = 8   # 08:00 UTC
    BUSINESS_HOURS_END: int = 19    # 19:00 UTC
    
    # Operational switches
    ENABLE_GLOBAL_FALLBACK: bool = False  # Strict baseline: do not guess if data is insufficient


ml_settings = MLSettings()
