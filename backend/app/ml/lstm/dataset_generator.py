"""
Synthetic Sequential Dataset Generator for SENTINEL LSTM Autoencoder
Generates chronological API event sequences for:
- LedgerOne (Core & PayGate)
- HelpDeskr
- TallyBridge

Produces:
1. Normal training sequences.
2. Normal validation sequences.
3. Test sequences containing multi-step attack scenarios.

IMPORTANT: All data produced here is SYNTHETIC DEVELOPMENT DATA.
Attack labels are preserved strictly for evaluation benchmarking and are never
exposed to the unsupervised LSTM Autoencoder training phase.
"""

import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
import numpy as np

from sentinel.backend.app.ml.lstm.config import lstm_settings
from sentinel.backend.app.ml.lstm.sequence_pipeline import build_sequences_from_events
from sentinel.backend.app.ml.dataset_generator import (
    VENDORS, PAYMENTS, CORPORATE_IPS, EXTERNAL_ANOMALOUS_IPS, _generate_normal_event
)


def generate_normal_event_stream(
    service_identity: str,
    num_events: int = 150,
    random_seed: int = 42
) -> List[Dict[str, Any]]:
    """
    Generate a continuous chronological sequence of normal, routine API events
    spaced realistically across business hours.
    """
    rng = random.Random(random_seed)
    base_time = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
    current_time = base_time

    events = []
    for _ in range(num_events):
        # Advance time by realistic inter-request interval (5 to 45 seconds)
        interval = rng.uniform(5.0, 45.0)
        current_time += timedelta(seconds=interval)

        # Wrap to next business day if past 18:00 UTC
        if current_time.hour >= 18:
            base_time += timedelta(days=1)
            current_time = base_time.replace(hour=9, minute=rng.randint(0, 30))

        ev = _generate_normal_event(service_identity, current_time, rng)
        events.append(ev)

    return events


def generate_anomalous_event_sequence(
    service_identity: str,
    scenario: str,
    start_time: datetime,
    seq_len: int = 20,
    random_seed: int = 42
) -> List[Dict[str, Any]]:
    """
    Generate a 20-event chronological sequence embodying a specific multi-step attack pattern.
    """
    rng = random.Random(random_seed)
    events = []
    current_time = start_time

    if scenario == "high_frequency_burst":
        # Rapid-fire robotic bursts: 0.05 - 0.20 second intervals
        for i in range(seq_len):
            current_time += timedelta(seconds=rng.uniform(0.05, 0.20))
            ev = _generate_normal_event(service_identity, current_time, rng)
            ev["request_size_bytes"] = rng.randint(800, 1500)
            events.append(ev)

    elif scenario == "off_hours_bulk_exfiltration":
        # Deep night (03:00 UTC), massive payloads, external untrusted IP
        off_hours_time = start_time.replace(hour=3, minute=rng.randint(10, 45))
        anom_ip = rng.choice(EXTERNAL_ANOMALOUS_IPS)
        for i in range(seq_len):
            off_hours_time += timedelta(seconds=rng.uniform(2.0, 10.0))
            ev = _generate_normal_event(service_identity, off_hours_time, rng)
            ev["source_ip"] = anom_ip
            ev["endpoint"] = "/api/v1/vendors/export/dump"
            ev["action"] = "EXPORT_DATABASE_BATCH"
            ev["response_size_bytes"] = rng.randint(15_000_000, 35_000_000)
            events.append(ev)

    elif scenario == "rapid_privilege_escalation":
        # Sequence of unauthorized write mutations on restricted config
        for i in range(seq_len):
            current_time += timedelta(seconds=rng.uniform(1.0, 8.0))
            ev = _generate_normal_event(service_identity, current_time, rng)
            ev["http_method"] = rng.choice(["POST", "PUT", "DELETE"])
            ev["endpoint"] = "/api/v1/internal/admin/privileges"
            ev["action"] = "ESCALATE_ROLE_PERMISSIONS"
            ev["http_status_code"] = rng.choice([200, 403])
            events.append(ev)

    elif scenario == "vendor_database_enumeration":
        # Systematic stepping through every vendor record sequentially
        for i in range(seq_len):
            current_time += timedelta(seconds=rng.uniform(0.5, 3.0))
            vendor_id = f"vnd_{10000 + i * 7:05d}"
            ev = _generate_normal_event(service_identity, current_time, rng)
            ev["endpoint"] = f"/api/v1/vendors/{vendor_id}/confidential"
            ev["resource_id"] = vendor_id
            ev["action"] = "HARVEST_VENDOR_DETAILS"
            events.append(ev)

    elif scenario == "shadow_api_probing":
        # Probing unadvertised endpoints with 404/403/500 errors
        endpoints = [
            "/api/v1/system/debug/heap",
            "/api/v1/internal/actuator/env",
            "/api/v1/config/credentials",
            "/api/v1/admin/sudo",
            "/api/v1/system/backup/keys"
        ]
        for i in range(seq_len):
            current_time += timedelta(seconds=rng.uniform(1.0, 5.0))
            ev = _generate_normal_event(service_identity, current_time, rng)
            ev["endpoint"] = rng.choice(endpoints)
            ev["http_status_code"] = rng.choice([403, 404, 500])
            events.append(ev)

    else:  # robotic_uniform_polling
        # Perfect, robotic, zero-jitter cadence (exactly 0.100s apart)
        for i in range(seq_len):
            current_time += timedelta(seconds=0.100)
            ev = _generate_normal_event(service_identity, current_time, rng)
            ev["request_size_bytes"] = 250
            ev["response_size_bytes"] = 1200
            events.append(ev)

    return events


def generate_lstm_training_dataset(
    service_identity: str,
    num_events: int = 200,
    seq_len: int = 20,
    stride: int = 2,
    random_seed: int = 42
) -> np.ndarray:
    """
    Generate normal training sequences array of shape (N, seq_len, 15) for an LSTM Autoencoder.
    """
    events = generate_normal_event_stream(
        service_identity=service_identity,
        num_events=num_events,
        random_seed=random_seed
    )
    sequences = build_sequences_from_events(
        events=events,
        service_identity=service_identity,
        seq_len=seq_len,
        stride=stride
    )
    return sequences


def generate_lstm_evaluation_dataset(
    service_identity: str,
    num_normal_sequences: int = 30,
    num_anomalous_sequences: int = 15,
    seq_len: int = 20,
    random_seed: int = 99
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Generate evaluation dataset combining normal and attack sequences.
    
    Returns:
        (sequences_array, ground_truth_labels, scenario_names)
        where labels: 0 = normal, 1 = anomaly.
    """
    rng = random.Random(random_seed)
    
    # 1. Normal sequences
    normal_events = generate_normal_event_stream(
        service_identity=service_identity,
        num_events=num_normal_sequences * 4 + seq_len,
        random_seed=random_seed
    )
    normal_seqs = build_sequences_from_events(
        events=normal_events,
        service_identity=service_identity,
        seq_len=seq_len,
        stride=3
    )[:num_normal_sequences]

    # 2. Anomalous sequences
    attack_scenarios = [
        "high_frequency_burst",
        "off_hours_bulk_exfiltration",
        "rapid_privilege_escalation",
        "vendor_database_enumeration",
        "shadow_api_probing",
        "robotic_uniform_polling"
    ]

    anom_seqs_list = []
    scenarios_list = ["normal"] * len(normal_seqs)

    base_time = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(num_anomalous_sequences):
        scenario = attack_scenarios[i % len(attack_scenarios)]
        start_t = base_time + timedelta(hours=i * 2)
        attack_events = generate_anomalous_event_sequence(
            service_identity=service_identity,
            scenario=scenario,
            start_time=start_t,
            seq_len=seq_len,
            random_seed=random_seed + i * 17
        )
        seq = build_sequences_from_events(
            events=attack_events,
            service_identity=service_identity,
            seq_len=seq_len,
            stride=seq_len
        )
        if len(seq) > 0:
            anom_seqs_list.append(seq[0])
            scenarios_list.append(scenario)

    if anom_seqs_list:
        anom_seqs_array = np.array(anom_seqs_list, dtype=np.float32)
        all_sequences = np.concatenate([normal_seqs, anom_seqs_array], axis=0)
    else:
        all_sequences = normal_seqs

    labels = np.array([0] * len(normal_seqs) + [1] * len(anom_seqs_list), dtype=np.int32)
    return all_sequences, labels, scenarios_list
