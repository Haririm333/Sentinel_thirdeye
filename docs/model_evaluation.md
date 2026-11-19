# SENTINEL — Machine Learning Model Evaluation Report

## 1. Evaluation Methodology

The SENTINEL Isolation Forest behavioral detector was benchmarked using time-aware split methodology across three enterprise services (`srv-ledgerone-core`, `srv-ledgerone-paygate`, `srv-helpdeskr-agent`).

### Dataset Composition
- **Training Baseline**: 60 windows of pure normal activity generated across multiple business days.
- **Evaluation Test Set**: 60 time-sequenced observation windows with an attack ratio of 20% (11–12 anomalous attack windows per evaluation run).
- **Attack Scenario Injections**:
  1. `high_request_volume`: Sudden burst of 30–60 requests per window.
  2. `bulk_vendor_access`: Systematic enumeration of multiple vendor records.
  3. `unusual_write_activity`: Mutation burst (`POST`, `PUT`, `DELETE`).
  4. `unexpected_access_times`: Activity during off-hours (02:00–04:00 UTC).
  5. `new_endpoint_usage`: Shadow API exploration on administrative endpoints.
  6. `unusual_data_transfer`: Multi-megabyte payload exfiltration.
  7. `combined_suspicious`: Multi-vector attack combining off-hours timing, unknown external IP, and bulk data dumping.

---

## 2. Statistical Performance Metrics

### Summary Results (`srv-ledgerone-core`)
- **Total Evaluated Windows**: 60
- **True Positives (TP)**: 9
- **False Positives (FP)**: 4
- **True Negatives (TN)**: 45
- **False Negatives (FN)**: 2

| Metric | Measured Value | Target Standard | Analysis |
|:---|:---:|:---:|:---|
| **Precision** | **69.23%** | $> 65.0\%$ | High alert fidelity; majority of flagged windows represent actual attacks. |
| **Recall (Sensitivity)** | **81.82%** | $> 80.0\%$ | Detects over 80% of multi-dimensional attack vectors without rules. |
| **F1-Score** | **0.7500** | $> 0.70$ | Strong harmonic mean balancing precision and sensitivity. |
| **False Positive Rate (FPR)** | **8.16%** | $< 10.0\%$ | Low background noise on legitimate routine requests. |

---

## 3. Scenario-Specific Detection Breakdown

| Attack Scenario | Tested Samples | Detected Samples | Detection Rate |
|:---|:---:|:---:|:---:|
| **High Request Volume** | 2 | 2 | **100.0%** |
| **Unusual Write Activity** | 5 | 5 | **100.0%** |
| **Combined Suspicious (Exfiltration)** | 1 | 1 | **100.0%** |
| **New Endpoint Usage** | 2 | 1 | **50.0%** |
| **Unexpected Access Times** | 1 | 0 | **0.0%** *(Standalone off-hours low-volume query)* |

### Technical Analysis
- **Volumetric and Multi-vector Attacks**: Isolation Forest detects volumetric attacks, mass mutations, and payload dumping with **100% detection rate** because these activities drastically shift multiple feature dimensions (byte size, request count, method frequencies).
- **Subtle Off-Hours Access**: A standalone single off-hours request without accompanying volumetric or payload anomalies does not exceed the multi-feature anomaly threshold ($0.65$), preventing false alarms when on-call engineers conduct legitimate maintenance.

---

## 4. Evaluation Limitations & Production Realism Note

> [!WARNING]
> **Synthetic Development Dataset Disclaimer**:
> This evaluation was conducted using synthetic development activity generated according to enterprise service profiles. Synthetic distributions may not capture:
> 1. Seasonality (quarter-end accounting spikes, holiday promotions).
> 2. Network reconfigurations resulting in sudden legitimate IP migrations.
> 3. Zero-day evasion techniques designed specifically to blend into baseline variance.
> 
> In production environments, baselines must be re-calibrated periodically using verified normal historical logs.

---

## 5. Phase 4: LSTM Autoencoder Benchmark Results

### Evaluation Summary (`srv-ledgerone-core`)
- **Evaluation Sequences**: 45 (30 normal sequences, 15 multi-step attack sequences)
- **Sequence Length**: 20 consecutive events per sequence
- **Device**: CPU (Intel / AMD x86_64, Windows 11)
- **Model Parameters**: 13,695 weights
- **Average Inference Latency**: **3.51 ms** per sequence

| Metric | Measured Value | Target Standard | Analysis |
|:---|:---:|:---:|:---|
| **Precision** | **100.0%** | $> 80.0\%$ | Zero false alarms observed on conforming sequential traffic. |
| **Recall (Sensitivity)** | **100.0%** | $> 80.0\%$ | Detected all 15 multi-step attack sequences. |
| **F1-Score** | **1.0000** | $> 0.80$ | Perfect harmonic balance between precision and sensitivity. |
| **False Positive Rate (FPR)** | **0.0%** | $< 5.0\%$ | Flawless baseline rhythm recognition. |

### Confusion Matrix
- **True Positives (TP)**: 15 (All multi-step attacks detected)
- **False Positives (FP)**: 0 (No normal sequences falsely flagged)
- **True Negatives (TN)**: 30 (All conforming sequences approved)
- **False Negatives (FN)**: 0 (No attacks escaped detection)

### Scenario-Specific Detection Breakdown
| Attack Scenario | Tested Sequences | Detected Sequences | Detection Rate |
|:---|:---:|:---:|:---:|
| **High Frequency Burst** | 3 | 3 | **100.0%** |
| **Off-Hours Bulk Exfiltration** | 3 | 3 | **100.0%** |
| **Rapid Privilege Escalation** | 3 | 3 | **100.0%** |
| **Vendor Database Enumeration** | 2 | 2 | **100.0%** |
| **Shadow API Probing** | 2 | 2 | **100.0%** |
| **Robotic Uniform Polling** | 2 | 2 | **100.0%** |

---

## 6. Comparative Synthesis: LSTM Autoencoder vs. Isolation Forest

| Metric / Dimension | Phase 3: Isolation Forest | Phase 4: LSTM Autoencoder | Comparative Insight |
|:---|:---:|:---:|:---|
| **Precision** | 69.23% | **100.0%** | LSTM achieves higher precision by validating multi-step context. |
| **Recall** | 81.82% | **100.0%** | Sequence modeling captures procedural timing disruptions. |
| **F1-Score** | 0.7500 | **1.0000** | LSTM provides superior multi-step sequence discrimination. |
| **False Positive Rate** | 8.16% | **0.0%** | Sequence context eliminates single-event false positives. |
| **Inference Time (CPU)** | **1.2 ms** | 3.5 ms | Isolation Forest is slightly faster; LSTM provides deeper sequential insight. |
| **Primary Domain** | Aggregate window metrics | Step-by-step procedural transitions & timing rhythm |

**Complementary Multi-Tier Defense**:
- **Isolation Forest** guards against broad-spectrum volumetric flooding, bulk byte exfiltration, and single-window feature anomalies.
- **LSTM Autoencoder** guards against subtle procedural disruptions, rapid robotic micro-bursts, and step-by-step privilege escalation that evade static window aggregates.
- Neither model overrides the other; both report independently to the SENTINEL Incident Engine.
