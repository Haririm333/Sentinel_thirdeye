# SENTINEL — Behavioral Feature Dictionary (15 Features)

## 1. Overview and Privacy Guarantees

The SENTINEL Feature Engineering pipeline extracts 15 numerical features from sliding time windows (default: 300 seconds / 5 minutes) grouped by `service_identity`.

### Zero-PII Guarantee
To maintain strict compliance with enterprise privacy standards:
- **No Event IDs**: UUIDs are never fed into the model.
- **No Raw Secrets / Credentials**: Bearer tokens, passwords, and API keys are redacted before ingestion.
- **No Plaintext Bank Accounts**: Redacted via Luhn/IBAN masking algorithms.
- **No Personally Identifiable Information**: Usernames and personal identities are completely excluded from the feature vector.

---

## 2. Feature Specification Matrix

| Index | Feature Identifier | Type | Description | Source Fields | Normal Range (Business Hours) | Anomalous Trigger Indicator |
|:---:|:---|:---:|:---|:---|:---|:---|
| 1 | `requests_count` | `float` | Number of requests submitted by the service in the window. | Event count | 4 – 15 | $> 30$ (Burst/DDoS) |
| 2 | `avg_request_size` | `float` | Mean request payload size in bytes. | `request_size_bytes` | 100 – 400 B | $> 2,000$ B (Large uploads) |
| 3 | `avg_response_size` | `float` | Mean response payload size in bytes. | `response_size_bytes` | 1,000 – 5,000 B | $> 1,000,000$ B (Data exfiltration) |
| 4 | `total_bytes_transferred` | `float` | Total byte volume (request + response) transferred in window. | Request + Response bytes | 10,000 – 50,000 B | $> 10,000,000$ B (Bulk dumping) |
| 5 | `unique_endpoints_count` | `float` | Cardinality of distinct API endpoints called. | `endpoint` | 1 – 6 | $> 12$ (Endpoint enumeration) |
| 6 | `unique_vendors_count` | `float` | Cardinality of unique vendor records accessed. | `resource_id`, URL path | 1 – 6 | $> 20$ (Vendor database scrape) |
| 7 | `read_to_write_ratio` | `float` | Ratio of read operations (`GET`, `HEAD`) to mutations (`POST`, `PUT`, `DELETE`). | `http_method` | 4.0 – 15.0 | $< 0.5$ (Mass mutation/deletion) |
| 8 | `failed_request_ratio` | `float` | Proportion of requests returning HTTP status $\ge 400$. | `http_status_code` | 0.0 – 0.05 | $> 0.30$ (Brute-force / probe) |
| 9 | `unusual_method_frequency` | `float` | Proportion of requests using non-standard methods (`PATCH`, `DELETE`, `OPTIONS`). | `http_method` | 0.0 – 0.05 | $> 0.25$ (Unapproved methods) |
| 10 | `time_of_day_deviation` | `float` | Distance from core business hours (08:00–19:00 UTC). Normalized $[0.0, 1.0]$. | `timestamp` | 0.00 – 0.10 | $> 0.70$ (Deep night / weekend access) |
| 11 | `inter_request_time_variance` | `float` | Variance of time intervals between consecutive requests in seconds. | `timestamp` differences | 5.0 – 80.0 | $\approx 0.0$ (Automated robotic script) |
| 12 | `new_endpoint_ratio` | `float` | Proportion of requests hitting endpoints absent from the historical service baseline. | `endpoint`, Baseline set | 0.00 | $> 0.30$ (Shadow API exploration) |
| 13 | `source_ip_novelty` | `float` | Proportion of requests originating from IP addresses outside the sanctioned list. | `source_ip`, Baseline set | 0.00 | $1.00$ (External untrusted origin) |
| 14 | `sensitive_resource_frequency` | `float` | Proportion of requests accessing banking, export, or administrative resources. | `resource_type`, `endpoint` | 0.00 – 0.05 | $> 0.40$ (Targeted sensitive theft) |
| 15 | `permission_deviation_count` | `float` | Count of requests violating service's configured role/method policy. | `http_method`, Service policy | 0.0 | $> 2.0$ (Scope escalation) |

---

## 3. Mathematical Calculations

### 3.1 Read-to-Write Ratio
Guards against zero-division using Laplace smoothing:
$$\text{read\_to\_write\_ratio} = \frac{\text{read\_count}}{\text{write\_count} + 1.0}$$

### 3.2 Time-of-Day Deviation
Maps UTC timestamps to a continuous $[0.0, 1.0]$ deviation metric:
$$h = \text{hour} + \frac{\text{minute}}{60.0}$$
$$\text{deviation} = \begin{cases} 
0.0 & \text{if } 8 \le h \le 19 \\
\min\left(1.0, \frac{\min(|h - 8|, |h - 19|)}{6.0}\right) & \text{otherwise}
\end{cases}$$

### 3.3 Inter-Request Variance
Measures cadence uniformity:
$$\sigma^2_t = \frac{1}{N - 1} \sum_{i=1}^{N-1} (\Delta t_i - \overline{\Delta t})^2$$
Where $\Delta t_i = t_{i+1} - t_i$. Near-zero variance indicates automated script or bot activity.

---

## 4. Phase 4: Sequential Feature Specification for LSTM Autoencoder

The LSTM Autoencoder operates on chronological sequence matrices of shape $(20, 15)$ representing 20 consecutive events for a single service identity. The features per event step are:

| Index | Feature Name | Description | Source Field |
|:---:|:---|:---|:---|
| 1 | `request_size_bytes` | Payload size of the request in bytes. | `request_size_bytes` |
| 2 | `response_size_bytes` | Payload size of the response in bytes. | `response_size_bytes` |
| 3 | `total_bytes` | Sum of request and response bytes. | Computed |
| 4 | `is_write` | Binary indicator (1.0 for `POST`, `PUT`, `PATCH`, `DELETE`). | `http_method` |
| 5 | `is_read` | Binary indicator (1.0 for `GET`, `HEAD`, `OPTIONS`). | `http_method` |
| 6 | `is_failed` | Binary indicator (1.0 if HTTP status code $\ge 400$). | `http_status_code` |
| 7 | `is_unusual_method` | Binary indicator (1.0 for `PATCH`, `DELETE`, `OPTIONS`, `HEAD`).| `http_method` |
| 8 | `time_of_day_deviation` | Distance from business hours (08:00–19:00 UTC) $[0.0, 1.0]$. | `timestamp` |
| 9 | `time_delta_seconds` | Elapsed seconds since previous sequence event ($\Delta t$). | $\text{timestamp}_t - \text{timestamp}_{t-1}$ |
| 10 | `is_vendor_access` | Binary indicator (1.0 if accessing vendor profile or record). | `resource_type`, `endpoint` |
| 11 | `is_new_endpoint` | Binary indicator (1.0 if endpoint is absent from baseline). | `endpoint` |
| 12 | `source_ip_novelty` | Binary indicator (1.0 if source IP is outside sanctioned list). | `source_ip` |
| 13 | `is_sensitive_resource`| Binary indicator (1.0 for banking, database dump, or config). | `resource_type`, `action` |
| 14 | `is_permission_violation`| Binary indicator (1.0 if method violates service policy). | Policy check |
| 15 | `endpoint_ordinal` | Normalized endpoint categorical ordinal $[0.0, 1.0]$. | `endpoint` hash bucket |

### Sequential Consistency
- Chronological sorting is strictly enforced on each sequence before feature extraction.
- $\Delta t$ looks strictly backward ($t - (t-1)$), preventing future data leakage.
- Service identities are never mixed within a sequence.
