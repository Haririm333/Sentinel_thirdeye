# SENTINEL Risk Scoring Model & Explainability Framework

## 1. Scoring Principles
1. **Bounded Integer Scale**: All risk scores evaluate to an integer between `0` and `100`.
2. **Transparent Explainability**: Every score is accompanied by a structured `scoring_breakdown` recording the baseline score, applied modifiers, and specific justifications.
3. **Non-Inflating Deduplication**: Correlating repeated events into an open incident does *not* blindly sum scores; the score only upgrades if a subsequent correlated event exhibits higher risk indicators.

---

## 2. Severity Bands

| Score Range | Severity Band | Operational Response Expectation |
| :---: | :---: | :--- |
| **80 – 100** | **CRITICAL** | Immediate SOC notification; potential automated session revocation. Sensitive bank alterations and unapproved mutations. |
| **60 – 79** | **HIGH** | High-priority investigation within 1 hour; unexpected external IPs and privilege violations. |
| **30 – 59** | **MEDIUM** | Standard investigation within 4 hours; high rate warnings and bulk data extraction patterns. |
| **0 – 29** | **LOW** | Informational; logged for longitudinal behavioral baseline analysis. |

---

## 3. Base Scores & Modifier Rules

| Rule ID | Rule Name | Base Score | Modifiers | Max Score |
| :--- | :--- | :---: | :--- | :---: |
| `SEC-RULE-RATE-001` | Excessive Request Rate | **45** (MEDIUM) | `rate > 1.5x`: +15<br>`rate > 3.0x`: +30 | **75** (HIGH) |
| `SEC-RULE-BULK-001` | Bulk Vendor Access | **50** (MEDIUM) | `volume > 2x limit`: +25<br>`repeated & single bulk`: +15 | **75** (HIGH) |
| `SEC-RULE-IP-001` | Unexpected Source IP | **65** (HIGH) | `unregistered service`: +15<br>`public internet IP`: +20 | **85** (CRITICAL) |
| `SEC-RULE-PRIV-001` | Privilege & Scope Violation | **75** (HIGH) | `write on read-only`: +15<br>`bank change without permission`: +20 | **95** (CRITICAL) |
| `SEC-RULE-BANK-001` | Sensitive Bank Modification | **80** (CRITICAL) | `missing/invalid approval`: +15 | **95** (CRITICAL) |
| `SEC-RULE-APPR-001` | Missing Approval Reference | **60** (HIGH) | `financial action`: +20<br>`fake override string`: +15 | **95** (CRITICAL) |

---

## 4. Structured Breakdown Example

Every incident's evidence dictionary contains the explicit scoring path:

```json
{
  "scoring_breakdown": {
    "base_score": 60,
    "modifiers": [
      {
        "factor": "financial_operation_without_approval",
        "points": 20,
        "reason": "Financial modification lacking governance authorization"
      },
      {
        "factor": "unverified_emergency_override",
        "points": 15,
        "reason": "Self-asserted emergency override string used in place of ticket"
      }
    ],
    "final_score": 95,
    "severity": "CRITICAL"
  }
}
```
