"""
Tests for Transparent Risk Scoring and Explainability
"""

from sentinel.backend.app.services.risk_service import evaluate_risk, score_to_severity


def test_severity_bands_mapping():
    """Verify standard severity bands mapping."""
    assert score_to_severity(10) == "LOW"
    assert score_to_severity(29) == "LOW"
    assert score_to_severity(30) == "MEDIUM"
    assert score_to_severity(59) == "MEDIUM"
    assert score_to_severity(60) == "HIGH"
    assert score_to_severity(79) == "HIGH"
    assert score_to_severity(80) == "CRITICAL"
    assert score_to_severity(100) == "CRITICAL"


def test_score_clamping():
    """Ensure risk scores are strictly clamped between 0 and 100."""
    score_low, _, _ = evaluate_risk(10, [{"factor": "deduction", "points": -50, "reason": "negative"}])
    assert score_low == 0

    score_high, _, _ = evaluate_risk(90, [{"factor": "surge", "points": +40, "reason": "overflow"}])
    assert score_high == 100


def test_explainable_breakdown():
    """Verify that risk evaluation produces a transparent modifier audit trail."""
    modifiers = [
        {"factor": "unverified_ip", "points": 15, "reason": "External IP"},
        {"factor": "missing_approval", "points": 10, "reason": "No ticket provided"}
    ]
    final_score, severity, breakdown = evaluate_risk(base_score=60, modifiers=modifiers)
    assert final_score == 85
    assert severity == "CRITICAL"
    assert breakdown["base_score"] == 60
    assert len(breakdown["modifiers"]) == 2
    assert breakdown["final_score"] == 85
    assert breakdown["severity"] == "CRITICAL"
