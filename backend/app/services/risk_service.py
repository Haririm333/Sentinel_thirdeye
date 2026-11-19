"""
Risk Scoring Service for SENTINEL
Calculates transparent, deterministic, and explainable risk scores (0–100).
Enforces severity thresholds and prevents arbitrary score inflation.
"""

from typing import List, Dict, Any, Tuple


SEVERITY_BANDS = [
    (80, 100, "CRITICAL"),
    (60, 79, "HIGH"),
    (30, 59, "MEDIUM"),
    (0, 29, "LOW"),
]


def score_to_severity(score: int) -> str:
    """Map a 0-100 score into standard severity bands."""
    clamped = max(0, min(100, score))
    for low, high, severity in SEVERITY_BANDS:
        if low <= clamped <= high:
            return severity
    return "LOW"


def evaluate_risk(
    base_score: int,
    modifiers: List[Dict[str, Any]] = None
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Compute explainable risk score from base score and contextual modifiers.
    
    Args:
        base_score: Initial baseline score established by the detection rule.
        modifiers: List of modifier dicts with 'factor', 'points', and 'reason'.
        
    Returns:
        (final_score, severity_str, explanation_dict)
    """
    if modifiers is None:
        modifiers = []

    current_score = base_score
    applied_modifiers = []

    for mod in modifiers:
        factor = mod.get("factor", "unspecified")
        points = mod.get("points", 0)
        reason = mod.get("reason", "")
        
        current_score += points
        applied_modifiers.append({
            "factor": factor,
            "points": points,
            "reason": reason
        })

    # Strict clamping between 0 and 100
    final_score = max(0, min(100, current_score))
    severity = score_to_severity(final_score)

    breakdown = {
        "base_score": base_score,
        "modifiers": applied_modifiers,
        "final_score": final_score,
        "severity": severity
    }

    return final_score, severity, breakdown
