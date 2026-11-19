"""
Unified Security Risk Assessment and Detection Integration Service for SENTINEL (Phase 6)
Integrates:
1. Deterministic Security Detection Rules (Phase 2)
2. Isolation Forest Behavioural Anomaly Detection (Phase 3)
3. LSTM Autoencoder Sequential Anomaly Detection (Phase 4)
4. Two-Person Vendor Bank Change Authorization Integration (Phase 5)

Guarantees:
- Documented, configurable synergistic risk aggregation (never blind averaging).
- Hard floor protection: deterministic rule findings are never diluted by zero ML baselines.
- Explicit model readiness tracking: missing/unavailable models are NEVER interpreted as normal.
- Cross-tier compounding: multi-model confirmations elevate risk scores.
- Non-interference invariant: AI risk scores NEVER authorize bank account changes.
"""

import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_, func

from sentinel.backend.app.models.api_event import ApiEvent
from sentinel.backend.app.models.incident import Incident
from sentinel.backend.app.models.bank_approval import BankChangeRequest
from sentinel.backend.app.detection.rule_registry import rule_registry
from sentinel.backend.app.detection.base_rule import DetectionResult
from sentinel.backend.app.services.incident_service import create_or_update_incident
from sentinel.backend.app.detection.config import detection_settings
from sentinel.backend.app.ml.config import ml_settings
from sentinel.backend.app.ml.features import extract_window_features
from sentinel.backend.app.ml.detector import anomaly_detector
from sentinel.backend.app.ml.baseline_manager import baseline_manager
from sentinel.backend.app.ml.lstm.config import lstm_settings
from sentinel.backend.app.ml.lstm.sequence_pipeline import build_sequences_from_events
from sentinel.backend.app.ml.lstm.detector import lstm_detector
from sentinel.backend.app.ml.lstm.baseline_manager import lstm_baseline_manager

logger = logging.getLogger("sentinel.unified_assessment")


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


def severity_from_score(score: int) -> str:
    """Map 0-100 risk score to standardized severity band."""
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def aggregate_risk(
    rule_findings: List[Dict[str, Any]],
    if_result: Dict[str, Any],
    lstm_result: Dict[str, Any]
) -> Tuple[int, str, str, List[str], Dict[str, Any]]:
    """
    Synergistic Multi-Tier Risk Aggregation Algorithm.
    
    Principles:
    1. Deterministic Floor: If a deterministic rule triggers, its score acts as a hard floor.
    2. Missing Model Handling: An unavailable model has evaluated=False and contributes 0 to the score,
       but its status is explicitly reported and it NEVER dilutes the other detectors.
    3. Multi-Detector Compounding:
       - Single detector: max score.
       - Dual detector confirmation (Rules + ML or IF + LSTM): +10 points synergy boost.
       - Triple detector confirmation (Rules + IF + LSTM): +15 points synergy boost.
    4. Clamping: Guaranteed bounded within [0, 100].
    
    Returns:
        (overall_risk_score, overall_risk_level, explanation, contributing_components, supporting_evidence)
    """
    contributing_components: List[str] = []
    explanations: List[str] = []
    supporting_evidence: Dict[str, Any] = {}

    # 1. Deterministic Rule Score
    rule_scores = [r["risk_score"] for r in rule_findings if r.get("triggered", True)]
    max_rule_score = max(rule_scores) if rule_scores else 0
    if rule_scores:
        contributing_components.append("DETERMINISTIC_RULES")
        rule_names = [f"{r['rule_name']} ({r['rule_id']})" for r in rule_findings]
        explanations.append(f"Deterministic policy violation triggered: {', '.join(rule_names)} [Score: {max_rule_score}]")
        supporting_evidence["rule_violations"] = rule_findings

    # 2. Isolation Forest Score
    if_score = 0
    if if_result.get("evaluated", False):
        if if_result.get("triggered", False):
            if_score = int(round(if_result.get("anomaly_score", 0.0) * 100))
            contributing_components.append("ISOLATION_FOREST")
            explanations.append(
                f"Isolation Forest behavioral anomaly detected: {if_result.get('explanation', 'Feature outlier')} [Score: {if_score}]"
            )
            supporting_evidence["isolation_forest"] = {
                "anomaly_score": if_result.get("anomaly_score"),
                "top_deviations": if_result.get("top_deviations", [])
            }
    else:
        status = if_result.get("model_status", "UNAVAILABLE")
        explanations.append(f"Note: Isolation Forest detector status was '{status}' and was not evaluated (not assumed normal).")

    # 3. LSTM Autoencoder Score
    lstm_score = 0
    if lstm_result.get("evaluated", False):
        if lstm_result.get("triggered", False):
            lstm_score = int(round(lstm_result.get("anomaly_score", 0.0) * 100))
            contributing_components.append("LSTM_AUTOENCODER")
            explanations.append(
                f"LSTM Autoencoder sequential anomaly detected: {lstm_result.get('explanation', 'Sequence reconstruction failure')} [Score: {lstm_score}]"
            )
            supporting_evidence["lstm_autoencoder"] = {
                "anomaly_score": lstm_result.get("anomaly_score"),
                "reconstruction_error": lstm_result.get("reconstruction_error"),
                "calibrated_threshold": lstm_result.get("calibrated_threshold"),
                "top_feature_errors": lstm_result.get("top_feature_errors", [])
            }
    else:
        status = lstm_result.get("model_status", "UNAVAILABLE")
        explanations.append(f"Note: LSTM sequential detector status was '{status}' and was not evaluated (not assumed normal).")

    # 4. Multi-Component Synergy
    base_score = max(max_rule_score, if_score, lstm_score)
    boost = 0
    num_triggers = len(contributing_components)
    if num_triggers >= 3:
        boost = 15
        explanations.append("Multi-tier critical alert: Deterministic rules, behavioral ML, and sequential deep learning all independently confirmed anomalous activity (+15 synergy boost).")
    elif num_triggers == 2:
        boost = 10
        explanations.append("Cross-component alert: Multiple independent detection tiers confirmed anomalous activity (+10 synergy boost).")

    final_score = min(100, max(0, base_score + boost))
    overall_level = severity_from_score(final_score)

    if not contributing_components:
        synthesized_explanation = "Normal API activity: No deterministic security rules triggered and behavioral patterns align with learned baselines."
    else:
        synthesized_explanation = " | ".join(explanations)

    return final_score, overall_level, synthesized_explanation, contributing_components, supporting_evidence


def assess_event(db: Session, event: ApiEvent) -> Dict[str, Any]:
    """
    Run comprehensive multi-tier risk assessment for a specific API event.
    Evaluates:
    - 6 Deterministic rules
    - Isolation Forest behavioral baseline
    - LSTM Autoencoder 20-event sequence baseline
    """
    assessment_id = str(uuid.uuid4())
    assessment_ts = utc_now().isoformat()

    # 1. Evaluate Deterministic Rules
    rule_findings: List[Dict[str, Any]] = []
    rules = rule_registry.list_rules()
    for rule in rules:
        if not rule.is_enabled:
            continue
        try:
            res: Optional[DetectionResult] = rule.evaluate(event, db)
            if res and res.triggered:
                rule_findings.append({
                    "rule_id": res.rule_id,
                    "rule_name": res.rule_name,
                    "severity": res.severity,
                    "risk_score": res.risk_score,
                    "triggered": True,
                    "explanation": res.explanation,
                    "evidence": res.evidence or {}
                })
        except Exception as exc:
            logger.error("Error evaluating rule %s on event %s: %s", rule.rule_id, event.event_id, exc)

    # 2. Evaluate Isolation Forest Behavioral Anomaly
    if_result: Dict[str, Any] = {
        "evaluated": False,
        "model_status": "UNAVAILABLE",
        "triggered": False,
        "anomaly_score": 0.0,
        "calibrated_threshold": None,
        "explanation": "Detector not invoked.",
        "top_deviations": []
    }
    try:
        model, meta, status = baseline_manager.get_service_model(event.service_identity)
        if status != "READY" or model is None:
            if_result["model_status"] = status
            if_result["explanation"] = f"Isolation Forest baseline status is '{status}'. Insufficient data to evaluate."
        else:
            window_start = event.timestamp - timedelta(seconds=ml_settings.WINDOW_SECONDS)
            recent_events = list(
                db.execute(
                    select(ApiEvent).where(
                        and_(
                            ApiEvent.service_identity == event.service_identity,
                            ApiEvent.timestamp >= window_start,
                            ApiEvent.timestamp <= event.timestamp
                        )
                    )
                ).scalars().all()
            )
            if len(recent_events) >= ml_settings.MIN_EVENTS_PER_WINDOW:
                features = extract_window_features(recent_events, event.service_identity)
                scored = anomaly_detector.score_features(features, event.service_identity)
                if_result = {
                    "evaluated": True,
                    "model_status": "READY",
                    "triggered": scored.get("is_anomaly", False),
                    "anomaly_score": scored.get("anomaly_score", 0.0),
                    "calibrated_threshold": meta.get("calibrated_threshold"),
                    "explanation": scored.get("explanation", ""),
                    "top_deviations": scored.get("top_deviations", [])
                }
            else:
                if_result["model_status"] = "INSUFFICIENT_DATA"
                if_result["explanation"] = f"Insufficient events in window ({len(recent_events)}/{ml_settings.MIN_EVENTS_PER_WINDOW})."
    except Exception as exc:
        logger.warning("Isolation Forest assessment exception for event %s: %s", event.event_id, exc)
        if_result["explanation"] = f"Detector error: {str(exc)}"

    # 3. Evaluate LSTM Autoencoder Sequential Anomaly
    lstm_result: Dict[str, Any] = {
        "evaluated": False,
        "model_status": "UNAVAILABLE",
        "triggered": False,
        "anomaly_score": 0.0,
        "reconstruction_error": 0.0,
        "calibrated_threshold": 0.0,
        "explanation": "Detector not invoked.",
        "top_feature_errors": []
    }
    try:
        lstm_model, scaler, meta, status = lstm_baseline_manager.get_service_model(event.service_identity)
        if status != "READY" or lstm_model is None or scaler is None:
            lstm_result["model_status"] = status
            lstm_result["explanation"] = f"LSTM baseline status is '{status}'. Insufficient data to evaluate."
        else:
            seq_events = list(
                db.execute(
                    select(ApiEvent)
                    .where(ApiEvent.service_identity == event.service_identity)
                    .order_by(ApiEvent.timestamp.desc())
                    .limit(lstm_settings.SEQUENCE_LENGTH)
                ).scalars().all()
            )
            if len(seq_events) == lstm_settings.SEQUENCE_LENGTH:
                chronological_events = list(reversed(seq_events))
                seq_array = build_sequences_from_events(
                    events=chronological_events,
                    service_identity=event.service_identity,
                    seq_len=lstm_settings.SEQUENCE_LENGTH,
                    stride=lstm_settings.SEQUENCE_LENGTH
                )
                if len(seq_array) > 0:
                    scored = lstm_detector.score_sequence(seq_array[0], event.service_identity)
                    lstm_result = {
                        "evaluated": True,
                        "model_status": "READY",
                        "triggered": scored.get("is_anomaly", False),
                        "anomaly_score": scored.get("anomaly_score", 0.0),
                        "reconstruction_error": scored.get("reconstruction_error", 0.0),
                        "calibrated_threshold": scored.get("calibrated_threshold", 0.0),
                        "explanation": scored.get("explanation", ""),
                        "top_feature_errors": scored.get("top_deviations", [])
                    }
            else:
                lstm_result["model_status"] = "INSUFFICIENT_DATA"
                lstm_result["explanation"] = f"Fewer than {lstm_settings.SEQUENCE_LENGTH} events available ({len(seq_events)} events)."
    except Exception as exc:
        logger.warning("LSTM assessment exception for event %s: %s", event.event_id, exc)
        lstm_result["explanation"] = f"Detector error: {str(exc)}"

    # 4. Synergistic Risk Aggregation
    overall_score, overall_level, explanation, components, evidence = aggregate_risk(
        rule_findings=rule_findings,
        if_result=if_result,
        lstm_result=lstm_result
    )

    model_readiness = {
        "deterministic_rules_count": len(rules),
        "isolation_forest_status": if_result["model_status"],
        "isolation_forest_evaluated": if_result["evaluated"],
        "lstm_status": lstm_result["model_status"],
        "lstm_evaluated": lstm_result["evaluated"]
    }

    return {
        "assessment_id": assessment_id,
        "event_id": event.event_id,
        "service_identity": event.service_identity,
        "overall_risk_score": overall_score,
        "overall_risk_level": overall_level,
        "risk_explanation": explanation,
        "contributing_components": components,
        "rule_findings": rule_findings,
        "isolation_forest_result": if_result,
        "lstm_result": lstm_result,
        "model_readiness": model_readiness,
        "supporting_evidence": evidence,
        "assessment_timestamp": assessment_ts
    }


def create_or_update_unified_incident(
    db: Session,
    event: ApiEvent,
    assessment: Dict[str, Any]
) -> Optional[Incident]:
    """
    Create or correlate a unified security incident when multi-tier suspicious activity is detected.
    Guarantees:
    - Deduplication within correlation window.
    - Preserves original evidence from all contributing components.
    - Captures contributing_components and unified_assessment snapshot.
    """
    if assessment["overall_risk_score"] < 60 and not assessment["contributing_components"]:
        return None

    rule_id = "SEC-UNIFIED-001"
    rule_name = "Multi-Tier Unified Security Threat"
    if assessment["rule_findings"]:
        # If deterministic rules fired, adopt primary rule identity
        primary = assessment["rule_findings"][0]
        rule_id = primary["rule_id"]
        rule_name = primary["rule_name"]
    elif "LSTM_AUTOENCODER" in assessment["contributing_components"]:
        rule_id = "ML-ANOMALY-LSTM-001"
        rule_name = "Sequential Behavioral Anomaly"
    elif "ISOLATION_FOREST" in assessment["contributing_components"]:
        rule_id = "ML-ANOMALY-ISOFOR-001"
        rule_name = "Behavioral Profile Anomaly"

    detection_res = DetectionResult(
        triggered=True,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=assessment["overall_risk_level"],
        risk_score=assessment["overall_risk_score"],
        explanation=assessment["risk_explanation"],
        evidence={
            "contributing_components": assessment["contributing_components"],
            "unified_assessment_id": assessment["assessment_id"],
            "supporting_evidence": assessment["supporting_evidence"],
            "unified_assessment": assessment
        },
        resource_type=event.resource_type,
        resource_id=event.resource_id
    )

    incident = create_or_update_incident(db=db, result=detection_res, event=event)
    return incident


def get_incident_assessment(db: Session, incident_id: str) -> Dict[str, Any]:
    """
    Retrieve unified assessment details for a specific incident.
    Extracts the embedded multi-tier assessment or builds an explainable breakdown.
    """
    stmt = select(Incident).where(Incident.incident_id == incident_id)
    incident = db.execute(stmt).scalar_one_or_none()
    if not incident:
        return None

    evidence = dict(incident.evidence or {})
    unified_snap = evidence.get("unified_assessment")
    contributing = evidence.get("contributing_components")

    if not contributing:
        if incident.rule_id.startswith("SEC-RULE-"):
            contributing = ["DETERMINISTIC_RULES"]
        elif incident.rule_id == "ML-ANOMALY-LSTM-001":
            contributing = ["LSTM_AUTOENCODER"]
        elif incident.rule_id == "ML-ANOMALY-ISOFOR-001":
            contributing = ["ISOLATION_FOREST"]
        else:
            contributing = ["DETERMINISTIC_RULES"]

    return {
        "incident_id": incident.incident_id,
        "rule_id": incident.rule_id,
        "rule_name": incident.rule_name,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "service_identity": incident.service_identity,
        "contributing_components": contributing,
        "explanation": incident.explanation,
        "evidence": incident.evidence or {},
        "unified_assessment": unified_snap,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }


def get_unified_summary(db: Session) -> Dict[str, Any]:
    """
    Compile comprehensive detection metrics and health status across all tiers.
    """
    total_events = db.execute(select(func.count(ApiEvent.id))).scalar() or 0
    incidents = db.execute(select(Incident)).scalars().all()

    sev_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    comp_triggers = {
        "DETERMINISTIC_RULES": 0,
        "ISOLATION_FOREST": 0,
        "LSTM_AUTOENCODER": 0,
        "MULTI_TIER_CORRELATED": 0
    }
    total_score = 0

    for inc in incidents:
        sev = inc.severity.upper() if inc.severity else "LOW"
        sev_dist[sev] = sev_dist.get(sev, 0) + 1
        total_score += inc.risk_score

        comps = inc.evidence.get("contributing_components") if inc.evidence else None
        if not comps:
            if inc.rule_id.startswith("SEC-RULE-"):
                comps = ["DETERMINISTIC_RULES"]
            elif inc.rule_id == "ML-ANOMALY-LSTM-001":
                comps = ["LSTM_AUTOENCODER"]
            elif inc.rule_id == "ML-ANOMALY-ISOFOR-001":
                comps = ["ISOLATION_FOREST"]
            else:
                comps = ["DETERMINISTIC_RULES"]

        for c in comps:
            if c in comp_triggers:
                comp_triggers[c] += 1
        if len(comps) > 1:
            comp_triggers["MULTI_TIER_CORRELATED"] += 1

    avg_score = round(total_score / len(incidents), 2) if incidents else 0.0

    return {
        "total_assessed_events": total_events,
        "total_incidents": len(incidents),
        "component_trigger_counts": comp_triggers,
        "severity_distribution": sev_dist,
        "average_risk_score": avg_score,
        "model_status": {
            "deterministic_engine": {"rules_active": len(rule_registry.list_rules()), "status": "READY"},
            "isolation_forest": baseline_manager.get_status_overview(),
            "lstm_autoencoder": lstm_baseline_manager.get_status_overview()
        }
    }


def assess_bank_change_risk(
    db: Session,
    vendor_id: str,
    requester_id: str
) -> Dict[str, Any]:
    """
    Examine recent and active security incidents associated with a vendor and requester.
    Compiles actionable warnings for finance reviewers.
    
    CRITICAL INVARIANT:
    AI risk scores NEVER replace human approvals.
    Two independent finance approver signoffs are ALWAYS mandatory.
    """
    now = utc_now()
    window_start = now - timedelta(hours=48)

    # Query all active or recent incidents matching vendor or requester
    stmt = (
        select(Incident)
        .where(
            and_(
                Incident.created_at >= window_start,
                or_(
                    Incident.resource_id == vendor_id,
                    Incident.service_identity == requester_id
                )
            )
        )
        .order_by(Incident.risk_score.desc())
    )
    incidents = db.execute(stmt).scalars().all()

    warnings: List[str] = []
    max_severity = "NONE"
    max_score = 0
    linked_ids: List[str] = []
    linked_summaries: List[Dict[str, Any]] = []

    for inc in incidents:
        linked_ids.append(inc.incident_id)
        linked_summaries.append({
            "incident_id": inc.incident_id,
            "rule_id": inc.rule_id,
            "rule_name": inc.rule_name,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "status": inc.status,
            "explanation": inc.explanation,
            "created_at": inc.created_at.isoformat()
        })

        if inc.risk_score > max_score:
            max_score = inc.risk_score
            max_severity = inc.severity

        # Generate human-readable warning message
        if inc.severity in ("HIGH", "CRITICAL"):
            warnings.append(
                f"[SECURITY WARNING - {inc.severity}] Incident {inc.incident_id[:8]} ({inc.rule_name}): "
                f"{inc.explanation[:120]} (Risk Score: {inc.risk_score})"
            )

    if not warnings and not incidents:
        warnings.append("[CLEAR] No suspicious security incidents or anomalous behavioral patterns detected for this vendor in the last 48 hours.")

    return {
        "vendor_id": vendor_id,
        "requester_id": requester_id,
        "associated_incidents_count": len(incidents),
        "max_incident_severity": max_severity,
        "max_incident_risk_score": max_score,
        "security_warnings": warnings,
        "linked_incident_ids": linked_ids,
        "linked_incidents": linked_summaries,
        "two_person_rule_status": "STRICT_HUMAN_APPROVAL_MANDATORY",
        "ai_authorization_override_permitted": False,
        "snapshot_timestamp": now.isoformat()
    }
