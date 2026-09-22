from typing import Dict, List
from config import RISK_WEIGHTS, RISK_THRESHOLDS


def calculate_risk_score(detection_results: List[Dict], anomaly_score: float = 0.0,
                         reputation_score: float = 0.0) -> Dict:
    score = 0.0
    reasons = []

    for result in detection_results:
        if not result.get("detected", False):
            continue

        alert_type = result.get("alert_type", "")
        weight_key = _map_alert_to_weight(alert_type)
        if weight_key and weight_key in RISK_WEIGHTS:
            score += RISK_WEIGHTS[weight_key]
            reasons.append(f"{alert_type}: +{RISK_WEIGHTS[weight_key]}")

    if anomaly_score > 0.5:
        penalty = int(20 * anomaly_score)
        score += penalty
        reasons.append(f"Anomaly detected (score: {anomaly_score:.2f}): +{penalty}")

    if reputation_score > 0.5:
        penalty = int(35 * reputation_score)
        score += penalty
        reasons.append(f"Reputation concern (score: {reputation_score:.2f}): +{penalty}")

    normalized = min(100, max(0, score))

    severity = "Normal"
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= normalized <= high:
            severity = level.capitalize()
            break

    confidence = min(1.0, normalized / 100 * 0.8 + len(reasons) * 0.05)

    return {
        "risk_score": normalized,
        "severity": severity,
        "confidence": round(confidence, 2),
        "reasons": reasons,
    }


def _map_alert_to_weight(alert_type: str) -> str:
    mapping = {
        "Possible Port Scan": "port_scan",
        "Excessive Connection Attempts": "high_connection_frequency",
        "Unusual Traffic Volume": "data_exfiltration",
        "Unusual Activity Time": "unusual_time",
        "Suspicious DNS Behavior": "dns_anomaly",
        "Repeated Failed Connections": "failed_connections",
        "Traffic Anomaly": "traffic_anomaly",
    }
    return mapping.get(alert_type, "")


def get_risk_category(score: float) -> str:
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level.capitalize()
    return "Normal"


def get_risk_color(severity: str) -> str:
    colors = {
        "Normal": "#22c55e",
        "Low": "#84cc16",
        "Suspicious": "#eab308",
        "High": "#f97316",
        "Critical": "#ef4444",
    }
    return colors.get(severity, "#6b7280")
