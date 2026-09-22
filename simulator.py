from typing import List, Dict
from database.db import insert_flow, insert_alert, upsert_entity, insert_relationship
from detection import run_all_rules
from detection.risk_engine import calculate_risk_score
from detection.anomaly_detector import AnomalyDetector
from intelligence.threat_intelligence import ThreatIntelligence
from simulation.scenarios import SCENARIO_GENERATORS

detector = AnomalyDetector()
threat_intel = ThreatIntelligence()


def process_flows(flows: List[Dict]) -> Dict:
    all_flows = []
    all_alerts = []

    for flow in flows:
        enriched = threat_intel.enrich_flow(flow)
        all_flows.append(enriched)

    if all_flows:
        detector.train(all_flows)
        anomaly_results = detector.batch_predict(all_flows)
        for flow, anomaly in zip(all_flows, anomaly_results):
            flow["anomaly_score"] = anomaly["anomaly_score"]

    for flow in all_flows:
        detections = run_all_rules(all_flows, flow)
        detection_dicts = [
            {"detected": d.detected, "alert_type": d.alert_type,
             "severity": d.severity, "confidence": d.confidence,
             "reasons": d.reasons, "evidence": d.evidence}
            for d in detections
        ]

        risk = calculate_risk_score(
            detection_dicts,
            anomaly_score=flow.get("anomaly_score", 0.0),
            reputation_score=flow.get("reputation_score", 0.0),
        )

        flow["risk_score"] = risk["risk_score"]
        flow["status"] = risk["severity"].lower()

        flow_id = insert_flow(flow)
        flow["id"] = flow_id

        _store_entities(flow)

        triggered = [d for d in detections if d.detected]
        if triggered:
            for det in triggered:
                reasons_str = "; ".join(det.reasons)
                alert_data = {
                    "timestamp": flow["timestamp"],
                    "severity": risk["severity"] if det.severity == "Normal" else det.severity,
                    "alert_type": det.alert_type,
                    "source_ip": flow.get("source_ip"),
                    "destination_ip": flow.get("destination_ip"),
                    "destination_port": flow.get("destination_port"),
                    "protocol": flow.get("protocol"),
                    "risk_score": risk["risk_score"],
                    "confidence": risk["confidence"],
                    "explanation": reasons_str,
                    "detection_reasons": reasons_str,
                    "status": "open",
                }
                alert_id = insert_alert(alert_data)
                alert_data["id"] = alert_id
                all_alerts.append(alert_data)

    return {
        "flows_processed": len(all_flows),
        "alerts_generated": len(all_alerts),
        "flows": all_flows,
        "alerts": all_alerts,
    }


def _store_entities(flow: Dict):
    src = flow.get("source_ip", "")
    dst = flow.get("destination_ip", "")
    domain = flow.get("dns_domain")

    src_risk = "high" if flow.get("risk_score", 0) > 60 else "normal"
    dst_risk = "high" if flow.get("reputation_score", 0) > 0.5 else "normal"

    src_id = upsert_entity("ip", src, src_risk)
    dst_id = upsert_entity("ip", dst, dst_risk)

    insert_relationship(src_id, "connected_to", dst_id,
                        evidence=f"Protocol: {flow.get('protocol')}, Port: {flow.get('destination_port')}")

    if domain:
        dom_id = upsert_entity("domain", domain, "normal")
        insert_relationship(dst_id, "resolves_to", dom_id,
                            evidence=f"DNS query from {src}")


def run_simulation(scenario_name: str) -> Dict:
    generator = SCENARIO_GENERATORS.get(scenario_name)
    if not generator:
        return {"error": f"Unknown scenario: {scenario_name}"}

    flows = generator()
    return process_flows(flows)
