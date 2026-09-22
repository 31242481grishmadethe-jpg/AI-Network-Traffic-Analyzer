from database.db import (
    get_alert_by_id, query_flows, query_alerts,
    get_entity_by_value, get_relationships_for_entity, get_db,
)
from datetime import datetime


def get_alert_details(alert_id: int) -> dict:
    alert = get_alert_by_id(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    related_flows = query_flows(
        limit=10,
        source_ip=alert.get("source_ip"),
        destination_ip=alert.get("destination_ip"),
    )
    return {
        "alert": alert,
        "related_flows": related_flows,
        "flow_count": len(related_flows),
    }


def search_traffic(source_ip=None, destination_ip=None, protocol=None) -> dict:
    flows = query_flows(limit=50, source_ip=source_ip,
                        destination_ip=destination_ip, protocol=protocol)
    return {
        "count": len(flows),
        "flows": flows[:20],
        "filters": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
        },
    }


def get_host_history(host_ip: str) -> dict:
    outgoing = query_flows(limit=50, source_ip=host_ip)
    incoming = query_flows(limit=50, destination_ip=host_ip)

    protocols = set()
    ports = set()
    domains = set()
    for f in outgoing + incoming:
        if f.get("protocol"):
            protocols.add(f["protocol"])
        if f.get("destination_port"):
            ports.add(f["destination_port"])
        if f.get("dns_domain"):
            domains.add(f["dns_domain"])

    return {
        "host": host_ip,
        "outgoing_flows": len(outgoing),
        "incoming_flows": len(incoming),
        "protocols_seen": list(protocols),
        "ports_contacted": sorted(ports)[:20],
        "domains_queried": list(domains)[:20],
        "recent_flows": (outgoing + incoming)[:15],
    }


def get_related_events(alert_id: int) -> dict:
    alert = get_alert_by_id(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}

    related = query_alerts(limit=20)
    related_events = []
    for r in related:
        if r["id"] == alert_id:
            continue
        if (r.get("source_ip") == alert.get("source_ip") or
                r.get("destination_ip") == alert.get("destination_ip")):
            related_events.append(r)

    return {
        "alert_id": alert_id,
        "related_count": len(related_events),
        "related_events": related_events,
    }


def get_dns_history(domain: str) -> dict:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM traffic_flows WHERE dns_domain = ? ORDER BY timestamp DESC LIMIT 30",
            (domain,),
        ).fetchall()
        flows = [dict(r) for r in rows]

    entity = get_entity_by_value("domain", domain)
    relationships = []
    if entity:
        relationships = get_relationships_for_entity(entity["id"])

    return {
        "domain": domain,
        "observations": len(flows),
        "flows": flows,
        "relationships": relationships,
    }


def get_historical_baseline(host_ip: str) -> dict:
    with get_db() as conn:
        row = conn.execute(
            """SELECT
                AVG(packet_count) as avg_packets,
                AVG(bytes_sent + bytes_received) as avg_bytes,
                AVG(duration) as avg_duration,
                COUNT(*) as sample_size
            FROM traffic_flows WHERE source_ip = ?""",
            (host_ip,),
        ).fetchone()

    if not row or row["sample_size"] == 0:
        return {"host": host_ip, "baseline_available": False}

    return {
        "host": host_ip,
        "baseline_available": True,
        "avg_packets": round(row["avg_packets"] or 0, 1),
        "avg_bytes": round(row["avg_bytes"] or 0, 1),
        "avg_duration": round(row["avg_duration"] or 0, 2),
        "sample_size": row["sample_size"],
    }


def get_investigation_evidence(investigation_id: int) -> dict:
    with get_db() as conn:
        inv = conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        evidence_rows = conn.execute(
            "SELECT * FROM evidence WHERE investigation_id = ? ORDER BY timestamp",
            (investigation_id,),
        ).fetchall()

    return {
        "investigation": dict(inv) if inv else None,
        "evidence": [dict(r) for r in evidence_rows],
        "evidence_count": len(evidence_rows),
    }
