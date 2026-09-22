from database.db import get_db
from datetime import datetime, timedelta


def compute_baseline(host_ip: str):
    with get_db() as conn:
        row = conn.execute(
            """SELECT
                AVG(packet_count) as avg_packets,
                AVG(bytes_sent + bytes_received) as avg_bytes,
                AVG(duration) as avg_duration,
                COUNT(DISTINCT destination_port) as port_diversity,
                COUNT(*) as sample_size
            FROM traffic_flows WHERE source_ip = ?""",
            (host_ip,),
        ).fetchone()

        if not row or row["sample_size"] == 0:
            return None

        baseline = {
            "host_ip": host_ip,
            "avg_packets": round(row["avg_packets"] or 0, 1),
            "avg_bytes": round(row["avg_bytes"] or 0, 1),
            "avg_duration": round(row["avg_duration"] or 0, 2),
            "port_diversity": row["port_diversity"] or 0,
            "sample_size": row["sample_size"],
        }

        conn.execute(
            """INSERT OR REPLACE INTO baselines (host_ip, metric_name, metric_value, sample_count, last_updated)
            VALUES (?, 'avg_packets', ?, ?, datetime('now')),
                   (?, 'avg_bytes', ?, ?, datetime('now')),
                   (?, 'avg_duration', ?, ?, datetime('now'))""",
            (host_ip, baseline["avg_packets"], baseline["sample_size"],
             host_ip, baseline["avg_bytes"], baseline["sample_size"],
             host_ip, baseline["avg_duration"], baseline["sample_size"]),
        )

        return baseline


def get_baseline(host_ip: str):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT metric_name, metric_value, sample_count FROM baselines WHERE host_ip = ?",
            (host_ip,),
        ).fetchall()

        if not rows:
            return compute_baseline(host_ip)

        baseline = {"host_ip": host_ip, "metrics": {}}
        for r in rows:
            baseline["metrics"][r["metric_name"]] = {
                "value": r["metric_value"],
                "samples": r["sample_count"],
            }
        return baseline


def detect_baseline_deviation(host_ip: str, current_flow: dict) -> dict:
    baseline = get_baseline(host_ip)
    if not baseline or "metrics" not in baseline:
        return {"deviation": False, "reason": "No baseline available"}

    deviations = []
    metrics = baseline["metrics"]

    if "avg_bytes" in metrics:
        expected = metrics["avg_bytes"]["value"]
        actual = current_flow.get("bytes_sent", 0) + current_flow.get("bytes_received", 0)
        if expected > 0 and actual > expected * 3:
            deviations.append(f"Traffic volume {actual} exceeds baseline {expected:.0f} by {actual/expected:.1f}x")

    if "avg_packets" in metrics:
        expected = metrics["avg_packets"]["value"]
        actual = current_flow.get("packet_count", 0)
        if expected > 0 and actual > expected * 3:
            deviations.append(f"Packet count {actual} exceeds baseline {expected:.0f} by {actual/expected:.1f}x")

    return {
        "deviation": len(deviations) > 0,
        "deviations": deviations,
        "baseline": metrics,
    }
