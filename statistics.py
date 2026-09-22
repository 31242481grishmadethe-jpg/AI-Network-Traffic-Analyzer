from database.db import get_db
from datetime import datetime, timedelta


def get_traffic_stats(hours=24):
    with get_db() as conn:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        row = conn.execute(
            """SELECT
                COUNT(*) as total_flows,
                COALESCE(SUM(packet_count), 0) as total_packets,
                COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bytes,
                COUNT(DISTINCT source_ip) as unique_sources,
                COUNT(DISTINCT destination_ip) as unique_destinations,
                COALESCE(AVG(risk_score), 0) as avg_risk
            FROM traffic_flows WHERE timestamp >= ?""",
            (since,),
        ).fetchone()
        return dict(row) if row else {}


def get_protocol_distribution():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT protocol, COUNT(*) as count FROM traffic_flows GROUP BY protocol ORDER BY count DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_alert_severity_distribution():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_top_destinations(limit=10):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT destination_ip, COUNT(*) as connection_count,
                AVG(risk_score) as avg_risk
            FROM traffic_flows
            GROUP BY destination_ip
            ORDER BY connection_count DESC
            LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_traffic_over_time(hours=24, bucket_minutes=15):
    with get_db() as conn:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        rows = conn.execute(
            """SELECT
                strftime('%Y-%m-%d %H:', timestamp) || printf('%02d',
                    (CAST(strftime('%M', timestamp) AS INTEGER) / ?) * ?) as time_bucket,
                COUNT(*) as flow_count,
                COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bytes,
                AVG(risk_score) as avg_risk
            FROM traffic_flows
            WHERE timestamp >= ?
            GROUP BY time_bucket
            ORDER BY time_bucket""",
            (bucket_minutes, bucket_minutes, since),
        ).fetchall()
        return [dict(r) for r in rows]


def get_hourly_distribution():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                COUNT(*) as count
            FROM traffic_flows
            GROUP BY hour
            ORDER BY hour"""
        ).fetchall()
        return [dict(r) for r in rows]


def get_risk_distribution():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT
                CASE
                    WHEN risk_score BETWEEN 0 AND 20 THEN 'Normal'
                    WHEN risk_score BETWEEN 21 AND 40 THEN 'Low'
                    WHEN risk_score BETWEEN 41 AND 60 THEN 'Suspicious'
                    WHEN risk_score BETWEEN 61 AND 80 THEN 'High'
                    ELSE 'Critical'
                END as category,
                COUNT(*) as count
            FROM traffic_flows
            GROUP BY category
            ORDER BY MIN(risk_score)"""
        ).fetchall()
        return [dict(r) for r in rows]


def compare_periods(days=15):
    with get_db() as conn:
        now = datetime.now().isoformat()
        period_start = (datetime.now() - timedelta(days=days)).isoformat()
        prev_start = (datetime.now() - timedelta(days=days * 2)).isoformat()

        current = conn.execute(
            """SELECT COUNT(*) as flows, COUNT(DISTINCT source_ip) as hosts,
                COALESCE(AVG(risk_score), 0) as avg_risk
            FROM traffic_flows WHERE timestamp BETWEEN ? AND ?""",
            (period_start, now),
        ).fetchone()

        previous = conn.execute(
            """SELECT COUNT(*) as flows, COUNT(DISTINCT source_ip) as hosts,
                COALESCE(AVG(risk_score), 0) as avg_risk
            FROM traffic_flows WHERE timestamp BETWEEN ? AND ?""",
            (prev_start, period_start),
        ).fetchone()

        current_alerts = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE timestamp BETWEEN ? AND ?",
            (period_start, now),
        ).fetchone()["c"]

        previous_alerts = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE timestamp BETWEEN ? AND ?",
            (prev_start, period_start),
        ).fetchone()["c"]

        return {
            "current": dict(current) if current else {},
            "previous": dict(previous) if previous else {},
            "current_alerts": current_alerts,
            "previous_alerts": previous_alerts,
        }
