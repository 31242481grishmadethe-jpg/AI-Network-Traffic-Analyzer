import sqlite3
from pathlib import Path
from contextlib import contextmanager
from config import DB_PATH


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, "r") as f:
        schema = f.read()
    with get_db() as conn:
        conn.executescript(schema)


def insert_flow(flow_data: dict) -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO traffic_flows
            (timestamp, source_ip, destination_ip, source_port, destination_port,
             protocol, packet_count, bytes_sent, bytes_received, duration,
             dns_domain, risk_score, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow_data["timestamp"], flow_data["source_ip"],
                flow_data["destination_ip"], flow_data.get("source_port"),
                flow_data.get("destination_port"), flow_data.get("protocol"),
                flow_data.get("packet_count", 0), flow_data.get("bytes_sent", 0),
                flow_data.get("bytes_received", 0), flow_data.get("duration", 0.0),
                flow_data.get("dns_domain"), flow_data.get("risk_score", 0.0),
                flow_data.get("status", "normal"),
            ),
        )
        return cursor.lastrowid


def insert_alert(alert_data: dict) -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO alerts
            (timestamp, severity, alert_type, source_ip, destination_ip,
             destination_port, protocol, risk_score, confidence, explanation,
             detection_reasons, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_data["timestamp"], alert_data["severity"],
                alert_data["alert_type"], alert_data.get("source_ip"),
                alert_data.get("destination_ip"), alert_data.get("destination_port"),
                alert_data.get("protocol"), alert_data.get("risk_score", 0.0),
                alert_data.get("confidence", 0.0), alert_data.get("explanation", ""),
                alert_data.get("detection_reasons", ""),
                alert_data.get("status", "open"),
            ),
        )
        return cursor.lastrowid


def upsert_entity(entity_type: str, value: str, risk_level: str = "normal") -> int:
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM entities WHERE type=? AND value=?",
            (entity_type, value),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE entities SET last_seen=datetime('now'), risk_level=? WHERE id=?",
                (risk_level, existing["id"]),
            )
            return existing["id"]
        else:
            cursor = conn.execute(
                "INSERT INTO entities (type, value, first_seen, last_seen, risk_level) VALUES (?, ?, datetime('now'), datetime('now'), ?)",
                (entity_type, value, risk_level),
            )
            return cursor.lastrowid


def insert_relationship(source_id: int, relationship: str, target_id: int,
                        confidence: float = 1.0, evidence: str = "") -> int:
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO relationships (source_entity_id, relationship, target_entity_id, confidence, evidence) VALUES (?, ?, ?, ?, ?)",
            (source_id, relationship, target_id, confidence, evidence),
        )
        return cursor.lastrowid


def create_investigation(case_name: str) -> int:
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO investigations (case_name) VALUES (?)", (case_name,)
        )
        return cursor.lastrowid


def insert_evidence(investigation_id: int, evidence_type: str,
                    description: str, source: str = "", reliability: str = "unverified") -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO evidence (investigation_id, evidence_type, description, source, reliability)
            VALUES (?, ?, ?, ?, ?)""",
            (investigation_id, evidence_type, description, source, reliability),
        )
        return cursor.lastrowid


def query_flows(limit=100, offset=0, source_ip=None, destination_ip=None,
                protocol=None, status=None, min_risk=0, max_risk=100):
    with get_db() as conn:
        conditions = ["risk_score >= ?", "risk_score <= ?"]
        params = [min_risk, max_risk]
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if destination_ip:
            conditions.append("destination_ip = ?")
            params.append(destination_ip)
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = " AND ".join(conditions)
        params.extend([limit, offset])
        rows = conn.execute(
            f"SELECT * FROM traffic_flows WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def query_alerts(limit=100, severity=None, status=None):
    with get_db() as conn:
        conditions = []
        params = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM alerts{where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def get_alert_by_id(alert_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None


def get_flow_by_id(flow_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM traffic_flows WHERE id = ?", (flow_id,)).fetchone()
        return dict(row) if row else None


def get_entity_by_value(entity_type: str, value: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM entities WHERE type = ? AND value = ?",
            (entity_type, value),
        ).fetchone()
        return dict(row) if row else None


def get_relationships_for_entity(entity_id: int):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT r.*, e1.type as src_type, e1.value as src_value,
                      e2.type as tgt_type, e2.value as tgt_value
            FROM relationships r
            JOIN entities e1 ON r.source_entity_id = e1.id
            JOIN entities e2 ON r.target_entity_id = e2.id
            WHERE r.source_entity_id = ? OR r.target_entity_id = ?""",
            (entity_id, entity_id),
        ).fetchall()
        return [dict(r) for r in rows]


def get_stats():
    with get_db() as conn:
        total_flows = conn.execute("SELECT COUNT(*) as c FROM traffic_flows").fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
        critical = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='Critical'").fetchone()["c"]
        high = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='High'").fetchone()["c"]
        suspicious = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='Suspicious'").fetchone()["c"]
        anomalies = conn.execute("SELECT COUNT(*) as c FROM traffic_flows WHERE risk_score > 60").fetchone()["c"]
        total_bytes = conn.execute("SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) as c FROM traffic_flows").fetchone()["c"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) as c FROM traffic_flows").fetchone()["c"]
        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "critical_alerts": critical,
            "high_alerts": high,
            "suspicious_alerts": suspicious,
            "anomalies": anomalies,
            "total_bytes": total_bytes,
            "unique_ips": unique_ips,
        }


def clear_all_data():
    with get_db() as conn:
        for table in ["evidence", "relationships", "entities", "alerts",
                       "traffic_flows", "investigations", "baselines"]:
            conn.execute(f"DELETE FROM {table}")
