CREATE TABLE IF NOT EXISTS traffic_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    packet_count INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    duration REAL DEFAULT 0.0,
    dns_domain TEXT,
    risk_score REAL DEFAULT 0.0,
    status TEXT DEFAULT 'normal',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    explanation TEXT,
    detection_reasons TEXT,
    status TEXT DEFAULT 'open',
    investigation_id INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE,
    first_seen TEXT,
    last_seen TEXT,
    risk_level TEXT DEFAULT 'normal'
);

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_entity_id INTEGER,
    relationship TEXT NOT NULL,
    target_entity_id INTEGER,
    confidence REAL DEFAULT 1.0,
    evidence TEXT,
    FOREIGN KEY (source_entity_id) REFERENCES entities(id),
    FOREIGN KEY (target_entity_id) REFERENCES entities(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'open',
    conclusion TEXT,
    confidence REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    evidence_type TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT,
    reliability TEXT DEFAULT 'unverified',
    timestamp TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL,
    sample_count INTEGER DEFAULT 0,
    last_updated TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_source ON traffic_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dest ON traffic_flows(destination_ip);
CREATE INDEX IF NOT EXISTS idx_flows_time ON traffic_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
