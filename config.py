import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "traffic_sentinel.db"

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

RISK_THRESHOLDS = {
    "normal": (0, 20),
    "low": (21, 40),
    "suspicious": (41, 60),
    "high": (61, 80),
    "critical": (81, 100),
}

RISK_WEIGHTS = {
    "unusual_port_activity": 20,
    "high_connection_frequency": 15,
    "reputation_concern": 35,
    "traffic_anomaly": 20,
    "unusual_time": 10,
    "dns_anomaly": 15,
    "port_scan": 25,
    "failed_connections": 15,
    "data_exfiltration": 30,
}

DETECTION_CONFIG = {
    "port_scan_threshold": 15,
    "high_freq_threshold": 50,
    "unusual_hour_start": 1,
    "unusual_hour_end": 5,
    "baseline_window_days": 30,
    "anomaly_contamination": 0.1,
}

SCAN_INTERVAL_DAYS = 15

LIVE_MODE = False
