import random
import string
from datetime import datetime, timedelta
from typing import List, Dict


def generate_timestamp(hours_back=0, minutes_back=0) -> str:
    now = datetime.now() - timedelta(hours=hours_back, minutes=minutes_back)
    return now.isoformat()


def random_ip(internal=False) -> str:
    if internal:
        return f"192.168.{random.randint(1, 5)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_domain() -> str:
    words = ["login", "api", "cdn", "mail", "update", "sync", "auth", "data"]
    tlds = [".com", ".net", ".org", ".io", ".co"]
    return random.choice(words) + random.choice(string.ascii_lowercase) + random.choice(tlds)


def generate_normal_traffic(count=30) -> List[Dict]:
    flows = []
    internal_ip = "192.168.1.100"
    external_ips = [random_ip() for _ in range(8)]
    common_ports = [80, 443, 53, 8080, 8443]
    protocols = ["TCP", "UDP", "TCP"]

    for i in range(count):
        proto = random.choice(protocols)
        flows.append({
            "timestamp": generate_timestamp(minutes_back=random.randint(0, 120)),
            "source_ip": internal_ip,
            "destination_ip": random.choice(external_ips),
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice(common_ports),
            "protocol": proto,
            "packet_count": random.randint(3, 50),
            "bytes_sent": random.randint(200, 5000),
            "bytes_received": random.randint(500, 20000),
            "duration": round(random.uniform(0.1, 5.0), 2),
            "dns_domain": random_domain() if random.random() > 0.3 else None,
        })
    return flows


def generate_port_scan(count=40) -> List[Dict]:
    flows = []
    scanner_ip = random_ip()
    target_ip = "192.168.1.100"
    ports = list(range(1, 1024)) + [3306, 5432, 8080, 8443, 6379, 27017]

    for i in range(count):
        port = random.choice(ports)
        flows.append({
            "timestamp": generate_timestamp(minutes_back=random.randint(0, 30)),
            "source_ip": scanner_ip,
            "destination_ip": target_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": port,
            "protocol": "TCP",
            "packet_count": random.randint(1, 3),
            "bytes_sent": random.randint(40, 200),
            "bytes_received": random.randint(0, 100),
            "duration": round(random.uniform(0.01, 0.5), 3),
            "dns_domain": None,
        })
    return flows


def generate_high_frequency(count=80) -> List[Dict]:
    flows = []
    src_ip = "192.168.1.100"
    dst_ip = random_ip()

    for i in range(count):
        flows.append({
            "timestamp": generate_timestamp(minutes_back=random.randint(0, 15)),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([443, 80, 8080]),
            "protocol": "TCP",
            "packet_count": random.randint(1, 5),
            "bytes_sent": random.randint(100, 1000),
            "bytes_received": random.randint(50, 500),
            "duration": round(random.uniform(0.05, 1.0), 2),
            "dns_domain": random_domain(),
        })
    return flows


def generate_dns_anomaly(count=25) -> List[Dict]:
    flows = []
    src_ip = "192.168.1.100"

    suspicious_domains = [
        "a1b2c3d4e5f6.tk", "xj7kmloq.xyz", "malware-download.ga",
        "data-exfil.cf", "c2server.top", "phishing-login.ml",
        "ransomware-payment.buzz", "botnet-controller.gq",
    ]
    normal_domains = ["google.com", "github.com", "stackoverflow.com"]

    for i in range(count):
        is_suspicious = random.random() > 0.3
        domain = random.choice(suspicious_domains) if is_suspicious else random.choice(normal_domains)
        flows.append({
            "timestamp": generate_timestamp(minutes_back=random.randint(0, 60)),
            "source_ip": src_ip,
            "destination_ip": "8.8.8.8",
            "source_port": random.randint(49152, 65535),
            "destination_port": 53,
            "protocol": "UDP",
            "packet_count": random.randint(1, 3),
            "bytes_sent": random.randint(40, 200),
            "bytes_received": random.randint(100, 500),
            "duration": round(random.uniform(0.01, 0.5), 3),
            "dns_domain": domain,
        })
    return flows


def generate_unusual_outbound(count=20) -> List[Dict]:
    flows = []
    src_ip = "192.168.1.100"
    suspicious_dests = ["45.33.32.156", "185.220.101.34", "198.51.100.42"]

    for i in range(count):
        flows.append({
            "timestamp": generate_timestamp(hours_back=random.randint(1, 4)),
            "source_ip": src_ip,
            "destination_ip": random.choice(suspicious_dests),
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([4444, 5555, 8080, 443]),
            "protocol": "TCP",
            "packet_count": random.randint(5, 200),
            "bytes_sent": random.randint(10000, 500000),
            "bytes_received": random.randint(100, 5000),
            "duration": round(random.uniform(5.0, 60.0), 2),
            "dns_domain": None,
        })
    return flows


def generate_brute_force(count=50) -> List[Dict]:
    flows = []
    src_ip = random_ip()
    target_ip = "192.168.1.100"

    for i in range(count):
        flows.append({
            "timestamp": generate_timestamp(minutes_back=random.randint(0, 20)),
            "source_ip": src_ip,
            "destination_ip": target_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([22, 3389, 21]),
            "protocol": "TCP",
            "packet_count": random.randint(1, 5),
            "bytes_sent": random.randint(50, 300),
            "bytes_received": random.randint(0, 100),
            "duration": round(random.uniform(0.1, 1.0), 2),
            "dns_domain": None,
        })
    return flows


SCENARIO_GENERATORS = {
    "Normal Traffic": generate_normal_traffic,
    "Port Scan": generate_port_scan,
    "High Connection Frequency": generate_high_frequency,
    "DNS Anomaly": generate_dns_anomaly,
    "Unusual Outbound Traffic": generate_unusual_outbound,
    "Brute Force Pattern": generate_brute_force,
}
