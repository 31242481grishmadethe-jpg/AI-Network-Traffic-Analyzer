import os
import random
from typing import Dict, Optional

MOCK_REPUTATIONS = {
    "8.8.8.8": {"score": 0.1, "label": "Clean", "source": "mock-db"},
    "1.1.1.1": {"score": 0.1, "label": "Clean", "source": "mock-db"},
    "192.168.1.1": {"score": 0.0, "label": "Internal", "source": "mock-db"},
    "10.0.0.1": {"score": 0.0, "label": "Internal", "source": "mock-db"},
}

SUSPICIOUS_IPS = [
    "45.33.32.156", "185.220.101.34", "198.51.100.42",
    "203.0.113.69", "192.0.2.100", "103.224.182.251",
]


class ThreatIntelligence:
    def __init__(self):
        self.api_key = os.getenv("THREAT_INTEL_API_KEY", "")
        self.enabled = bool(self.api_key)
        self.use_mock = not self.enabled

    def lookup_ip(self, ip: str) -> Dict:
        if not self.use_mock:
            return self._api_lookup(ip)
        return self._mock_lookup(ip)

    def _mock_lookup(self, ip: str) -> Dict:
        if ip in MOCK_REPUTATIONS:
            return MOCK_REPUTATIONS[ip]

        if ip in SUSPICIOUS_IPS:
            return {
                "score": random.uniform(0.6, 0.9),
                "label": "Suspicious",
                "source": "mock-reputation-db",
            }

        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return {"score": 0.0, "label": "Internal", "source": "mock-db"}

        return {
            "score": random.uniform(0.0, 0.3),
            "label": "Unknown",
            "source": "mock-reputation-db",
        }

    def _api_lookup(self, ip: str) -> Dict:
        try:
            import requests
            headers = {"X-Api-Key": self.api_key}
            resp = requests.get(
                f"https://api.threatintelligence.example/v1/ip/{ip}",
                headers=headers, timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "score": data.get("reputation_score", 0.5),
                    "label": data.get("label", "Unknown"),
                    "source": "threat-intel-api",
                }
        except Exception:
            pass
        return self._mock_lookup(ip)

    def enrich_flow(self, flow: dict) -> dict:
        dest_ip = flow.get("destination_ip", "")
        src_ip = flow.get("source_ip", "")

        dest_info = self.lookup_ip(dest_ip)
        src_info = self.lookup_ip(src_ip)

        flow["dest_reputation"] = dest_info
        flow["src_reputation"] = src_info
        flow["reputation_score"] = max(dest_info["score"], src_info["score"])
        return flow
