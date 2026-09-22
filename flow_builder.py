from datetime import datetime
from typing import Dict, List


class FlowBuilder:
    def __init__(self, flow_timeout=30):
        self.flow_timeout = flow_timeout
        self.active_flows = {}

    def process_packet(self, packet_data: dict) -> dict:
        key = self._flow_key(packet_data)
        now = datetime.now()

        if key in self.active_flows:
            flow = self.active_flows[key]
            flow["packet_count"] += 1
            src = packet_data.get("source_ip", "")
            if src == flow.get("source_ip"):
                flow["bytes_sent"] += packet_data.get("bytes", 0)
            else:
                flow["bytes_received"] += packet_data.get("bytes", 0)

            if packet_data.get("dns_domain") and not flow.get("dns_domain"):
                flow["dns_domain"] = packet_data["dns_domain"]

            flow["last_seen"] = now.isoformat()
        else:
            self.active_flows[key] = {
                "timestamp": now.isoformat(),
                "source_ip": packet_data.get("source_ip", ""),
                "destination_ip": packet_data.get("destination_ip", ""),
                "source_port": packet_data.get("source_port"),
                "destination_port": packet_data.get("destination_port"),
                "protocol": packet_data.get("protocol", "TCP"),
                "packet_count": 1,
                "bytes_sent": packet_data.get("bytes", 0),
                "bytes_received": 0,
                "duration": 0.0,
                "dns_domain": packet_data.get("dns_domain"),
                "last_seen": now.isoformat(),
            }

        return self.active_flows[key]

    def get_expired_flows(self) -> List[Dict]:
        now = datetime.now()
        expired = []
        to_remove = []

        for key, flow in self.active_flows.items():
            try:
                last = datetime.fromisoformat(flow["last_seen"])
                elapsed = (now - last).total_seconds()
                if elapsed >= self.flow_timeout:
                    flow["duration"] = round(elapsed, 2)
                    expired.append(flow)
                    to_remove.append(key)
            except (ValueError, TypeError):
                to_remove.append(key)

        for key in to_remove:
            del self.active_flows[key]

        return expired

    def _flow_key(self, packet_data: dict) -> str:
        return (
            f"{packet_data.get('source_ip', '')}:"
            f"{packet_data.get('source_port', 0)}-"
            f"{packet_data.get('destination_ip', '')}:"
            f"{packet_data.get('destination_port', 0)}-"
            f"{packet_data.get('protocol', 'TCP')}"
        )
