from datetime import datetime
from typing import Dict, List, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class PacketCapture:
    def __init__(self):
        self.capturing = False
        self.flows = []

    def start_capture(self, interface=None, packet_count=100, timeout=30):
        if not HAS_SCAPY:
            return {"error": "Scapy not installed. Run: pip install scapy"}

        self.capturing = True
        captured = []

        def process_packet(pkt):
            if not self.capturing:
                return
            if IP in pkt:
                flow = self._extract_flow(pkt)
                if flow:
                    captured.append(flow)

        try:
            sniff(
                iface=interface,
                prn=process_packet,
                count=packet_count,
                timeout=timeout,
                store=False,
            )
        except Exception as e:
            return {"error": f"Capture failed: {str(e)}"}

        self.capturing = False
        self.flows = captured
        return {"captured": len(captured), "flows": captured}

    def stop_capture(self):
        self.capturing = False

    def _extract_flow(self, pkt) -> Optional[Dict]:
        flow = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": pkt[IP].src,
            "destination_ip": pkt[IP].dst,
            "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
            "packet_count": 1,
            "bytes_sent": len(pkt),
            "bytes_received": 0,
            "duration": 0.0,
            "dns_domain": None,
        }

        if TCP in pkt:
            flow["source_port"] = pkt[TCP].sport
            flow["destination_port"] = pkt[TCP].dport
        elif UDP in pkt:
            flow["source_port"] = pkt[UDP].sport
            flow["destination_port"] = pkt[UDP].dport

        if DNS in pkt and pkt[DNS].qd:
            try:
                flow["dns_domain"] = pkt[DNS].qd.qname.decode("utf-8").rstrip(".")
            except Exception:
                pass

        return flow
