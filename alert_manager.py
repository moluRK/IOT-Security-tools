"""
Module 5: Alert Generation
Creates structured alerts with severity classification and history.
"""

from datetime import datetime
from collections import deque


class AlertManager:
    SEVERITY_MAP = {
        "malicious IP":          "CRITICAL",
        "botnet":                "CRITICAL",
        "Botnet":                "CRITICAL",
        "DDoS":                  "HIGH",
        "exfiltration":          "HIGH",
        "Exfiltration":          "HIGH",
        "Port Scan":             "HIGH",
        "port":                  "MEDIUM",
        "SYN scan":              "HIGH",
        "large packet":          "MEDIUM",
        "ML anomaly":            "MEDIUM",
    }

    def __init__(self, db_logger, max_history=500):
        self.db_logger = db_logger
        self._recent = deque(maxlen=max_history)

    def create_alert(self, packet: dict, score: float, reason: str) -> dict:
        severity = self._classify_severity(reason, packet)
        alert = {
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      packet.get("src_ip", ""),
            "dst_ip":      packet.get("dst_ip", ""),
            "protocol":    packet.get("protocol", ""),
            "size":        packet.get("size", 0),
            "dst_port":    packet.get("dst_port", 0),
            "device":      packet.get("device", "Unknown"),
            "severity":    severity,
            "reason":      reason,
            "score":       round(score, 4),
            "attack_type": packet.get("attack_type", ""),
            "resolved":    False,
        }
        self._recent.appendleft(alert)
        return alert

    def get_alerts(self, limit=20, severity=None):
        alerts = list(self._recent)
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        return alerts[:limit]

    def get_critical_count(self):
        return sum(1 for a in self._recent if a["severity"] == "CRITICAL")

    def _classify_severity(self, reason: str, packet: dict) -> str:
        # Check packet's own attack_type first
        at = packet.get("attack_type", "")
        for keyword, sev in self.SEVERITY_MAP.items():
            if keyword in at or keyword in reason:
                return sev
        return "LOW"
