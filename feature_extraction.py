"""
Module 3: Feature Extraction
Transforms raw packet data into numerical feature vectors for ML model.
"""

import math


class FeatureExtractor:
    """Converts raw packet dictionaries into numeric feature arrays."""

    PROTOCOL_MAP = {
        "TCP": 1, "UDP": 2, "HTTP": 3, "HTTPS": 4,
        "DNS": 5, "MQTT": 6, "CoAP": 7, "OTHER": 0,
    }

    SUSPICIOUS_PORTS = {22, 23, 25, 445, 1433, 3389, 4444, 6667, 9001, 31337}
    SUSPICIOUS_IPS   = {"185.220.101.10", "198.199.100.20", "45.33.32.156"}

    def extract(self, packet: dict) -> list:
        """
        Returns a feature vector:
        [protocol_enc, size_log, dst_port_norm, is_suspicious_ip,
         is_suspicious_port, has_syn_flag, has_large_payload,
         is_known_bad_port, size_raw]
        """
        proto    = self.PROTOCOL_MAP.get(packet.get("protocol", "OTHER"), 0)
        size     = packet.get("size", 0)
        dst_port = packet.get("dst_port", 0)
        flags    = packet.get("flags", "")
        dst_ip   = packet.get("dst_ip", "")

        size_log        = math.log1p(size)
        dst_port_norm   = min(dst_port / 65535.0, 1.0)
        is_susp_ip      = 1 if dst_ip in self.SUSPICIOUS_IPS else 0
        is_susp_port    = 1 if dst_port in self.SUSPICIOUS_PORTS else 0
        has_syn         = 1 if "S" in flags and "A" not in flags else 0
        large_payload   = 1 if size > 10000 else 0
        is_known_bad    = 1 if dst_port in {4444, 6667, 9001, 31337} else 0

        return [
            proto,
            size_log,
            dst_port_norm,
            is_susp_ip,
            is_susp_port,
            has_syn,
            large_payload,
            is_known_bad,
            size,
        ]

    def batch_extract(self, packets: list) -> list:
        return [self.extract(p) for p in packets]

    def feature_names(self):
        return [
            "protocol_enc", "size_log", "dst_port_norm",
            "is_suspicious_ip", "is_suspicious_port",
            "has_syn_flag", "large_payload", "is_known_bad_port",
            "size_raw"
        ]
