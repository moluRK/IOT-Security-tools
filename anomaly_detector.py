"""
Module 4: Anomaly Detection
Uses Isolation Forest (unsupervised ML) to detect abnormal IoT traffic.
Falls back to rule-based detection when insufficient data for training.
"""

import os
import pickle
import numpy as np
from datetime import datetime


class AnomalyDetector:
    MODEL_PATH = "models/isolation_forest.pkl"
    MIN_SAMPLES = 100  # need at least this many packets before ML kicks in

    SUSPICIOUS_PORTS = {4444, 6667, 9001, 31337, 23, 445}
    SUSPICIOUS_IPS   = {"185.220.101.10", "198.199.100.20"}
    KNOWN_CC_PORTS   = {6667, 6668, 6669}  # IRC botnet

    def __init__(self):
        self.model = None
        self.is_trained = False
        self.sample_count = 0
        self._recent_features = []  # buffer for online learning

    # ─── Model lifecycle ─────────────────────────────────────────────────────

    def load_or_create_model(self):
        os.makedirs("models", exist_ok=True)
        if os.path.exists(self.MODEL_PATH):
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                print("[AnomalyDetector] Loaded saved model.")
            except Exception as e:
                print(f"[AnomalyDetector] Could not load model: {e}")
                self._init_fresh_model()
        else:
            self._init_fresh_model()

    def _init_fresh_model(self):
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,  # expect ~5% anomalies
                random_state=42,
                max_samples="auto"
            )
            print("[AnomalyDetector] Fresh Isolation Forest created (not yet trained).")
        except ImportError:
            print("[AnomalyDetector] sklearn not found. Using rule-based detection only.")
            self.model = None

    def save_model(self):
        if self.model and self.is_trained:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            print("[AnomalyDetector] Model saved.")

    def train(self, db_logger):
        """Train on all existing logged packets."""
        packets = db_logger.get_all_packets_for_training()
        if len(packets) < self.MIN_SAMPLES:
            return {
                "status": "insufficient_data",
                "message": f"Need {self.MIN_SAMPLES} packets, have {len(packets)}",
                "count": len(packets)
            }

        from modules.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        X = fe.batch_extract(packets)

        try:
            self.model.fit(X)
            self.is_trained = True
            self.sample_count = len(X)
            self.save_model()
            return {
                "status": "success",
                "message": f"Model trained on {len(X)} packets",
                "count": len(X)
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ─── Prediction ──────────────────────────────────────────────────────────

    def predict(self, features: list, raw_packet: dict):
        """
        Returns (is_anomaly: bool, score: float, reason: str)
        Uses ML if trained, otherwise falls back to rules.
        """
        # Always run rule-based first (high-confidence catches)
        rule_anomaly, rule_reason = self._rule_based(raw_packet)
        if rule_anomaly:
            return True, 1.0, rule_reason

        # Online buffer: accumulate features for potential re-training
        self._recent_features.append(features)
        if len(self._recent_features) > 5000:
            self._recent_features = self._recent_features[-5000:]

        # Try ML model
        if self.is_trained and self.model:
            try:
                X = np.array([features])
                pred = self.model.predict(X)[0]
                score_raw = self.model.score_samples(X)[0]
                # IsolationForest: -1 = anomaly, score more negative = more anomalous
                anomaly_score = max(0.0, min(1.0, -score_raw))
                is_anomaly = (pred == -1)
                reason = "ML anomaly detected (Isolation Forest)" if is_anomaly else ""
                return is_anomaly, anomaly_score, reason
            except Exception:
                pass

        # Auto-train when enough buffer data and model not trained yet
        if not self.is_trained and len(self._recent_features) >= self.MIN_SAMPLES and self.model:
            try:
                self.model.fit(self._recent_features)
                self.is_trained = True
                self.save_model()
                print("[AnomalyDetector] Auto-trained on buffered data.")
            except Exception:
                pass

        return False, 0.0, ""

    def _rule_based(self, pkt: dict):
        """Hard rules for known bad patterns."""
        dst_ip   = pkt.get("dst_ip", "")
        dst_port = pkt.get("dst_port", 0)
        size     = pkt.get("size", 0)
        flags    = pkt.get("flags", "")
        proto    = pkt.get("protocol", "")

        if dst_ip in self.SUSPICIOUS_IPS:
            return True, f"Traffic to known malicious IP: {dst_ip}"

        if dst_port in self.SUSPICIOUS_PORTS:
            return True, f"Suspicious destination port: {dst_port}"

        if dst_port in self.KNOWN_CC_PORTS and proto == "TCP":
            return True, f"Possible IRC botnet C&C on port {dst_port}"

        if size > 50000:
            return True, f"Unusually large packet ({size} bytes) — possible data exfiltration"

        if flags == "S" and dst_port < 1024:
            return True, f"SYN scan detected on privileged port {dst_port}"

        if pkt.get("attack_type"):
            return True, f"Simulated attack: {pkt['attack_type']}"

        return False, ""
