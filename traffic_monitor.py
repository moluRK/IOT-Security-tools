"""
Module 1: Traffic Monitoring
Captures network packets from IoT devices and feeds them through the pipeline.
"""

import time
import random
import threading
from datetime import datetime


class TrafficMonitor:
    """
    Monitors network traffic. In real deployment uses Scapy for live capture.
    In simulation mode (no root/interface), generates realistic IoT traffic.
    """

    def __init__(self, db_logger, feature_extractor, anomaly_detector, alert_manager, socketio):
        self.db_logger = db_logger
        self.feature_extractor = feature_extractor
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.socketio = socketio

        self.packet_count = 0
        self.anomaly_count = 0
        self._running = False
        self._start_time = None

        # Known IoT device profiles for simulation
        self.iot_devices = [
            {"ip": "192.168.1.101", "name": "Smart Camera", "mac": "AA:BB:CC:11:22:33"},
            {"ip": "192.168.1.102", "name": "Smart Bulb",   "mac": "AA:BB:CC:44:55:66"},
            {"ip": "192.168.1.103", "name": "Smart Router",  "mac": "AA:BB:CC:77:88:99"},
            {"ip": "192.168.1.104", "name": "Thermostat",    "mac": "AA:BB:CC:AA:BB:CC"},
            {"ip": "192.168.1.105", "name": "Smart Lock",    "mac": "AA:BB:CC:DD:EE:FF"},
        ]
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "52.86.12.45",
            "104.21.5.33", "185.220.101.10",  # last one is Tor exit node (suspicious)
            "198.199.100.20", "45.33.32.156"
        ]
        self.protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "MQTT", "CoAP"]

    # ─── Public API ──────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._start_time = time.time()
        try:
            self._try_live_capture()
        except Exception:
            # Fall back to simulation (no root / no interface)
            self._simulate_traffic()

    def stop(self):
        self._running = False

    def get_uptime(self):
        if self._start_time is None:
            return 0
        return int(time.time() - self._start_time)

    # ─── Live capture (requires root + Scapy) ────────────────────────────────

    def _try_live_capture(self):
        from scapy.all import sniff, IP, TCP, UDP

        def process_packet(pkt):
            if not self._running:
                return
            if IP not in pkt:
                return

            raw = {
                "src_ip":    pkt[IP].src,
                "dst_ip":    pkt[IP].dst,
                "protocol":  "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER"),
                "size":      len(pkt),
                "timestamp": datetime.now().isoformat(),
                "flags":     str(pkt[TCP].flags) if TCP in pkt else "",
                "dst_port":  pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            }
            self._handle_packet(raw)

        sniff(prn=process_packet, store=False, stop_filter=lambda _: not self._running)

    # ─── Simulation mode ─────────────────────────────────────────────────────

    def _simulate_traffic(self):
        """Generate realistic IoT traffic patterns with occasional attacks."""
        attack_scenarios = [
            self._simulate_ddos,
            self._simulate_port_scan,
            self._simulate_data_exfil,
            self._simulate_botnet,
        ]

        attack_timer = 0
        attack_interval = random.randint(30, 60)  # inject attack every 30-60s

        while self._running:
            # Normal traffic burst
            burst = random.randint(1, 5)
            for _ in range(burst):
                pkt = self._generate_normal_packet()
                self._handle_packet(pkt)
                time.sleep(random.uniform(0.05, 0.3))

            attack_timer += burst * 0.2
            if attack_timer >= attack_interval:
                # Inject an attack scenario
                scenario = random.choice(attack_scenarios)
                scenario()
                attack_timer = 0
                attack_interval = random.randint(30, 60)

    def _generate_normal_packet(self):
        device = random.choice(self.iot_devices)
        ext_ip = random.choice(self.external_ips[:-2])  # avoid suspicious ones
        proto = random.choice(self.protocols)
        return {
            "src_ip":    device["ip"],
            "dst_ip":    ext_ip,
            "protocol":  proto,
            "size":      random.randint(64, 1500),
            "timestamp": datetime.now().isoformat(),
            "flags":     "PA",
            "dst_port":  self._port_for_protocol(proto),
            "device":    device["name"],
            "is_attack": False,
        }

    def _simulate_ddos(self):
        device = random.choice(self.iot_devices)
        target = "203.0.113.99"
        for _ in range(random.randint(20, 50)):
            if not self._running:
                break
            pkt = {
                "src_ip":    device["ip"],
                "dst_ip":    target,
                "protocol":  "UDP",
                "size":      random.randint(1000, 1500),
                "timestamp": datetime.now().isoformat(),
                "flags":     "",
                "dst_port":  80,
                "device":    device["name"],
                "attack_type": "DDoS",
                "is_attack": True,
            }
            self._handle_packet(pkt)
            time.sleep(0.05)

    def _simulate_port_scan(self):
        device = random.choice(self.iot_devices)
        target = random.choice(self.external_ips)
        for port in random.sample(range(1, 1024), 30):
            if not self._running:
                break
            pkt = {
                "src_ip":    device["ip"],
                "dst_ip":    target,
                "protocol":  "TCP",
                "size":      64,
                "timestamp": datetime.now().isoformat(),
                "flags":     "S",
                "dst_port":  port,
                "device":    device["name"],
                "attack_type": "Port Scan",
                "is_attack": True,
            }
            self._handle_packet(pkt)
            time.sleep(0.02)

    def _simulate_data_exfil(self):
        device = random.choice(self.iot_devices)
        suspicious_ip = "185.220.101.10"  # Tor exit
        for _ in range(random.randint(5, 15)):
            if not self._running:
                break
            pkt = {
                "src_ip":    device["ip"],
                "dst_ip":    suspicious_ip,
                "protocol":  "TCP",
                "size":      random.randint(5000, 65000),  # large payload
                "timestamp": datetime.now().isoformat(),
                "flags":     "PA",
                "dst_port":  9001,
                "device":    device["name"],
                "attack_type": "Data Exfiltration",
                "is_attack": True,
            }
            self._handle_packet(pkt)
            time.sleep(0.1)

    def _simulate_botnet(self):
        # Multiple devices suddenly communicating with same C&C
        cc_ip = "198.199.100.20"
        for device in random.sample(self.iot_devices, 3):
            if not self._running:
                break
            pkt = {
                "src_ip":    device["ip"],
                "dst_ip":    cc_ip,
                "protocol":  "TCP",
                "size":      random.randint(200, 600),
                "timestamp": datetime.now().isoformat(),
                "flags":     "PA",
                "dst_port":  6667,
                "device":    device["name"],
                "attack_type": "Botnet C&C",
                "is_attack": True,
            }
            self._handle_packet(pkt)
            time.sleep(0.15)

    # ─── Packet pipeline ─────────────────────────────────────────────────────

    def _handle_packet(self, raw_packet):
        """Full pipeline: log → extract features → detect anomaly → alert → broadcast."""
        self.packet_count += 1

        # Step 1: Log to DB
        packet_id = self.db_logger.log_packet(raw_packet)

        # Step 2: Extract features
        features = self.feature_extractor.extract(raw_packet)

        # Step 3: Anomaly detection
        is_anomaly, score, reason = self.anomaly_detector.predict(features, raw_packet)

        # Step 4: Alert if anomaly
        if is_anomaly:
            self.anomaly_count += 1
            alert = self.alert_manager.create_alert(
                packet=raw_packet,
                score=score,
                reason=reason
            )
            self.db_logger.log_alert(alert)
            self.socketio.emit('new_alert', alert)

        # Step 5: Broadcast to dashboard via WebSocket
        self.socketio.emit('new_packet', {
            "id":         packet_id,
            "src_ip":     raw_packet["src_ip"],
            "dst_ip":     raw_packet["dst_ip"],
            "protocol":   raw_packet["protocol"],
            "size":       raw_packet["size"],
            "timestamp":  raw_packet["timestamp"],
            "is_anomaly": is_anomaly,
            "score":      round(score, 4),
            "reason":     reason,
        })

    @staticmethod
    def _port_for_protocol(proto):
        mapping = {
            "HTTP": 80, "HTTPS": 443, "DNS": 53,
            "MQTT": 1883, "CoAP": 5683,
            "TCP": random.randint(1024, 65535),
            "UDP": random.randint(1024, 65535),
        }
        return mapping.get(proto, 80)
