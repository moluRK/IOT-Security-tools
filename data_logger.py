"""
Module 2: Data Logging
Stores all traffic data, alerts, and statistics in SQLite.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from collections import defaultdict
import os


class DataLogger:
    def __init__(self, db_path="logs/traffic.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS packets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    protocol    TEXT,
                    size        INTEGER,
                    timestamp   TEXT,
                    flags       TEXT,
                    dst_port    INTEGER,
                    device      TEXT,
                    is_attack   INTEGER DEFAULT 0,
                    attack_type TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    protocol    TEXT,
                    severity    TEXT,
                    reason      TEXT,
                    score       REAL,
                    attack_type TEXT,
                    resolved    INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_packets_ts  ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(timestamp);
            """)
        print("[DataLogger] Database initialized.")

    # ─── Write ───────────────────────────────────────────────────────────────

    def log_packet(self, pkt: dict) -> int:
        with self._conn() as conn:
            cur = conn.execute("""
                INSERT INTO packets
                    (src_ip, dst_ip, protocol, size, timestamp, flags, dst_port, device, is_attack, attack_type)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                pkt.get("src_ip", ""),
                pkt.get("dst_ip", ""),
                pkt.get("protocol", ""),
                pkt.get("size", 0),
                pkt.get("timestamp", datetime.now().isoformat()),
                pkt.get("flags", ""),
                pkt.get("dst_port", 0),
                pkt.get("device", "Unknown"),
                1 if pkt.get("is_attack") else 0,
                pkt.get("attack_type", ""),
            ))
            return cur.lastrowid

    def log_alert(self, alert: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO alerts
                    (timestamp, src_ip, dst_ip, protocol, severity, reason, score, attack_type)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                alert.get("timestamp", datetime.now().isoformat()),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                alert.get("protocol", ""),
                alert.get("severity", "MEDIUM"),
                alert.get("reason", ""),
                alert.get("score", 0.0),
                alert.get("attack_type", ""),
            ))

    # ─── Read ────────────────────────────────────────────────────────────────

    def get_recent_packets(self, limit=50):
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM packets ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        with self._conn() as conn:
            total_packets = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            anomaly_count = conn.execute("SELECT COUNT(*) FROM packets WHERE is_attack=1").fetchone()[0]
            unique_ips    = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM packets").fetchone()[0]
            last_packet   = conn.execute("SELECT timestamp FROM packets ORDER BY id DESC LIMIT 1").fetchone()

        return {
            "total_packets":  total_packets,
            "total_alerts":   total_alerts,
            "anomaly_count":  anomaly_count,
            "unique_ips":     unique_ips,
            "last_packet_ts": last_packet[0] if last_packet else None,
            "clean_packets":  total_packets - anomaly_count,
        }

    def get_traffic_over_time(self, minutes=30):
        """Returns packet count bucketed per minute for the last N minutes."""
        since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT substr(timestamp, 1, 16) as minute, COUNT(*) as count
                FROM packets
                WHERE timestamp >= ?
                GROUP BY minute
                ORDER BY minute ASC
            """, (since,)).fetchall()
        return [{"time": r[0], "count": r[1]} for r in rows]

    def get_protocol_distribution(self):
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT protocol, COUNT(*) as count
                FROM packets
                GROUP BY protocol
                ORDER BY count DESC
            """).fetchall()
        return [{"protocol": r[0], "count": r[1]} for r in rows]

    def get_top_ips(self, limit=10):
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT src_ip, COUNT(*) as count,
                       SUM(is_attack) as attacks
                FROM packets
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [{"ip": r[0], "count": r[1], "attacks": r[2]} for r in rows]

    def get_all_packets_for_training(self):
        """Returns all packets as dicts for model training."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM packets").fetchall()
        return [dict(r) for r in rows]
