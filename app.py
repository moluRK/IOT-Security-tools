"""
IoT Security Tool - Main Application
Author: Moluram Kushwaha (B2455R10175010)
AKS University, Satna
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import json
import os
from datetime import datetime

from modules.traffic_monitor import TrafficMonitor
from modules.data_logger import DataLogger
from modules.feature_extractor import FeatureExtractor
from modules.anomaly_detector import AnomalyDetector
from modules.alert_manager import AlertManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'iot-security-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize modules
db_logger = DataLogger(db_path="logs/traffic.db")
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector()
alert_manager = AlertManager(db_logger)
traffic_monitor = TrafficMonitor(
    db_logger=db_logger,
    feature_extractor=feature_extractor,
    anomaly_detector=anomaly_detector,
    alert_manager=alert_manager,
    socketio=socketio
)

monitoring_thread = None
is_monitoring = False


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/stats')
def api_stats():
    stats = db_logger.get_stats()
    return jsonify(stats)


@app.route('/api/packets')
def api_packets():
    limit = request.args.get('limit', 50, type=int)
    packets = db_logger.get_recent_packets(limit=limit)
    return jsonify(packets)


@app.route('/api/alerts')
def api_alerts():
    limit = request.args.get('limit', 20, type=int)
    alerts = alert_manager.get_alerts(limit=limit)
    return jsonify(alerts)


@app.route('/api/traffic/chart')
def api_traffic_chart():
    data = db_logger.get_traffic_over_time()
    return jsonify(data)


@app.route('/api/protocol/distribution')
def api_protocol_dist():
    data = db_logger.get_protocol_distribution()
    return jsonify(data)


@app.route('/api/top/ips')
def api_top_ips():
    data = db_logger.get_top_ips(limit=10)
    return jsonify(data)


@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    global monitoring_thread, is_monitoring
    if not is_monitoring:
        is_monitoring = True
        monitoring_thread = threading.Thread(
            target=traffic_monitor.start, daemon=True
        )
        monitoring_thread.start()
        return jsonify({"status": "started", "message": "Traffic monitoring started"})
    return jsonify({"status": "already_running", "message": "Monitor already active"})


@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    global is_monitoring
    if is_monitoring:
        traffic_monitor.stop()
        is_monitoring = False
        return jsonify({"status": "stopped", "message": "Traffic monitoring stopped"})
    return jsonify({"status": "not_running", "message": "Monitor was not running"})


@app.route('/api/monitor/status')
def monitor_status():
    return jsonify({
        "is_monitoring": is_monitoring,
        "packets_captured": traffic_monitor.packet_count,
        "anomalies_detected": traffic_monitor.anomaly_count,
        "uptime": traffic_monitor.get_uptime()
    })


@app.route('/api/train', methods=['POST'])
def train_model():
    """Train anomaly detection model on existing data"""
    result = anomaly_detector.train(db_logger)
    return jsonify(result)


# ─── SocketIO events ──────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    emit('status', {'message': 'Connected to IoT Security Dashboard'})


@socketio.on('request_stats')
def handle_stats_request():
    stats = db_logger.get_stats()
    emit('stats_update', stats)


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    db_logger.init_db()
    anomaly_detector.load_or_create_model()
    print("\n" + "="*55)
    print("  IoT Security Tool - Smart Gateway Dashboard")
    print("  AKS University | Moluram Kushwaha")
    print("  Running at: http://localhost:5000")
    print("="*55 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
