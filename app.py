"""
BAZTA Lightweight SDN Dashboard — app.py
========================================
Flask + SocketIO backend that:
  1. Exposes POST /score_flow  (called by Ryu controller — backward-compatible)
  2. Pushes real-time events to the web dashboard via WebSocket
  3. Serves the monitoring dashboard at GET /
"""

import eventlet
eventlet.monkey_patch()

import warnings
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=UserWarning, module="joblib")

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from core import FlowFeatureExtractor, TrustEngine

import time, json, os

# ── App setup ───────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "bazta-iot-2026"
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

extractor = FlowFeatureExtractor(window_sec=30)
engine    = TrustEngine(models_dir=os.path.join(BASE_DIR, "models"))

# Track recent events for the dashboard feed (ring buffer)
_event_log = []
MAX_EVENTS = 200


# ── Dashboard page ──────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/logs")
def logs():
    return render_template("logs.html")


# ── REST API (called by Ryu controller) ─────────────────────────────────
@app.route("/score_flow", methods=["POST"])
def score_flow():
    """
    Ryu controller calls this per new flow.
    Payload: { src_ip, dst_ip, proto, port, packets,
               bytes, duration, pkt_rate, byte_rate }
    """
    flow     = request.json
    features = extractor.extract(flow)
    result   = engine.update(features)

    # Build event for dashboard
    event = {
        "timestamp": time.time(),
        "src_ip":    result["src_ip"],
        "dst_ip":    flow.get("dst_ip", ""),
        "proto":     flow.get("proto", 0),
        "port":      flow.get("port"),
        "score":     result["trust_score"],
        "action":    result["action"],
        "triggered": result["triggered"],
        "pkt_rate":  features.get("pkt_rate", 0),
        "byte_rate": features.get("byte_rate", 0),
        "unique_ports": features.get("unique_ports", 0),
        "port_entropy": features.get("port_entropy", 0),
    }

    # Store in ring buffer
    _event_log.append(event)
    if len(_event_log) > MAX_EVENTS:
        _event_log.pop(0)

    # Push to dashboard via WebSocket
    socketio.emit("flow_update", event)

    if result["action"] == "BLOCK":
        socketio.emit("block_event", {
            "src_ip": result["src_ip"],
            "score":  result["trust_score"],
            "triggered": result["triggered"],
            "timestamp": time.time(),
        })

    return jsonify(result)


# ── REST endpoints for dashboard ────────────────────────────────────────
@app.route("/scores", methods=["GET"])
def all_scores():
    return jsonify(engine._scores)


@app.route("/stats", methods=["GET"])
def stats():
    s = engine.get_stats()
    s["active_hosts"] = len(engine._scores)
    s["avg_score"]    = round(
        sum(engine._scores.values()) / max(len(engine._scores), 1), 1
    )
    return jsonify(s)


@app.route("/events", methods=["GET"])
def events():
    """Return recent events for initial dashboard load."""
    return jsonify(_event_log[-50:])


@app.route("/all_events", methods=["GET"])
def all_events():
    """Return all stored events for the logs page."""
    return jsonify(_event_log)


@app.route("/model_info", methods=["GET"])
def model_info():
    """Return info about the loaded ML model and all model comparison data."""
    info = engine.get_model_info()

    # Add comparison data — trained on CICIoT2023 (WATAI) dataset
    # Metrics below are placeholders; update after running train_model.ipynb
    info["comparison"] = {
        "isolation_forest": {
            "name": "Isolation Forest",
            "accuracy": info.get("accuracy", 0),
            "precision": info.get("precision", 0),
            "recall": info.get("recall", 0),
            "f1_score": info.get("f1_score", 0),
            "type": "Unsupervised",
            "description": "Tree-based anomaly detection on CICIoT2023, lightweight for IoT"
        },
        "logistic_regression_34": {
            "name": "LogisticRegression (34 classes)",
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "type": "Supervised",
            "description": "Multi-class classification on CICIoT2023 (update after training)"
        },
        "logistic_regression_2": {
            "name": "LogisticRegression (2 classes)",
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "type": "Supervised",
            "description": "Binary classification on CICIoT2023 (update after training)"
        }
    }
    return jsonify(info)


@app.route("/reset", methods=["POST"])
def reset():
    """Reset all state for a fresh run."""
    extractor.reset()
    engine.reset()
    _event_log.clear()
    socketio.emit("reset")
    return jsonify({"status": "ok"})


# ── WebSocket handlers ──────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    """Send current state when dashboard connects."""
    socketio.emit("init", {
        "scores": engine._scores,
        "stats":  engine.get_stats(),
        "events": _event_log[-30:],
    })


# ── Main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    model_info_data = engine.get_model_info()
    model_status = "✓ ML Model loaded" if model_info_data.get("loaded") else "✗ No ML model (rule-based only)"
    scaler_status = "✓ Scaler loaded" if model_info_data.get("has_scaler") else "✗ No scaler"

    print("\n" + "=" * 60)
    print("  BAZTA — Zero Trust IoT Security Dashboard")
    print("=" * 60)
    print(f"  Dashboard  :  http://0.0.0.0:5050")
    print(f"  Trust API  :  POST http://0.0.0.0:5050/score_flow")
    print(f"  Model Info :  GET  http://0.0.0.0:5050/model_info")
    print(f"  {model_status}")
    print(f"  {scaler_status}")
    print("=" * 60 + "\n")
    socketio.run(app, host="0.0.0.0", port=5050, debug=False,
                 allow_unsafe_werkzeug=True)
