import pickle, os
import numpy as np
from sklearn.ensemble import IsolationForest

DECAY   = 0.95    # trust recovers slowly when benign
BASE    = 100.0   # starting trust

# Thresholds tuned from YOUR data:
#   - Normal ICMP pairs: ~18 pps  → flood threshold = 5× = 90 pps (conservative)
#     Your 10.0.0.1↔10.0.0.2 ICMP is at 697 pps — extreme outlier
#   - Normal port touches: 1–3 per pair → scan threshold = 20 unique ports/30s
RULES = [
    # (feature, operator, threshold, label, penalty)
    ("pkt_rate",     ">",  90,   "icmp_flood",    -50),
    ("unique_ports", ">",  20,   "port_scan",     -40),
    ("port_entropy", ">",  3.5,  "high_entropy",  -20),
    ("byte_rate",    ">",  50000,"byte_flood",    -30),
]

class TrustEngine:
    def __init__(self, model_path="if_model.pkl"):
        self._scores = {}           # {src_ip: float}
        self._model  = None
        self._stats  = {"total_flows": 0, "blocks": 0, "rate_limits": 0,
                        "icmp_flood": 0, "port_scan": 0,
                        "high_entropy": 0, "byte_flood": 0, "ml_anomaly": 0}
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)

    # ── offline training (run once on your InSDN dataset) ──────────────
    @staticmethod
    def train_isolation_forest(X: np.ndarray, path="if_model.pkl",
                               contamination=0.05):
        """
        X columns: [pkt_rate, byte_rate, unique_ports, port_entropy]
        contamination ≈ expected attack fraction in training data
        """
        clf = IsolationForest(
            n_estimators=50,        # keep small for IoT inference speed
            max_samples=256,        # subsample for memory
            contamination=contamination,
            random_state=42
        )
        clf.fit(X)
        with open(path, "wb") as f:
            pickle.dump(clf, f)
        print(f"Trained IF: {len(X)} samples → {path}")
        return clf

    # ── per-flow scoring ────────────────────────────────────────────────
    def update(self, features: dict) -> dict:
        src = features["src_ip"]
        score = self._scores.get(src, BASE)

        # Decay toward zero (trust erodes with every cycle if not earned)
        score *= DECAY

        triggered = []

        # 1. Rule-based checks (fast, O(n_rules))
        for feat, op, threshold, label, penalty in RULES:
            val = features.get(feat, 0)
            hit = (val > threshold  if op == ">" else
                   val < threshold  if op == "<" else False)
            if hit:
                score += penalty
                triggered.append(label)

        # 2. ML anomaly score (only if model loaded)
        ml_label = "normal"
        if self._model:
            vec = np.array([[
                features["pkt_rate"],
                features["byte_rate"],
                features["unique_ports"],
                features["port_entropy"],
            ]])
            # decision_function: negative = anomalous, positive = normal
            ml_score = self._model.decision_function(vec)[0]
            if ml_score < -0.1:
                score -= 30
                ml_label = f"ml_anomaly({ml_score:.3f})"
                triggered.append(ml_label)

        score = max(0.0, min(100.0, score))
        self._scores[src] = score

        action = self._action(score)

        # Update stats
        self._stats["total_flows"] += 1
        if action == "BLOCK":
            self._stats["blocks"] += 1
        elif action == "RATE_LIMIT":
            self._stats["rate_limits"] += 1
        for t in triggered:
            key = t.split("(")[0]   # strip ml_anomaly(...) → ml_anomaly
            if key in self._stats:
                self._stats[key] += 1

        return {
            "src_ip":     src,
            "trust_score": round(score, 2),
            "triggered":  triggered,
            "action":     action,
        }

    def reset(self):
        """Clear all trust scores and stats for a fresh run."""
        self._scores.clear()
        for k in self._stats:
            self._stats[k] = 0

    def get_stats(self) -> dict:
        """Return detection statistics for the dashboard."""
        return dict(self._stats)

    @staticmethod
    def _action(score: float) -> str:
        if score >= 70: return "ALLOW"
        if score >= 30: return "RATE_LIMIT"
        return "BLOCK"