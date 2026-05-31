import pickle, os, json
import numpy as np
import warnings

# Suppress sklearn/joblib unpickling and feature name warnings
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=UserWarning, module="joblib")

from sklearn.ensemble import IsolationForest

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False



RECOVERY_RATE = 0.08    # trust recovers gradually on benign traffic
BASE          = 100.0   # starting trust

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

# Feature order for the ML model (must match training script)
LIVE_FEATURES = ["pkt_rate", "byte_rate", "unique_ports", "port_entropy"]


class TrustEngine:
    def __init__(self, model_path=None, models_dir=None):
        self._scores = {}           # {src_ip: float}
        self._model  = None
        self._scaler = None
        self._model_meta = None
        self._stats  = {"total_flows": 0, "blocks": 0, "rate_limits": 0,
                        "icmp_flood": 0, "port_scan": 0,
                        "high_entropy": 0, "byte_flood": 0, "ml_anomaly": 0}

        # Determine models directory
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "models")

        
        self._load_model_pipeline(models_dir, model_path)

    def _load_model_pipeline(self, models_dir, legacy_model_path=None):
        """
        Load live_if_model.pkl and live_scaler.pkl from models_dir.
        """
        live_model_path = os.path.join(models_dir, "live_if_model.pkl")
        live_scaler_path = os.path.join(models_dir, "live_scaler.pkl")
        self._scaler = None
        self._model_meta = None

        if os.path.exists(live_model_path):
            try:
                import joblib
                self._model = joblib.load(live_model_path)
                print(f"[TrustEngine] Loaded model: {live_model_path}")
                
                if os.path.exists(live_scaler_path):
                    self._scaler = joblib.load(live_scaler_path)
                    print(f"[TrustEngine] Loaded scaler: {live_scaler_path}")
                else:
                    print("[TrustEngine] WARNING: live_scaler.pkl not found — IF predictions will be wrong")

                # Check for metadata
                live_meta_path = os.path.join(models_dir, "live_model_meta.json")
                if os.path.exists(live_meta_path):
                    with open(live_meta_path) as f:
                        self._model_meta = json.load(f)
                return
            except Exception as e:
                print(f"[TrustEngine] Warning: Failed to load model: {e}")

        print("[TrustEngine] No ML model loaded — using rule-based detection only")


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

        triggered = []

        # 1. Rule-based checks (fast, O(n_rules))
        is_response = features.get("is_response", False)
        if not is_response:
            for feat, op, threshold, label, penalty in RULES:
                val = features.get(feat, 0)
                hit = (val > threshold  if op == ">" else
                       val < threshold  if op == "<" else False)
                if hit:
                    score += penalty
                    triggered.append(label)

       
        ml_label = "normal"
        if self._model and not is_response:
            vec = np.array([[
                features.get("pkt_rate", 0),
                features.get("byte_rate", 0),
                features.get("unique_ports", 0),
                features.get("port_entropy", 0),
            ]], dtype=np.float64)

            # Always scale if scaler exists — no pandas dependency
            if self._scaler is not None:
                vec = self._scaler.transform(vec)

            # decision_function: negative = anomalous, positive = normal
            ml_score = self._model.decision_function(vec)[0]
            if ml_score < -0.26:
                score -= 30
                ml_label = f"ml_anomaly({ml_score:.3f})"
                triggered.append(ml_label)


        if not triggered:
            score += (BASE - score) * RECOVERY_RATE

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

    def get_model_info(self) -> dict:
        """Return info about the loaded ML model for the dashboard."""
        if self._model_meta:
            return {
                "model_type": self._model_meta.get("model_type", "IsolationForest"),
                "features": self._model_meta.get("live_feature_names", LIVE_FEATURES),
                "accuracy": self._model_meta.get("accuracy", 0),
                "precision": self._model_meta.get("precision", 0),
                "recall": self._model_meta.get("recall", 0),
                "f1_score": self._model_meta.get("f1_score", 0),
                "training_samples": self._model_meta.get("training_samples", 0),
                "dataset": self._model_meta.get("dataset", "unknown"),
                "has_scaler": self._scaler is not None,
                "loaded": True,
            }
        return {
            "model_type": "IsolationForest" if self._model else "none",
            "features": LIVE_FEATURES,
            "has_scaler": self._scaler is not None,
            "loaded": self._model is not None,
            "legacy": False,
        }

    @staticmethod
    def _action(score: float) -> str:
        if score >= 70: return "ALLOW"
        if score >= 30: return "RATE_LIMIT"
        return "BLOCK"
