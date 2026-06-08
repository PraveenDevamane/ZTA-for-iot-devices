import os
import sys
import numpy as np
import joblib

models_dir = "/Users/praveenkumardevamane/Downloads/miniproject/models"
model_path = os.path.join(models_dir, "live_if_model.pkl")
scaler_path = os.path.join(models_dir, "live_scaler.pkl")

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

scenarios = [
    {"name": "Benign Traffic", "pkt_rate": 10.0, "byte_rate": 1500.0, "proto": 6.0, "pkt_size_variance": 500.0},
    {"name": "Case A: Stealthy Flooding", "pkt_rate": 80.0, "byte_rate": 45000.0, "proto": 6.0, "pkt_size_variance": 100.0},
    {"name": "Case B: Covert Channel", "pkt_rate": 15.0, "byte_rate": 5000.0, "proto": 17.0, "pkt_size_variance": 900000.0},
    {"name": "Case C: Atypical Proto", "pkt_rate": 5.0, "byte_rate": 400.0, "proto": 47.0, "pkt_size_variance": 10.0},
    {"name": "Case D: High-Payload Exfil", "pkt_rate": 35.0, "byte_rate": 48000.0, "proto": 6.0, "pkt_size_variance": 50000.0}
]

print("Model decision threshold in code: -0.26\n")

for s in scenarios:
    vec = np.array([[s["pkt_rate"], s["byte_rate"], float(s["proto"]), s["pkt_size_variance"]]], dtype=np.float64)
    scaled_vec = scaler.transform(vec)
    score = model.decision_function(scaled_vec)[0]
    pred = model.predict(scaled_vec)[0]
    print(f"=== {s['name']} ===")
    print(f"  Raw: {vec[0]}")
    print(f"  Scaled: {scaled_vec[0]}")
    print(f"  Decision Score: {score:.6f}")
    print(f"  Predict (1=benign, -1=anomaly): {pred}")
