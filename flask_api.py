from flask import Flask, request, jsonify
from feature_extractor import FlowFeatureExtractor
from trust_engine import TrustEngine

app = Flask(__name__)
extractor = FlowFeatureExtractor(window_sec=30)
engine    = TrustEngine(model_path="if_model.pkl")

@app.route("/score_flow", methods=["POST"])
def score_flow():
    """
    os-ken calls this per new flow.
    Payload: { src_ip, dst_ip, proto, port, packets,
               bytes, duration, pkt_rate, byte_rate }
    """
    flow     = request.json
    features = extractor.extract(flow)
    result   = engine.update(features)
    return jsonify(result)

@app.route("/scores", methods=["GET"])
def all_scores():
    return jsonify(engine._scores)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)