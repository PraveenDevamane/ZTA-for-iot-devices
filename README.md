# BAZTA — Zero Trust Architecture for IoT Devices

Behavioral Anomaly-based Zero Trust Architecture for securing campus IoT networks using SDN, machine learning, and real-time trust scoring.

---

## Architecture

```
IoT Devices (h1–h6)
    │
    ▼
┌──────────────┐
│   Mininet     │   Virtual campus network (3 microsegments)
│   OVS 1.3    │
└──────┬───────┘
       │  OpenFlow
┌──────┴───────────────┐
│   Ryu SDN Controller  │   Intercepts flows, installs block rules
└──────┬───────────────┘
       │  REST API
┌──────┴───────────────────────┐
│   Flask + SocketIO (app.py)   │
│   ├── Feature Extractor       │   Rolling window stats per IP
│   ├── Trust Engine + ML       │   Rule-based + Isolation Forest
│   └── WebSocket Dashboard     │   Real-time monitoring
└──────────────────────────────┘
```

---

## Prerequisites

- **OS:** Ubuntu 20.04 / 22.04 (required for Mininet + Ryu)
- **Python:** 3.8 or higher
- **System packages:** Mininet, Open vSwitch, hping3, nmap

Install system packages first:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 nmap python3-pip
```

---

## Setup (Step by Step)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/PraveenDevamane/ZTA-for-iot-devices.git
cd ZTA-for-iot-devices
```

### Step 2 — Install Dashboard Dependencies

```bash
pip install -r requirements.txt
```

This installs: Flask, Flask-SocketIO, NumPy, scikit-learn, joblib, pandas.

### Step 3 — Install SDN Controller Dependencies (Ryu)

> **Important:** Ryu requires an older version of setuptools. Run these commands **in this exact order:**

```bash
pip install "setuptools<74"
pip install -r sdn/requirements-sdn.txt
```

This installs: setuptools, eventlet 0.30.2, ryu 4.34, requests.

### Step 4 — Extract ML Models & Verify Setup

The pre-trained Isolation Forest model is compressed due to GitHub file size limits. Extract it before running the system:

```bash
cd models
unzip live_if_model.zip
cd ..
```

Then verify the TrustEngine loads it correctly:

```bash
python -c "from core import TrustEngine, FlowFeatureExtractor; print('Setup OK')"
```

*(The ML model is already pre-trained on Kaggle using the CICIoT2023 dataset.)*

If this prints `Setup OK`, everything is installed correctly.

---

## Running the Project (3 Terminals)

### Terminal 1 — Start the Dashboard + Trust Engine

```bash
python app.py
```

You should see:

```
============================================================
  BAZTA — Zero Trust IoT Security Dashboard
============================================================
  Dashboard  :  http://0.0.0.0:5050
  Trust API  :  POST http://0.0.0.0:5050/score_flow
  ✓ ML Model loaded
  ✓ Scaler loaded
============================================================
```

Open **http://localhost:5050** in your browser to see the dashboard.

### Terminal 2 — Start the Ryu SDN Controller

```bash
ryu-manager sdn/bazta_ryu_controller.py
```

### Terminal 3 — Start the Mininet Network

```bash
sudo python sdn/mininet_topo.py
```

You should see the Mininet CLI prompt: `mininet>`

---

## Demo Attacks (Run in Mininet CLI)

Once all 3 terminals are running:

```bash
# Test normal connectivity
mininet> pingall

# Full attack demo (normal → ICMP flood → port scan → recovery)
mininet> h1 bash scripts/attacks.sh full_demo 10.0.1.2

# Individual attacks
mininet> h1 bash scripts/attacks.sh icmp_flood 10.0.1.2
mininet> h1 bash scripts/attacks.sh port_scan 10.0.1.2
mininet> h1 bash scripts/attacks.sh byte_flood 10.0.1.2
```

Watch the dashboard at **http://localhost:5050** — you'll see trust scores drop, attacks detected, and hosts getting blocked in real time.

---

## One-Shot Setup (Alternative)

If you prefer a single command:

```bash
bash setup.sh
```

This installs dependencies and verifies the setup automatically. You still need to install Ryu separately (Step 3).

---

## Project Structure

```
├── app.py                       # Flask + SocketIO server (main entry point)
├── setup.sh                     # One-shot setup script
├── requirements.txt             # Dashboard dependencies
│
├── core/                        # Trust scoring pipeline
│   ├── trust_engine.py          # Rule-based + ML anomaly scoring
│   ├── feature_extractor.py     # Per-IP rolling window features
│   └── acc91.ipynb              # Kaggle notebook used for model training
│
├── sdn/                         # SDN components
│   ├── bazta_ryu_controller.py  # Ryu OpenFlow 1.3 controller
│   ├── mininet_topo.py          # Campus IoT network topology
│   └── requirements-sdn.txt    # Ryu + eventlet dependencies
│
├── models/                      # Trained ML models
│   ├── live_if_model.pkl        # Live Isolation Forest (4 features)
│   ├── live_scaler.pkl          # StandardScaler for live model
│   └── live_model_meta.json     # Model metadata + metrics
│
├── scripts/                     # Automation & testing
│   └── attacks.sh               # Attack simulation scripts for Mininet
│
├── templates/index.html         # Dashboard HTML
└── static/style.css             # Dashboard CSS
```

---

## ML Models (CICIoT2023 Dataset)

The anomaly detection model was trained on the CICIoT2023 dataset using Kaggle (see `core/acc91.ipynb` for the training notebook). The dataset provides modern IoT network traffic scenarios, including various DoS and DDoS attacks.

| Model              | Accuracy | Precision | Recall  | F1 Score | Type                |
|--------------------|----------|-----------|---------|----------|---------------------|
| Isolation Forest   | 91.28%   | 99.87%    | 91.20%  | 95.33%   | Unsupervised        |

The **live model** is deployed in `models/live_if_model.pkl` and evaluates 4 real-time extracted flow features to generate a trust score.

---

## Detection Capabilities

| Attack          | Feature         | Threshold   | Penalty | Action      |
|-----------------|-----------------|-------------|---------|-------------|
| ICMP Flood      | `pkt_rate`      | > 90 pps    | −50     | BLOCK       |
| Port Scan       | `unique_ports`  | > 20 / 30s  | −40     | BLOCK       |
| High Entropy    | `port_entropy`  | > 3.5       | −20     | RATE_LIMIT  |
| Byte Flood      | `byte_rate`     | > 50 KB/s   | −30     | BLOCK       |
| ML Anomaly      | Isolation Forest| score < −0.1| −30     | BLOCK       |

**Trust Score Actions:**

| Score Range | Action     | Description               |
|-------------|------------|---------------------------|
| ≥ 70        | ALLOW      | Normal traffic             |
| 30 – 70     | RATE_LIMIT | Suspicious, limit traffic  |
| < 30        | BLOCK      | Malicious, drop all packets|

---

## Troubleshooting

### `ryu` installation fails with `get_script_args` error

```bash
# Fix: Install older setuptools FIRST
pip install "setuptools<74"
pip install ryu==4.34
```

### `eventlet.wsgi.ALREADY_HANDLED` error when running Ryu

```bash
# Fix: Use the pinned eventlet version
pip install eventlet==0.30.2
```

### `ModuleNotFoundError: No module named 'core'`

Make sure you are running commands from the project root directory:

```bash
cd ZTA-for-iot-devices
python app.py
```

### Dashboard shows "Disconnected"

Make sure `app.py` is running in Terminal 1 before opening the browser.

---

## Tech Stack

- **SDN Controller:** Ryu (OpenFlow 1.3)
- **Virtual Network:** Mininet + Open vSwitch
- **Trust Engine:** Python (rule-based + scikit-learn Isolation Forest)
- **ML Models:** Isolation Forest
- **Dataset:** CICIoT2023
- **Dashboard:** Flask + SocketIO + Vanilla JS (WebSocket real-time)
