# BAZTA — Zero Trust Architecture for IoT Devices

Behavioral Anomaly-based Zero Trust Architecture for securing campus IoT networks using SDN, machine learning, and real-time trust scoring.

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

## Project Structure

```
├── app.py                       # Main entry — Flask + SocketIO server
├── requirements.txt             # Python dependencies
│
├── core/                        # Trust scoring pipeline
│   ├── trust_engine.py          # Rule-based + ML anomaly scoring
│   └── feature_extractor.py     # Per-IP rolling window features
│
├── sdn/                         # SDN components (run on Linux VM)
│   ├── bazta_ryu_controller.py  # Ryu OpenFlow 1.3 controller
│   └── mininet_topo.py          # Campus IoT network topology
│
├── models/                      # Machine learning
│   ├── if_model.pkl             # Trained Isolation Forest model
│   └── train_model.ipynb        # Training notebook
│
├── data/                        # Network flow data
│   └── flow.txt                 # Captured flow records
│
├── scripts/                     # Demo & testing
│   └── attacks.sh               # Attack simulation scripts
│
├── templates/                   # Dashboard HTML
│   └── index.html
│
└── static/                      # Dashboard CSS
    └── style.css
```

## Detection Capabilities

| Attack          | Feature         | Threshold   | Penalty |
|-----------------|-----------------|-------------|---------|
| ICMP Flood      | `pkt_rate`      | > 90 pps    | −50     |
| Port Scan       | `unique_ports`  | > 20 / 30s  | −40     |
| High Entropy    | `port_entropy`  | > 3.5       | −20     |
| Byte Flood      | `byte_rate`     | > 50 KB/s   | −30     |
| ML Anomaly      | Isolation Forest| score < −0.1| −30     |

**Trust Actions:** Score ≥ 70 → ALLOW · 30–70 → RATE_LIMIT · < 30 → BLOCK

## Quick Start

### Prerequisites

- **Ubuntu 20.04/22.04** (Mininet requires Linux)
- Python 3.8+
- Mininet, hping3, nmap

```bash
sudo apt install -y mininet hping3 nmap python3-pip
```

### Install

```bash
git clone https://github.com/PraveenDevamane/ZTA-for-iot-devices.git
cd ZTA-for-iot-devices
pip3 install ryu -r requirements.txt
```

### Run (3 Terminals)

```bash
# Terminal 1: Trust Engine + Dashboard
python3 app.py

# Terminal 2: Ryu SDN Controller
ryu-manager sdn/bazta_ryu_controller.py

# Terminal 3: Mininet Campus Network
sudo python3 sdn/mininet_topo.py
```

Open **http://localhost:5050** for the real-time dashboard.

### Demo Attacks (in Mininet CLI)

```bash
mininet> pingall                                    # Normal traffic
mininet> h1 bash scripts/attacks.sh full_demo 10.0.1.2   # Full attack scenario
mininet> h1 bash scripts/attacks.sh icmp_flood 10.0.1.2   # ICMP flood only
mininet> h1 bash scripts/attacks.sh port_scan 10.0.1.2    # Port scan only
```

## Tech Stack

- **SDN Controller:** Ryu (OpenFlow 1.3)
- **Virtual Network:** Mininet + Open vSwitch
- **Trust Engine:** Python (rule-based + scikit-learn Isolation Forest)
- **Dashboard:** Flask + SocketIO + Vanilla JS
- **ML Training:** Jupyter Notebook + pandas
