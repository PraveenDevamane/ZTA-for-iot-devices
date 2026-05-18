# BAZTA — Complete Setup Guide

Behavioral Anomaly-based Zero Trust Architecture for securing IoT devices using:

* SDN (Software Defined Networking)
* OS-Ken Controller
* Mininet
* Open vSwitch
* Flask + SocketIO Dashboard
* Machine Learning Trust Engine

---

# Architecture

```text
IoT Devices (h1–h6)
        │
        ▼
┌────────────────────┐
│      Mininet       │
│   Open vSwitch     │
└─────────┬──────────┘
          │ OpenFlow
┌─────────┴──────────┐
│   OS-Ken Controller│
└─────────┬──────────┘
          │ REST API
┌─────────┴────────────────────┐
│ Flask + SocketIO Dashboard   │
│  Trust Engine + ML Model     │
└──────────────────────────────┘
```

---

# PART 1 — SYSTEM SETUP

## Step 1 — Update Ubuntu

```bash
sudo apt update && sudo apt upgrade -y
```

---

## Step 2 — Install Required System Packages

```bash
sudo apt install -y \
python3.10 \
python3.10-venv \
python3-pip \
mininet \
openvswitch-switch \
hping3 \
nmap \
unzip \
net-tools
```

---

## Step 3 — Verify Mininet

```bash
sudo mn --test pingall
```

Expected:

```text
0% dropped
```

---

# PART 2 — CREATE PYTHON VIRTUAL ENVIRONMENT

## Step 4 — Go to Home Directory

```bash
cd ~
```

---

---

## Step 6 — Create Python 3.10 Virtual Environment

```bash
python3.10 -m venv myenv
```

---

## Step 7 — Activate Environment

```bash
source ~/myenv/bin/activate
```

Expected:

```text
(myenv)
```

---

## Step 8 — Verify Python Version

```bash
python --version
```

Expected:

```text
Python 3.10.x
```

---

# PART 3 — PROJECT SETUP

## Step 9 — Go to Project Directory

```bash
cd /mnt/share/miniproject
```

---

# PART 4 — REQUIREMENTS FILES

## requirements.txt

Replace contents with:

```txt
flask==3.0.3
flask-socketio==5.3.6
python-socketio==5.11.2
python-engineio==4.9.1
eventlet==0.33.3
numpy==1.26.4
scikit-learn==1.5.2
joblib==1.4.2
pandas==2.2.3
```

---

## sdn/requirements-sdn.txt

Replace contents with:

```txt
os-ken==2.6.0
requests==2.32.3
```

---

# PART 5 — INSTALL PYTHON DEPENDENCIES

## Step 10 — Upgrade pip

```bash
pip install --upgrade pip
```

---

## Step 11 — Install Dashboard Dependencies

```bash
pip install -r requirements.txt
```

---

## Step 12 — Install SDN Dependencies

```bash
pip install -r sdn/requirements-sdn.txt
```

---

## Step 13 — Verify Installation

```bash
python -c "import flask, flask_socketio, sklearn, pandas, numpy, os_ken; print('ALL OK')"
```

Expected:

```text
ALL OK
```

---

# PART 6 — PROJECT CODE

The project source code is assumed to already contain the required fixes and updates.

Do all code edits inside your IDE before pushing to GitHub.

This setup guide only covers:

* Ubuntu VM setup
* Python virtual environment setup
* Dependency installation
* Running the services
* Mininet testing
* Attack simulation
* Troubleshooting runtime issues

---

# PART 7 — EXTRACT ML MODEL

## Step 20 — Extract Model Files

```bash
cd models
unzip live_if_model.zip
cd ..
```

---

## Step 21 — Verify ML Setup

```bash
python -c "from core import TrustEngine, FlowFeatureExtractor; print('Setup OK')"
```

Expected:

```text
Setup OK
```

---

# PART 9 — RUN THE PROJECT

You need 3 terminals.

---

# TERMINAL 1 — Flask Dashboard

```bash
cd /mnt/share/miniproject
source ~/myenv/bin/activate
python app.py
```

Expected:

```text
Running on http://0.0.0.0:5050
```

Open browser:

```text
http://127.0.0.1:5050
```

Dashboard should show:

```text
Connected
```

---

# TERMINAL 2 — OS-Ken Controller

```bash
cd /mnt/share/miniproject
source ~/myenv/bin/activate
python -m os_ken.cmd.manager sdn/bazta_osken_controller.py
```

Expected:

```text
Switch connected
```

---

# TERMINAL 3 — Mininet

## Clean Old Topology

```bash
sudo mn -c
```

---

## Start Topology

```bash
cd /mnt/share/miniproject
sudo python3 sdn/mininet_topo.py
```

Expected:

```text
mininet>
```

---

# PART 10 — TESTING

## Step 22 — Test Connectivity

Inside Mininet:

```bash
h1 ping -c 3 10.0.1.2
```

---

## Step 23 — ICMP Flood Attack

```bash
h1 bash scripts/attacks.sh icmp_flood 10.0.1.2
```

Expected:

* Trust score drops
* Dashboard alert appears
* Action becomes BLOCK

---

## Step 24 — Port Scan Attack

Fast scan:

```bash
h1 nmap -F 10.0.1.2
```

Full scan:

```bash
h1 bash scripts/attacks.sh port_scan 10.0.1.2
```

---

## Step 25 — Byte Flood Attack

```bash
h1 bash scripts/attacks.sh byte_flood 10.0.1.2
```

---

## Step 26 — Full Demo

```bash
h1 bash scripts/attacks.sh full_demo 10.0.1.2
```

Flow:

1. Normal traffic
2. ICMP flood
3. Port scan
4. Recovery

---

# PART 11 — STOP EVERYTHING

## Stop Mininet

```bash
sudo mn -c
```

---

## Stop Flask Dashboard

```bash
sudo pkill -f app.py
```

---

## Stop OS-Ken Controller

```bash
sudo pkill -f os_ken
```

---

# PROJECT STRUCTURE

```text
├── app.py
├── requirements.txt
├── setup.sh
│
├── core/
│   ├── trust_engine.py
│   ├── feature_extractor.py
│   └── acc91.ipynb
│
├── sdn/
│   ├── bazta_osken_controller.py
│   ├── mininet_topo.py
│   └── requirements-sdn.txt
│
├── models/
│   ├── live_if_model.pkl
│   ├── live_scaler.pkl
│   └── live_model_meta.json
│
├── scripts/
│   └── attacks.sh
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

---

# TROUBLESHOOTING

## Dashboard shows "Disconnected"

Make sure:

* app.py is running
* SocketIO versions match
* browser opened after Flask starts

---

## Mininet Cleanup

```bash
sudo mn -c
```

---

## Open vSwitch Restart

```bash
sudo systemctl restart openvswitch-switch
```

---

## Kill Stuck Processes

```bash
sudo pkill -f app.py
sudo pkill -f os_ken
sudo pkill -f mininet
```

---

# TECH STACK

* SDN Controller: OS-Ken
* Virtual Network: Mininet + Open vSwitch
* Dashboard: Flask + SocketIO
* ML Model: Isolation Forest
* Dataset: CICIoT2023
* Detection: Behavioral Anomaly Detection
