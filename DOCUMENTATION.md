# BAZTA: Behavioral Anomaly-based Zero Trust Architecture

## 1. Project Overview
BAZTA is a Software-Defined Networking (SDN) based Zero Trust security framework designed to protect Campus IoT networks from lateral movement attacks. It eschews static firewalls and IP whitelists in favor of continuously evaluating device behavior in real-time. By assigning a dynamically calculated **Trust Score**, BAZTA autonomously isolates compromised devices before they can affect the broader network.

## 2. Architecture & Components

The architecture runs on three interacting planes:

### A. Data Plane (Mininet Simulation)
- **Environment:** Open vSwitch / Mininet (`sdn/mininet_topo.py`)
- **Topology:** 1 Core Switch connected to 3 Micro-segment Switches. Each segment manages 2 IoT end-hosts (h1-h6).
- **Communication:** Uses OpenFlow 1.3.

### B. Control Plane (SDN Controller)
- **Framework:** OS-Ken (a modern Python fork of Ryu) (`sdn/bazta_osken_controller.py`)
- **Role:** 
  1. Intercepts `PacketIn` events for unknown network flows.
  2. Parses packet headers and forwards payload data to the Trust Engine API.
  3. Receives mitigation directives (`ALLOW`, `RATE_LIMIT`, `BLOCK`) and installs OpenFlow flow rules dynamically on the switches.

### C. Application Plane (Trust Engine & Flask Dashboard)
- **Modules:** `app.py`, `core/trust_engine.py`, `core/feature_extractor.py`
- **Role:** Maintains a 30-second rolling window per IP to extract traffic metrics (e.g., packet rate, port entropy). Uses a hybrid engine combining static rules and a Machine Learning model to calculate trust points and decide mitigation actions.

---

## 3. Trust Scoring Metrics & Heuristics

The heart of BAZTA is the dynamically calculated Trust Score. The system applies continuous zero-trust decay and strict penalties for abnormal metrics.

* **Base Score:** Every new IP starts at a baseline of `100.0`.
* **Zero-Trust Decay:** As a fundamental Zero Trust principle, trust decays over time. The score is multiplied by `0.95` at every update cycle, meaning a device must continuously exhibit benign behavior to maintain standing.

### Detailed Anomaly Penalties
If the extracted flow features breach predefined thresholds, immediate point deductions are applied:

| Attack Type / Anomaly | Trigger Condition | Penalty Applied |
| :--- | :--- | :--- |
| **ICMP / Packet Flood** | `pkt_rate > 90` pkts/sec | **-50 points** |
| **Port Scan** | `unique_ports > 20` | **-40 points** |
| **Volumetric / Byte Flood** | `byte_rate > 50000` bytes/sec | **-30 points** |
| **High Port Entropy** | `port_entropy > 3.5` | **-20 points** |
| **ML Anomaly Detection** | Isolation Forest output = Outlier | **-30 points** |

### Network Actions based on Trust Score
The accumulated trust score translates directly into automated SDN actions:

* 🟢 **ALLOW (Score ≥ 70):** The traffic is deemed benign. The SDN controller permits the packet flow.
* 🟡 **RATE_LIMIT (Score 30 - 69):** Suspicious behavior is flagged. The controller applies QoS/Meter tables to rate-limit the device's traffic throughput.
* 🔴 **BLOCK (Score < 30):** The device is deemed compromised. A hard OpenFlow `DROP` rule is installed, entirely isolating the node from lateral movement.

---

## 4. Machine Learning Pipeline & Model Metrics

Alongside static heuristics, BAZTA leverages an **Isolation Forest** model to detect subtle, multi-dimensional anomalies that rule-based systems might miss. Isolation Forest was chosen for its lightweight footprint, making it ideal for edge IoT environments.

### Dataset & Feature Selection
- **Dataset:** CICIoT2023 dataset (WATAI distribution).
- **Scale:** Trained on a dataset of over 36 million records, filtering for ~854,873 benign samples to establish a baseline.
- **Features Used (`LIVE_FEATURE_COLS`):**
  1. `pkt_rate` (Rate)
  2. `byte_rate` (Srate)
  3. `unique_ports` (Protocol Type)
  4. `port_entropy` (Variance)

### Training Parameters
- **Estimators:** 200 trees
- **Max Samples:** 0.8
- **Contamination Rate:** 0.05 (assumes 5% of traffic contains anomalies during outlier detection)

### Detailed Evaluation Metrics (Test Set)
The model underwent evaluation on unseen test splits of the CICIoT2023 dataset containing diverse attack vectors (DDoS, TCP Floods, Port scans, etc.):

* **Accuracy:** `91.28%` (0.9128)
* **Precision:** `99.87%` (0.9987) — *Exceptionally low false positive rate.*
* **Recall:** `91.20%` (0.9120)
* **F1 Score:** `95.33%` (0.9533)

These metrics show that the model is extremely precise when determining if a flow is an attack (nearly 100% precision) while successfully identifying the vast majority of threats (91.2% recall).

---

## 5. Setup & Execution Guide

### Prerequisites
- Python 3.8+
- Virtual Environment tool (`venv`)
- Mininet installed (`sudo apt install mininet`)
- OS-Ken SDN Framework

### Step 1: Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate

# Install AI/Flask dependencies
pip install -r requirements.txt

# Install SDN Controller dependencies (os-ken)
pip install -r sdn/requirements-sdn.txt
```

### Step 2: Start the Security Dashboard / Trust API (Terminal 1)
```bash
source venv/bin/activate
python app.py
```
*(The API will now listen on port 5000 or 5050 for controller requests).*

### Step 3: Start the OS-Ken SDN Controller (Terminal 2)
```bash
source venv/bin/activate
python -m osken.cmd.manager sdn/bazta_osken_controller.py
```

### Step 4: Run Mininet Topology (Terminal 3)
```bash
sudo mn -c  # Clean old topologies
sudo python3 sdn/mininet_topo.py
```

---

## 6. Testing & Simulating Attacks

Within the Mininet CLI (`mininet>`), you can trigger various attacks using the provided script, and observe the metrics drop in the live dashboard:

* **Normal Traffic:** `h1 ping -c 3 10.0.1.2` (Trust remains high)
* **ICMP Flood:** `h1 bash scripts/attacks.sh icmp_flood 10.0.1.2` (Triggers `pkt_rate` penalty)
* **Port Scan:** `h1 bash scripts/attacks.sh port_scan 10.0.1.2` (Triggers `unique_ports` and `port_entropy` penalties)
* **Byte Flood:** `h1 bash scripts/attacks.sh byte_flood 10.0.1.2` (Triggers `byte_rate` penalty)
* **Full Automated Demo:** `h1 bash scripts/attacks.sh full_demo 10.0.1.2`