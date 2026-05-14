#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  BAZTA — One-Shot Setup Script
#  Run: bash setup.sh
# ══════════════════════════════════════════════════════════════

set -e

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  BAZTA — Zero Trust IoT Security Architecture"
echo "  One-Shot Setup"
echo "══════════════════════════════════════════════════════════"
echo ""

# Step 1: Install Python dependencies
echo "[1/2] Installing Python dependencies..."
pip install -r requirements.txt
echo "      ✓ Dependencies installed"
echo ""

# Step 2: Verify
echo "[2/2] Verifying setup..."
if [ -f "models/live_if_model.zip" ] && [ ! -f "models/live_if_model.pkl" ]; then
    echo "      * Unzipping pre-trained ML model..."
    unzip -q models/live_if_model.zip -d models/
fi

if [ ! -f "models/live_if_model.pkl" ]; then
    echo "      ⚠ Pre-trained model not found (models/live_if_model.pkl)"
    echo "        System will fall back to rule-based detection"
fi
python -c "
from core import TrustEngine, FlowFeatureExtractor
import os
e = TrustEngine(models_dir=os.path.join(os.path.dirname(os.path.abspath('app.py')), 'models'))
print('      ✓ TrustEngine loaded successfully')
print(f'      ✓ Model: {e.get_model_info()[\"model_type\"]}')
print(f'      ✓ Scaler: {\"yes\" if e.get_model_info()[\"has_scaler\"] else \"no\"}')
"
echo ""

echo "══════════════════════════════════════════════════════════"
echo "  ✓ Setup Complete!"
echo ""
echo "  Start the dashboard:"
echo "    python app.py"
echo ""
echo "  Then open: http://localhost:5050"
echo ""
echo "  For SDN (on Linux VM):"
echo "    # 1. Download and run ONOS locally (in home dir)"
echo "    cd ~"
echo "    wget https://repo1.maven.org/maven2/org/onosproject/onos-releases/2.7.0/onos-2.7.0.tar.gz"
echo "    tar -xzf onos-2.7.0.tar.gz && cd onos-2.7.0 && bin/onos-service start &"
echo ""
echo "    # 2. Build and install BAZTA ONOS App"
echo "    cd /mnt/share/miniproject/sdn/bazta-onos-app"
echo "    mvn clean install"
echo "    ~/onos-2.7.0/bin/onos-app localhost install! target/bazta-onos-app-1.0-SNAPSHOT.oar"
echo ""
echo "    # 3. Start Mininet"
echo "    cd /mnt/share/miniproject"
echo "    sudo python sdn/mininet_topo.py"
echo "══════════════════════════════════════════════════════════"
