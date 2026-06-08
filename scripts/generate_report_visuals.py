import matplotlib.pyplot as plt
import numpy as np
import os
import json

# Ensure reports directory exists inside the project
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(WORKSPACE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Set global matplotlib style parameters for consistent, clean aesthetics
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Helvetica', 'Arial', 'DejaVu Sans']
plt.rcParams['text.color'] = '#2c3e50'
plt.rcParams['axes.labelcolor'] = '#2c3e50'
plt.rcParams['xtick.color'] = '#5d6d7e'
plt.rcParams['ytick.color'] = '#5d6d7e'

def generate_topology():
    print("Generating Network Topology Diagram...")
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.axis('off')
    
    # Node Coordinates
    c0 = (0, 3)
    trust_engine = (3.5, 3)
    s0 = (0, 1.2)
    s1 = (-3.5, -0.6)
    s2 = (0, -0.6)
    s3 = (3.5, -0.6)
    
    hosts = {
        "h1": (-4.2, -2.4), "h2": (-2.8, -2.4),
        "h3": (-0.7, -2.4), "h4": (0.7, -2.4),
        "h5": (2.8, -2.4), "h6": (4.2, -2.4)
    }
    
    # Control Plane Links (OpenFlow 1.3 Path - Red dashed lines)
    control_style = dict(color="#e74c3c", linestyle="--", linewidth=1.5, alpha=0.8, zorder=1)
    for s_pos in [s0, s1, s2, s3]:
        ax.plot([c0[0], s_pos[0]], [c0[1], s_pos[1]], **control_style)
        
    # REST API Connection
    ax.annotate("", xy=trust_engine, xytext=c0,
                arrowprops=dict(arrowstyle="<->", color="#2c3e50", lw=2, shrinkA=12, shrinkB=12, zorder=2))
    ax.text(1.75, 3.2, "REST API\nPOST /score_flow", ha="center", va="center", color="#2c3e50", fontsize=8.5, fontweight="bold")
    
    # Data Plane Links (OVS Switches - Blue solid lines)
    switch_style = dict(color="#2980b9", linestyle="-", linewidth=2.5, zorder=2)
    for s_pos in [s1, s2, s3]:
        ax.plot([s0[0], s_pos[0]], [s0[1], s_pos[1]], **switch_style)
        
    # Host Links (Green solid lines)
    host_style = dict(color="#27ae60", linestyle="-", linewidth=1.8, zorder=2)
    ax.plot([s1[0], hosts["h1"][0]], [s1[1], hosts["h1"][1]], **host_style)
    ax.plot([s1[0], hosts["h2"][0]], [s1[1], hosts["h2"][1]], **host_style)
    ax.plot([s2[0], hosts["h3"][0]], [s2[1], hosts["h3"][1]], **host_style)
    ax.plot([s2[0], hosts["h4"][0]], [s2[1], hosts["h4"][1]], **host_style)
    ax.plot([s3[0], hosts["h5"][0]], [s3[1], hosts["h5"][1]], **host_style)
    ax.plot([s3[0], hosts["h6"][0]], [s3[1], hosts["h6"][1]], **host_style)
    
    # Draw Nodes
    # 1. Controller
    ax.scatter(*c0, s=2000, color="#e74c3c", edgecolor="#c0392b", linewidth=2, marker="s", zorder=3)
    ax.text(c0[0], c0[1], "c0\nSDN Controller\n(OS-Ken)", ha="center", va="center", color="white", fontsize=9, fontweight="bold")
    
    # 2. Trust Engine
    bbox_props = dict(boxstyle="round,pad=0.5", fc="#f39c12", ec="#d35400", lw=2)
    ax.text(trust_engine[0], trust_engine[1], "BAZTA Trust Engine\n• Feature Extractor\n• Heuristics Rules\n• Isolation Forest ML",
            ha="center", va="center", color="white", fontsize=8.5, fontweight="bold", bbox=bbox_props, zorder=3)
    
    # 3. Switches
    ax.scatter(*s0, s=1600, color="#2980b9", edgecolor="#21618c", linewidth=2, marker="o", zorder=3)
    ax.text(s0[0], s0[1], "s0\nCore\nSwitch", ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")
    
    for name, pos in [("s1\nSeg A", s1), ("s2\nSeg B", s2), ("s3\nSeg C", s3)]:
        ax.scatter(*pos, s=1300, color="#3498db", edgecolor="#2980b9", linewidth=2, marker="o", zorder=3)
        ax.text(pos[0], pos[1], name, ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")
        
    # 4. Hosts
    host_ips = {
        "h1": "10.0.1.1", "h2": "10.0.1.2",
        "h3": "10.0.2.1", "h4": "10.0.2.2",
        "h5": "10.0.3.1", "h6": "10.0.3.2"
    }
    for h_name, h_pos in hosts.items():
        ax.scatter(*h_pos, s=700, color="#2ecc71", edgecolor="#27ae60", linewidth=1.5, marker="p", zorder=3)
        ax.text(h_pos[0], h_pos[1], h_name, ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")
        ax.text(h_pos[0], h_pos[1] - 0.38, host_ips[h_name], ha="center", va="center", color="#2c3e50", fontsize=8, fontweight="bold")
        
    # Labels
    ax.text(s1[0], s1[1] + 0.45, "Subnet 10.0.1.0/24", ha="center", va="center", color="#7f8c8d", fontsize=8, style="italic")
    ax.text(s2[0], s2[1] + 0.45, "Subnet 10.0.2.0/24", ha="center", va="center", color="#7f8c8d", fontsize=8, style="italic")
    ax.text(s3[0], s3[1] + 0.45, "Subnet 10.0.3.0/24", ha="center", va="center", color="#7f8c8d", fontsize=8, style="italic")
    
    # Legend
    custom_legend = [
        plt.Line2D([0], [0], color="#2980b9", lw=2.5, label="Data Plane (OVS Switch Links)"),
        plt.Line2D([0], [0], color="#e74c3c", lw=1.5, linestyle="--", label="Control Plane (OpenFlow 1.3)"),
        plt.Line2D([0], [0], marker="p", color="w", markerfacecolor="#2ecc71", markeredgecolor="#27ae60", markersize=8, label="IoT End-Host"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#3498db", markeredgecolor="#2980b9", markersize=10, label="OpenFlow Switch")
    ]
    ax.legend(handles=custom_legend, loc="lower center", ncol=2, frameon=True, facecolor="#f8f9f9", edgecolor="#ccc", fontsize=9)
    ax.set_title("BAZTA Network Simulation Topology (Mininet)", fontsize=13, fontweight="bold", pad=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "network_topology.png"), dpi=300, bbox_inches="tight")
    plt.close()

def generate_latency_breakdown():
    print("Generating Response Latency Breakdown Chart...")
    components = [
        "Switch Packet Parsing (OS-Ken)",
        "REST API Roundtrip (Local Loopback)",
        "Heuristics & Rule Evaluation",
        "ML Inference (Isolation Forest)",
        "Flow Table Rule Enactment (OVS)"
    ]
    times = [0.4, 1.2, 1.8, 2.7, 2.1]  # in milliseconds
    colors = ["#34495e", "#2980b9", "#f39c12", "#e74c3c", "#27ae60"]
    
    total_time = sum(times)
    percentages = [(t / total_time) * 100 for t in times]
    
    fig, ax = plt.subplots(figsize=(9.5, 4.5))
    bars = ax.barh(components, times, color=colors, edgecolor="#2c3e50", height=0.55, zorder=3)
    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    
    ax.set_xlabel("Latency (milliseconds)", fontsize=11, fontweight="bold", labelpad=8)
    ax.set_title(f"BAZTA Mitigation Response Latency Breakdown\nTotal Action Latency: {total_time:.1f} ms", 
                 fontsize=12, fontweight="bold", pad=12)
    
    for bar, t, p in zip(bars, times, percentages):
        width = bar.get_width()
        ax.text(width + 0.08, bar.get_y() + bar.get_height()/2, 
                f"{t:.1f} ms ({p:.1f}%)", 
                va="center", ha="left", fontsize=9, fontweight="bold")
        
    ax.set_xlim(0, max(times) + 0.8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cccccc')
    ax.spines['bottom'].set_color('#cccccc')
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "response_time_breakdown.png"), dpi=300, bbox_inches="tight")
    plt.close()

def generate_trust_timeline():
    print("Generating Trust Score Behavior Profile...")
    t_max = 55
    timeline = np.arange(0, t_max + 1)
    scores = []
    current_score = 100.0
    BASE = 100.0
    RECOVERY_RATE = 0.08
    
    for t in timeline:
        if 0 <= t <= 10:
            current_score = 100.0
        elif 11 <= t <= 25:
            if t == 11:
                current_score = max(0.0, current_score - 80.0)
            else:
                current_score = 20.0
        elif 26 <= t <= 30:
            current_score += (BASE - current_score) * RECOVERY_RATE
        elif 31 <= t <= 35:
            if t == 31:
                current_score = max(0.0, current_score - 60.0)
            else:
                current_score = 0.0
        elif t >= 36:
            current_score += (BASE - current_score) * RECOVERY_RATE
        scores.append(current_score)
        
    fig, ax = plt.subplots(figsize=(11, 5.5))
    
    # Background Policy Zones (Updated thresholds: 80 and 40)
    ax.axhspan(0, 40, color="#f9ebd2", alpha=0.5, label="BLOCK (Isolation)")
    ax.axhspan(40, 80, color="#fef9e7", alpha=0.6, label="RATE_LIMIT")
    ax.axhspan(80, 100, color="#e8f8f5", alpha=0.6, label="ALLOW (Benign)")
    
    # Plot line
    ax.plot(timeline, scores, color="#2c3e50", linewidth=2.2, marker="o", markersize=3.5, label="Trust Score (T)", zorder=4)
    ax.axhline(80, color="#1abc9c", linestyle="--", linewidth=1.0, alpha=0.8, zorder=2)
    ax.axhline(40, color="#e67e22", linestyle="--", linewidth=1.0, alpha=0.8, zorder=2)
    
    # Annotations
    ax.annotate("Normal Ping\n(T = 100)", xy=(5, 100), xytext=(5, 80),
                arrowprops=dict(arrowstyle="->", color="#7f8c8d"), ha="center", fontweight="bold", fontsize=8.5)
    ax.annotate("ICMP Flood\n-80 Points\n(T -> 20)", xy=(11, 20), xytext=(15, 45),
                arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=1.2), ha="center", color="#c0392b", fontweight="bold", fontsize=8.5)
    ax.annotate("Mitigation: BLOCK\nFlow Drop Rule", xy=(11.5, 20), xytext=(16, 12),
                arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.2), ha="left", color="#c0392b", fontweight="bold", fontsize=8.5)
    ax.annotate("Recovery\n(+8% per sec)", xy=(28, 35), xytext=(22, 55),
                arrowprops=dict(arrowstyle="->", color="#7f8c8d"), ha="center", fontsize=8.5)
    ax.annotate("Port Scan\n-60 Points\n(T -> 0)", xy=(31, 0), xytext=(27, 18),
                arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=1.2), ha="center", color="#c0392b", fontweight="bold", fontsize=8.5)
    ax.annotate("Final Recovery\nRe-enters ALLOW", xy=(55, 81), xytext=(48, 60),
                arrowprops=dict(arrowstyle="->", color="#27ae60"), ha="center", color="#27ae60", fontweight="bold", fontsize=8.5)
                
    ax.set_title("BAZTA Dynamic Trust Score Behavior Profile (Simulation Timeline)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Simulation Timeline (Seconds)", fontsize=10, fontweight="bold", labelpad=8)
    ax.set_ylabel("Calculated Trust Score (T)", fontsize=10, fontweight="bold", labelpad=8)
    ax.set_xlim(0, t_max)
    ax.set_ylim(-5, 105)
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#ccc", shadow=True, fontsize=8.5)
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "trust_score_timeline.png"), dpi=300, bbox_inches="tight")
    plt.close()

def generate_ml_metrics():
    print("Generating ML Model Performance Metrics Chart...")
    metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]
    # Values extracted from live_model_meta.json
    values = [91.28, 99.87, 91.20, 95.33]
    colors = ["#3498db", "#2ecc71", "#e67e22", "#9b59b6"]
    
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    bars = ax.barh(metrics, values, color=colors, edgecolor="#2c3e50", height=0.5, zorder=3)
    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    
    ax.set_xlabel("Score (%)", fontsize=11, fontweight="bold", labelpad=8)
    ax.set_title("BAZTA Anomaly Detection ML Model Performance\n(Classifier: Isolation Forest | Dataset: CICIoT2023)", 
                 fontsize=12, fontweight="bold", pad=12)
    
    for bar, val in zip(bars, values):
        width = bar.get_width()
        ax.text(width + 1.0, bar.get_y() + bar.get_height()/2, 
                f"{val:.2f}%", 
                va="center", ha="left", fontsize=10, fontweight="bold")
        
    ax.set_xlim(0, 110)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cccccc')
    ax.spines['bottom'].set_color('#cccccc')
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "ml_model_evaluation.png"), dpi=300, bbox_inches="tight")
    plt.close()

def generate_mitigation_throughput():
    print("Generating Mitigation Throughput Impact Chart...")
    t_max = 55
    timeline = np.arange(0, t_max + 1)
    scores = []
    throughput = []  # in Mbps. Nominal 100 Mbps link.
    
    current_score = 100.0
    BASE = 100.0
    RECOVERY_RATE = 0.08
    
    # Simulate trust and resulting SDN rate limits/blocks
    for t in timeline:
        if 0 <= t <= 10:
            current_score = 100.0
        elif 11 <= t <= 25:
            if t == 11:
                current_score = max(0.0, current_score - 80.0)
            else:
                current_score = 20.0
        elif 26 <= t <= 30:
            current_score += (BASE - current_score) * RECOVERY_RATE
        elif 31 <= t <= 35:
            if t == 31:
                current_score = max(0.0, current_score - 60.0)
            else:
                current_score = 0.0
        elif t >= 36:
            current_score += (BASE - current_score) * RECOVERY_RATE
        scores.append(current_score)
        
        # Traffic Throughput Logic:
        # ALLOW (T >= 80): 100 Mbps
        # RATE_LIMIT / QoS (T 40-79): 25 Mbps (SDN meter table)
        # BLOCK (T < 40): 0 Mbps (SDN drop rule)
        if current_score >= 80:
            throughput.append(100.0)
        elif current_score >= 40:
            throughput.append(25.0)
        else:
            throughput.append(0.0)
            
    fig, ax1 = plt.subplots(figsize=(11, 5.5))
    
    # Plot Trust Score on Left Y Axis
    color_trust = "#2c3e50"
    ax1.set_xlabel("Simulation Timeline (Seconds)", fontsize=10, fontweight="bold", labelpad=8)
    ax1.set_ylabel("Calculated Trust Score (0-100)", color=color_trust, fontsize=10, fontweight="bold")
    line_trust = ax1.plot(timeline, scores, color=color_trust, linewidth=2.2, label="Trust Score (Left Y)", zorder=4)
    ax1.tick_params(axis='y', labelcolor=color_trust)
    ax1.set_ylim(-5, 105)
    ax1.grid(True, linestyle=":", alpha=0.4)
    
    # Create Twin Axis for Throughput
    ax2 = ax1.twinx()
    color_tp = "#c0392b"
    ax2.set_ylabel("Effective Forwarding Throughput (Mbps)", color=color_tp, fontsize=10, fontweight="bold")
    # Step plot is more realistic for SDN rule installations
    line_tp = ax2.step(timeline, throughput, color=color_tp, where="mid", linewidth=2.2, linestyle="-", label="Available Bandwidth (Right Y)", zorder=3)
    ax2.tick_params(axis='y', labelcolor=color_tp)
    ax2.set_ylim(-5, 110)
    
    # Dynamic shading logic for segments
    current_state = None
    start_t = 0
    for t in range(len(timeline)):
        score = scores[t]
        if score >= 80:
            state = "ALLOW"
        elif score >= 40:
            state = "RATE_LIMIT"
        else:
            state = "BLOCK"
            
        if current_state is None:
            current_state = state
            start_t = t
        elif state != current_state:
            # Draw span for [start_t, t-1]
            color = "#2ecc71" if current_state == "ALLOW" else "#f1c40f" if current_state == "RATE_LIMIT" else "#e74c3c"
            ax1.axvspan(start_t - 0.5, t - 0.5, color=color, alpha=0.08)
            # Label
            label_text = "ALLOW\n(100M)" if current_state == "ALLOW" else "RATE_LIMIT\n(25M)" if current_state == "RATE_LIMIT" else "BLOCK\n(0M)"
            label_color = "#27ae60" if current_state == "ALLOW" else "#d35400" if current_state == "RATE_LIMIT" else "#c0392b"
            ax1.text((start_t + t - 1) / 2, 101, label_text, ha="center", va="bottom", fontsize=8, color=label_color, fontweight="bold")
            
            current_state = state
            start_t = t
            
    # Draw last span
    color = "#2ecc71" if current_state == "ALLOW" else "#f1c40f" if current_state == "RATE_LIMIT" else "#e74c3c"
    ax1.axvspan(start_t - 0.5, len(timeline) - 0.5, color=color, alpha=0.08)
    label_text = "ALLOW\n(100M)" if current_state == "ALLOW" else "QoS\n(25M)" if current_state == "RATE_LIMIT" else "BLOCK\n(0M)"
    label_color = "#27ae60" if current_state == "ALLOW" else "#d35400" if current_state == "RATE_LIMIT" else "#c0392b"
    ax1.text((start_t + len(timeline) - 1) / 2, 101, label_text, ha="center", va="bottom", fontsize=8, color=label_color, fontweight="bold")
    
    # Legend combining lines from both axes
    lines = line_trust + line_tp
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper right", frameon=True, facecolor="white", edgecolor="#ccc", fontsize=8.5)
    
    ax1.set_title("Zero Trust Enforcement: Impact of Trust Scoring on Network Throughput", fontsize=12, fontweight="bold", pad=12)
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "mitigation_throughput_impact.png"), dpi=300, bbox_inches="tight")
    plt.close()

def generate_feature_anomaly_profiles():
    print("Generating Feature Anomaly Profiles...")
    # Group comparison of metrics
    categories = ["Packet Rate\n(pkts/sec)", "Byte Rate\n(x1000 bytes/sec)", "Unique Ports\n(count/30s)", "Port Entropy\n(bits)"]
    
    # Nominal benign values vs thresholds/attacks
    benign_vals = [15.0, 7.5, 2.0, 1.2]  # Typical values
    thresholds  = [90.0, 50.0, 20.0, 3.5]  # Action triggers
    
    x = np.arange(len(categories))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(9, 5))
    rects1 = ax.bar(x - width/2, benign_vals, width, label="Normal IoT Baseline", color="#2ecc71", edgecolor="#2c3e50")
    rects2 = ax.bar(x + width/2, thresholds, width, label="ZTA Threat Threshold", color="#e74c3c", edgecolor="#2c3e50")
    
    ax.set_ylabel("Metric Values (Normalized/Scale Adjusted)", fontsize=10, fontweight="bold")
    ax.set_title("BAZTA Network Feature Baseline vs. Anomaly Deduction Thresholds", fontsize=12, fontweight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9, fontweight="bold")
    ax.legend(frameon=True, facecolor="white", edgecolor="#ccc")
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    
    # Add actual value labels above bars
    def autolabel(rects, label_format="{:.1f}"):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(label_format.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight="bold")
                        
    autolabel(rects1)
    autolabel(rects2)
    
    # Add details about scaling
    ax.text(-0.35, 102, "Rule: -50 pts", ha="center", fontsize=8, color="#c0392b", style="italic", fontweight="bold")
    ax.text(0.65, 55, "Rule: -30 pts", ha="center", fontsize=8, color="#c0392b", style="italic", fontweight="bold")
    ax.text(1.65, 23, "Rule: -40 pts", ha="center", fontsize=8, color="#c0392b", style="italic", fontweight="bold")
    ax.text(2.65, 4.2, "Rule: -20 pts", ha="center", fontsize=8, color="#c0392b", style="italic", fontweight="bold")
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cccccc')
    ax.spines['bottom'].set_color('#cccccc')
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "feature_anomaly_thresholds.png"), dpi=300, bbox_inches="tight")
    plt.close()

if __name__ == "__main__":
    print(f"Saving all charts to: {REPORTS_DIR}")
    generate_topology()
    generate_latency_breakdown()
    generate_trust_timeline()
    generate_ml_metrics()
    generate_mitigation_throughput()
    generate_feature_anomaly_profiles()
    print("All report charts generated successfully!")
