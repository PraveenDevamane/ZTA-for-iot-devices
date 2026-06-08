import matplotlib.pyplot as plt
import numpy as np
import os

def simulate_trust_timeline():
    t_max = 55
    timeline = np.arange(0, t_max + 1)
    scores = []
    
    current_score = 100.0
    BASE = 100.0
    RECOVERY_RATE = 0.08
    
    # Simulation logic matching attacks.sh full_demo
    for t in timeline:
        # Phase 1: Normal Traffic (0s to 10s)
        if 0 <= t <= 10:
            current_score = 100.0
            
        # Phase 2: ICMP Flood Starts (11s to 25s)
        elif 11 <= t <= 25:
            if t == 11:
                # Deduct -50 (pkt_rate rule) and -30 (ML outlier)
                current_score = max(0.0, current_score - 80.0)
            else:
                # Keep low due to persistent attack
                current_score = 20.0
                
        # Phase 3: Short Recovery/Pause (26s to 30s)
        elif 26 <= t <= 30:
            # Gradual recovery on benign traffic
            current_score += (BASE - current_score) * RECOVERY_RATE
            
        # Phase 4: Port Scan Starts (31s to 35s)
        elif 31 <= t <= 35:
            if t == 31:
                # Deduct -40 (unique_ports) and -20 (entropy)
                current_score = max(0.0, current_score - 60.0)
            else:
                current_score = 0.0
                
        # Phase 5: Long Recovery/Normal Traffic (36s to 55s)
        elif t >= 36:
            current_score += (BASE - current_score) * RECOVERY_RATE
            
        scores.append(current_score)
        
    # Plotting
    plt.figure(figsize=(11, 6))
    fig, ax = plt.subplots(figsize=(11, 6.2))
    
    # Draw Background Policy Zones (Updated thresholds: 80 and 40)
    # BLOCK Zone (0 to 40) - Light Red
    ax.axhspan(0, 40, color="#f9ebd2", alpha=0.5, label="BLOCK (Isolation)")
    # RATE_LIMIT Zone (40 to 80) - Light Yellow/Orange
    ax.axhspan(40, 80, color="#fef9e7", alpha=0.6, label="RATE_LIMIT (QoS)")
    # ALLOW Zone (80 to 100) - Light Green
    ax.axhspan(80, 100, color="#e8f8f5", alpha=0.6, label="ALLOW (Benign)")
    
    # Plot trust score line
    ax.plot(timeline, scores, color="#2c3e50", linewidth=2.5, marker="o", markersize=4, label="Trust Score (T)", zorder=4)
    
    # Threshold Lines
    ax.axhline(80, color="#1abc9c", linestyle="--", linewidth=1.2, alpha=0.8, zorder=2)
    ax.axhline(40, color="#e67e22", linestyle="--", linewidth=1.2, alpha=0.8, zorder=2)
    
    # Annotations for Events
    ax.annotate("Normal Ping\n(T = 100)", xy=(5, 100), xytext=(5, 80),
                arrowprops=dict(arrowstyle="->", color="#7f8c8d"), ha="center", fontweight="bold", fontsize=9)
                
    ax.annotate("ICMP Flood\n-50 Rule, -30 ML\n(T -> 20)", xy=(11, 20), xytext=(15, 45),
                arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=1.5), ha="center", color="#c0392b", fontweight="bold", fontsize=9)
                
    ax.annotate("Mitigation: BLOCK\nFlow Drop Installed", xy=(11.5, 20), xytext=(18, 10),
                arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.5), ha="left", color="#c0392b", fontweight="bold", fontsize=9)
                
    ax.annotate("Recovery\n(+8% per sec)", xy=(28, 35), xytext=(22, 55),
                arrowprops=dict(arrowstyle="->", color="#7f8c8d"), ha="center", fontsize=9)
                
    ax.annotate("Port Scan\n-40 Scan, -20 Entropy\n(T -> 0)", xy=(31, 0), xytext=(28, 18),
                arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=1.5), ha="center", color="#c0392b", fontweight="bold", fontsize=9)
                
    ax.annotate("Final Recovery\nRe-enters ALLOW", xy=(55, 81), xytext=(48, 60),
                arrowprops=dict(arrowstyle="->", color="#27ae60"), ha="center", color="#27ae60", fontweight="bold", fontsize=9)
                
    # Labels and Titles
    ax.set_title("BAZTA Dynamic Trust Score Behavior Profile\n(Multi-Phase Attack Simulation)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Simulation Timeline (Seconds)", fontsize=11, fontweight="bold", labelpad=10)
    ax.set_ylabel("Calculated Trust Score (T)", fontsize=11, fontweight="bold", labelpad=10)
    
    ax.set_xlim(0, t_max)
    ax.set_ylim(-5, 105)
    ax.grid(True, linestyle=":", alpha=0.5)
    
    # Legend settings
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#ccc", shadow=True)
    
    # Formatting
    plt.tight_layout()
    
    # Save path
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    save_path = os.path.join(reports_dir, "trust_score_timeline_legacy.png")
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    print(f"Trust score graph saved successfully at: {save_path}")

if __name__ == "__main__":
    simulate_trust_timeline()
