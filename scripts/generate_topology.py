import matplotlib.pyplot as plt
import os

def draw_topology():
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Hide axes
    ax.axis('off')
    
    # Node Coordinates
    # Control/App Plane
    c0 = (0, 3)
    trust_engine = (3.5, 3)
    
    # Data Plane Switches
    s0 = (0, 1.2)
    s1 = (-3.5, -0.6)
    s2 = (0, -0.6)
    s3 = (3.5, -0.6)
    
    # Hosts
    hosts = {
        "h1": (-4.2, -2.4),
        "h2": (-2.8, -2.4),
        "h3": (-0.7, -2.4),
        "h4": (0.7, -2.4),
        "h5": (2.8, -2.4),
        "h6": (4.2, -2.4)
    }
    
    # Draw Connections (Lines)
    # Control Plane Links (Dashed Red Lines representing OpenFlow 1.3 Control Path)
    control_style = dict(color="#e74c3c", linestyle="--", linewidth=1.8, alpha=0.85, zorder=1)
    ax.plot([c0[0], s0[0]], [c0[1], s0[1]], **control_style)
    ax.plot([c0[0], s1[0]], [c0[1], s1[1]], **control_style)
    ax.plot([c0[0], s2[0]], [c0[1], s2[1]], **control_style)
    ax.plot([c0[0], s3[0]], [c0[1], s3[1]], **control_style)
    
    # REST Connection between Controller and Trust Engine (Solid Black Double-headed line)
    ax.annotate("", xy=trust_engine, xytext=c0,
                arrowprops=dict(arrowstyle="<->", color="#34495e", lw=2, shrinkA=12, shrinkB=12, zorder=2))
    ax.text(1.75, 3.2, "REST API\nPOST /score_flow", ha="center", va="center", color="#2c3e50", fontsize=9, fontweight="bold")
    
    # Data Plane Switch Links (Solid Thick Blue Lines)
    switch_style = dict(color="#2980b9", linestyle="-", linewidth=2.5, zorder=2)
    ax.plot([s0[0], s1[0]], [s0[1], s1[1]], **switch_style)
    ax.plot([s0[0], s2[0]], [s0[1], s2[1]], **switch_style)
    ax.plot([s0[0], s3[0]], [s0[1], s3[1]], **switch_style)
    
    # Host Links (Solid Green Lines)
    host_style = dict(color="#27ae60", linestyle="-", linewidth=2.0, zorder=2)
    ax.plot([s1[0], hosts["h1"][0]], [s1[1], hosts["h1"][1]], **host_style)
    ax.plot([s1[0], hosts["h2"][0]], [s1[1], hosts["h2"][1]], **host_style)
    ax.plot([s2[0], hosts["h3"][0]], [s2[1], hosts["h3"][1]], **host_style)
    ax.plot([s2[0], hosts["h4"][0]], [s2[1], hosts["h4"][1]], **host_style)
    ax.plot([s3[0], hosts["h5"][0]], [s3[1], hosts["h5"][1]], **host_style)
    ax.plot([s3[0], hosts["h6"][0]], [s3[1], hosts["h6"][1]], **host_style)
    
    # Draw Nodes as stylized markers/boxes
    # 1. Controller Node
    ax.scatter(*c0, s=2200, color="#e74c3c", edgecolor="#c0392b", linewidth=2.5, marker="s", zorder=3)
    ax.text(c0[0], c0[1], "c0\nSDN Controller\n(OS-Ken)", ha="center", va="center", color="white", fontsize=10, fontweight="bold")
    
    # 2. Trust Engine Node
    bbox_props = dict(boxstyle="round,pad=0.5", fc="#f39c12", ec="#d35400", lw=2.5)
    ax.text(trust_engine[0], trust_engine[1], "BAZTA Trust Engine\n- Flow Feature Extractor\n- Heuristics Rules Engine\n- Isolation Forest ML",
            ha="center", va="center", color="white", fontsize=9, fontweight="bold", bbox=bbox_props, zorder=3)
    
    # 3. Core Switch Node
    ax.scatter(*s0, s=1800, color="#2980b9", edgecolor="#21618c", linewidth=2.5, marker="o", zorder=3)
    ax.text(s0[0], s0[1], "s0\nCore\nSwitch", ha="center", va="center", color="white", fontsize=9, fontweight="bold")
    
    # 4. Microsegment Switches
    for name, pos in [("s1\nSeg A", s1), ("s2\nSeg B", s2), ("s3\nSeg C", s3)]:
        ax.scatter(*pos, s=1500, color="#3498db", edgecolor="#2980b9", linewidth=2, marker="o", zorder=3)
        ax.text(pos[0], pos[1], name, ha="center", va="center", color="white", fontsize=9, fontweight="bold")
        
    # 5. Hosts (IoT Devices)
    host_ips = {
        "h1": "10.0.1.1", "h2": "10.0.1.2",
        "h3": "10.0.2.1", "h4": "10.0.2.2",
        "h5": "10.0.3.1", "h6": "10.0.3.2"
    }
    for h_name, h_pos in hosts.items():
        ax.scatter(*h_pos, s=800, color="#2ecc71", edgecolor="#27ae60", linewidth=1.5, marker="p", zorder=3)
        ax.text(h_pos[0], h_pos[1], h_name, ha="center", va="center", color="white", fontsize=9, fontweight="bold")
        # Add IP under host
        ax.text(h_pos[0], h_pos[1] - 0.4, host_ips[h_name], ha="center", va="center", color="#2c3e50", fontsize=8.5, fontweight="bold")
        
    # Legending Subnets
    ax.text(s1[0], s1[1] + 0.45, "Subnet 10.0.1.0/24", ha="center", va="center", color="#7f8c8d", fontsize=9, style="italic")
    ax.text(s2[0], s2[1] + 0.45, "Subnet 10.0.2.0/24", ha="center", va="center", color="#7f8c8d", fontsize=9, style="italic")
    ax.text(s3[0], s3[1] + 0.45, "Subnet 10.0.3.0/24", ha="center", va="center", color="#7f8c8d", fontsize=9, style="italic")
    
    # Draw Legends
    custom_legend = [
        plt.Line2D([0], [0], color="#2980b9", lw=3.0, label="Data Plane Link (OVS Switches)"),
        plt.Line2D([0], [0], color="#e74c3c", lw=1.8, linestyle="--", label="Control Plane Link (OpenFlow 1.3)"),
        plt.Line2D([0], [0], marker="p", color="w", markerfacecolor="#2ecc71", markeredgecolor="#27ae60", markersize=10, label="IoT End-Host"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#3498db", markeredgecolor="#2980b9", markersize=12, label="OpenFlow Switch")
    ]
    ax.legend(handles=custom_legend, loc="lower center", ncol=2, frameon=True, facecolor="#f8f9f9", edgecolor="#ccc", fontsize=9.5)
    
    plt.title("BAZTA Network Simulation Topology (Mininet)", fontsize=14, fontweight="bold", pad=20)
    plt.tight_layout()
    
    # Save Image to Artifacts
    artifact_dir = "/Users/praveenkumardevamane/.gemini/antigravity/brain/5ef31cc6-79d2-4276-8bbe-15d49fffe107"
    os.makedirs(artifact_dir, exist_ok=True)
    save_path = os.path.join(artifact_dir, "network_topology.png")
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    print(f"Topology saved successfully at: {save_path}")

if __name__ == "__main__":
    draw_topology()
