import matplotlib.pyplot as plt
import numpy as np
import os

# Data definition
components = [
    "Switch Packet Parsing (OS-Ken)",
    "REST API Roundtrip (Local Loopback)",
    "Heuristics & Rule Evaluation",
    "ML Inference (Isolation Forest)",
    "Flow Table Rule Enactment (OVS)"
]

times = [0.4, 1.2, 1.8, 2.7, 2.1]  # in milliseconds
colors = ["#34495e", "#2980b9", "#f39c12", "#e74c3c", "#27ae60"]

# Calculate percentages
total_time = sum(times)
percentages = [(t / total_time) * 100 for t in times]

# Create figure and axis
plt.figure(figsize=(9, 5))
fig, ax = plt.subplots(figsize=(10, 5.5))

# Plot bars
bars = ax.barh(components, times, color=colors, edgecolor="black", height=0.55, zorder=3)

# Grid lines
ax.xaxis.grid(True, linestyle="--", alpha=0.6, zorder=0)

# Customize axes labels and titles
ax.set_xlabel("Latency (milliseconds)", fontsize=12, fontweight="bold", labelpad=10)
ax.set_title("BAZTA Mitigation Response Latency Breakdown\nTotal Response Time: {:.1f} ms".format(total_time), 
             fontsize=14, fontweight="bold", pad=15)

# Add value labels inside/outside bars
for bar, t, p in zip(bars, times, percentages):
    width = bar.get_width()
    ax.text(width + 0.08, bar.get_y() + bar.get_height()/2, 
            f"{t:.1f} ms ({p:.1f}%)", 
            va="center", ha="left", fontsize=10, fontweight="bold")

# Adjust x-axis limit to accommodate labels
ax.set_xlim(0, max(times) + 0.8)

# Stylize chart borders
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color('#cccccc')
ax.spines['bottom'].set_color('#cccccc')

# Set tight layout
plt.tight_layout()

# Save path
artifact_dir = "/Users/praveenkumardevamane/.gemini/antigravity/brain/5ef31cc6-79d2-4276-8bbe-15d49fffe107"
os.makedirs(artifact_dir, exist_ok=True)
save_path = os.path.join(artifact_dir, "response_time_breakdown.png")
plt.savefig(save_path, dpi=300, bbox_inches="tight")
print(f"Chart saved successfully at: {save_path}")
