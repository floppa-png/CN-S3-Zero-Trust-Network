import json
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import os
import sys

if len(sys.argv) < 2:
    print("Usage: python generate_chart.py <output_directory>")
    sys.exit(1)

out_dir = sys.argv[1]
state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'controller_state.json')
output_png = os.path.join(out_dir, 'traffic_comparison.png')

with open(state_file, 'r') as f:
    state = json.load(f)

flows = state.get('flow_stats', {}).get('1', {})
trust_scores = state.get('trust_scores', {})
enforcement = state.get('enforcement_actions', {})

# All 4 hosts
host_labels = {
    '10.0.0.1': 'Host 1\n(10.0.0.1)',
    '10.0.0.2': 'Host 2\n(10.0.0.2)',
    '10.0.0.3': 'Host 3 / Server\n(10.0.0.3)',
    '10.0.0.4': 'Host 4\n(10.0.0.4)',
}

# Count packets per source IP
packet_counts = {}
for key, flow in flows.items():
    src_ip = flow.get('src_ip')
    if src_ip:
        packet_counts[src_ip] = packet_counts.get(src_ip, 0) + flow.get('packet_count', 0)

# Ensure all 4 hosts are represented
ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
labels = [host_labels[ip] for ip in ips]
counts = [packet_counts.get(ip, 0) for ip in ips]

# Color: green if trusted (allow), red if blocked/restricted
colors = []
for ip in ips:
    action = enforcement.get(ip, 'allow')
    if action == 'allow':
        colors.append('#4CAF50')  # Green
    else:
        colors.append('#F44336')  # Red

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, counts, color=colors, edgecolor='black', linewidth=1.5)

plt.title('SDN Traffic Volume per Host', fontsize=18, fontweight='bold', pad=20)
plt.ylabel('Total Packets Sent', fontsize=14, fontweight='bold')
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.xticks(fontsize=11, fontweight='bold')
plt.yticks(fontsize=12)

# Add values + status on top of bars
max_count = max(counts) if counts and max(counts) > 0 else 100
for i, bar in enumerate(bars):
    yval = bar.get_height()
    action = enforcement.get(ips[i], 'allow')
    status_label = 'SAFE' if action == 'allow' else 'BLOCKED'
    color = '#4CAF50' if action == 'allow' else '#F44336'
    plt.text(bar.get_x() + bar.get_width()/2, yval + (max_count*0.02),
             f'{yval:,} pkts\n[{status_label}]', ha='center', va='bottom',
             fontsize=10, fontweight='bold', color=color)

# Add legend
import matplotlib.patches as mpatches
green_patch = mpatches.Patch(color='#4CAF50', label='Trusted (Allow)')
red_patch = mpatches.Patch(color='#F44336', label='Anomalous (Blocked)')
plt.legend(handles=[green_patch, red_patch], fontsize=11, loc='upper left')

plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig(output_png, dpi=300)
print(f"Chart saved to {output_png}")
