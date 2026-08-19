import json
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import os
import sys
from datetime import datetime
from collections import defaultdict

if len(sys.argv) < 2:
    print("Usage: python plot_trust_scores.py <output_directory>")
    sys.exit(1)

out_dir = sys.argv[1]
decisions_file = os.path.join(out_dir, 'decisions.json')
output_png = os.path.join(out_dir, 'trust_score_decay.png')

if not os.path.exists(decisions_file):
    print(f"No decisions file found at {decisions_file}")
    sys.exit(0)

with open(decisions_file, 'r') as f:
    decisions = json.load(f)

# Group scores by host — ALL 4 hosts
scores_by_host = defaultdict(lambda: {'times': [], 'scores': []})
base_time = None

for entry in decisions:
    ip = entry.get('host_ip')
    if ip:
        try:
            t = datetime.fromisoformat(entry['timestamp'])
            if base_time is None:
                base_time = t
            seconds = (t - base_time).total_seconds()
            scores_by_host[ip]['times'].append(seconds)
            scores_by_host[ip]['scores'].append(entry['trust_score'])
        except Exception:
            pass

# Determine which hosts ended up blocked (final score < 80)
final_scores = {}
for ip, data in scores_by_host.items():
    if data['scores']:
        final_scores[ip] = data['scores'][-1]

plt.figure(figsize=(10, 6))

# Plot all 4 hosts, sorted by IP for consistency
sorted_ips = sorted(scores_by_host.keys())

for ip in sorted_ips:
    data = scores_by_host[ip]
    if not data['times']:
        continue
    
    final = final_scores.get(ip, 100)
    is_safe = final >= 80
    color = '#4CAF50' if is_safe else '#F44336'
    linestyle = '-' if not is_safe else '-'
    linewidth = 3 if not is_safe else 2.5
    
    label = f'Host ({ip})'
    if not is_safe:
        label += ' [BLOCKED]'
    else:
        label += ' [SAFE]'
    
    plt.plot(data['times'], data['scores'], label=label, color=color,
             linewidth=linewidth, linestyle=linestyle, marker='o', markersize=3)

# Block threshold line
plt.axhline(y=80, color='#FF5722', linestyle='--', linewidth=2, alpha=0.7)
plt.text(1, 82, 'Block Threshold (80)', color='#FF5722', fontsize=10,
         fontstyle='italic', fontweight='bold')

plt.title('Dynamic AI Trust Score Over Time', fontsize=18, fontweight='bold', pad=20)
plt.xlabel('Seconds since start', fontsize=14, fontweight='bold')
plt.ylabel('Trust Score (0-100)', fontsize=14, fontweight='bold')
plt.ylim(-5, 110)
plt.grid(True, linestyle='--', alpha=0.4)
plt.legend(fontsize=11, loc='lower left')
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig(output_png, dpi=300)
print(f"Decay chart saved to {output_png}")
