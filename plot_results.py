#!/usr/bin/env python3
"""
Plots Trust Score vs Time and Traffic Rate to visualize the LDoS attack detection.
Also generates a graph comparing trust scores of all 4 users over time.
"""
import json
import os
import matplotlib.pyplot as plt
import datetime
import glob

def get_latest_roles():
    """Find the most recent roles.json from data/collected/"""
    files = glob.glob(os.path.join('data', 'collected', '*', 'roles.json'))
    if not files:
        return {}
    files.sort(reverse=True) # Newest first
    with open(files[0], 'r') as f:
        return json.load(f)

def main():
    decisions_file = os.path.join('data', 'processed', 'decisions.json')
    if not os.path.exists(decisions_file):
        print(f"Error: {decisions_file} not found. Run the demo first.")
        return

    with open(decisions_file, 'r') as f:
        data = json.load(f)

    if not data:
        print("No data found in decisions.json")
        return

    # Create output directory
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)

    # Dictionary to hold time series data per host
    hosts_data = {}
    for entry in data:
        ip = entry['host_ip']
        if ip not in hosts_data:
            hosts_data[ip] = {'times': [], 'scores': [], 'packet_rates': []}
        
        dt = datetime.datetime.fromisoformat(entry['timestamp'])
        hosts_data[ip]['times'].append(dt)
        hosts_data[ip]['scores'].append(entry['trust_score'])
        if entry.get('features') and len(entry['features']) > 0:
            hosts_data[ip]['packet_rates'].append(entry['features'][0])
        else:
            hosts_data[ip]['packet_rates'].append(0)

    # Establish common start time (earliest timestamp among all hosts)
    all_times = [dt for host in hosts_data.values() for dt in host['times']]
    start_time = min(all_times) if all_times else None

    if not start_time:
        print("No timestamp data found.")
        return

    # Convert to relative seconds
    for ip, hdata in hosts_data.items():
        hdata['rel_times'] = [(t - start_time).total_seconds() for t in hdata['times']]

    roles = get_latest_roles()
    
    # Fallback default if roles.json isn't found
    if not roles:
        roles = {'10.0.0.1': 'h1 (Employee)', '10.0.0.2': 'h2 (Employee)', 
                 '10.0.0.3': 'h3 (Server)', '10.0.0.4': 'h4 (Attacker)'}

    # Identify which IP is the attacker
    attacker_ip = '10.0.0.4'
    for ip, label in roles.items():
        if 'Attacker' in label:
            attacker_ip = ip
            break

    # ---------------------------------------------------------
    # Graph 1: Multi-Vector Attack (Focus on Attacker)
    # ---------------------------------------------------------
    if attacker_ip in hosts_data:
        h4_data = hosts_data[attacker_ip]
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)

        # Plot 1: Trust Score
        ax1.plot(h4_data['rel_times'], h4_data['scores'], 'r-', linewidth=2, label='Trust Score (0-100)')
        ax1.axhline(y=50, color='orange', linestyle='--', label='Rate Limit Threshold (50)')
        ax1.axhline(y=20, color='red', linestyle='--', label='Block Threshold (20)')
        ax1.set_ylabel('Trust Score')
        ax1.set_title(f'Continuous Trust Scoring & Enforcement (Attacker: {attacker_ip})')
        ax1.grid(True)
        ax1.legend(loc='upper right')

        # Plot 2: Packet Rate
        ax2.plot(h4_data['rel_times'], h4_data['packet_rates'], 'b-', linewidth=2, label='Packet Rate (pps)')
        ax2.set_xlabel('Time (seconds)')
        ax2.set_ylabel('Packets per second')
        ax2.set_title('Multi-Vector Attack Traffic Pattern (Port Scan -> DoS -> LDoS)')
        ax2.grid(True)
        ax2.legend(loc='upper right')

        plt.tight_layout()
        output_img1 = os.path.join(output_dir, 'multi_attack_detection_results.png')
        plt.savefig(output_img1, dpi=300)
        print(f"Successfully generated graph: {output_img1}")

    # ---------------------------------------------------------
    # Graph 2: All Users Trust Scores
    # ---------------------------------------------------------
    plt.figure(figsize=(10, 6))
    
    employee_colors = ['green', 'blue']
    emp_idx = 0
    
    for ip, hdata in hosts_data.items():
        label = roles.get(ip, ip)
        # Give attacker the red line, server purple, and others green/blue
        if 'Attacker' in label:
            color = 'red'
        elif 'Server' in label:
            color = 'purple'
        else:
            color = employee_colors[emp_idx % 2]
            emp_idx += 1
            
        plt.plot(hdata['rel_times'], hdata['scores'], color=color, linewidth=2, label=label)

    plt.axhline(y=50, color='orange', linestyle='--', label='Rate Limit (50)')
    plt.axhline(y=20, color='red', linestyle='--', label='Block (20)')
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Trust Score (0-100)')
    plt.title('Real-Time Trust Scores of All Network Hosts')
    plt.grid(True)
    plt.legend(loc='best')
    plt.tight_layout()
    
    output_img2 = os.path.join(output_dir, 'all_users_trust_scores.png')
    plt.savefig(output_img2, dpi=300)
    print(f"Successfully generated graph: {output_img2}")

    # ---------------------------------------------------------
    # QoL: Terminal Summary for Presentation
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print(" FINAL TRUST SCORES SUMMARY")
    print("=" * 60)
    for ip, hdata in sorted(hosts_data.items()):
        label = roles.get(ip, ip)
        final_score = hdata['scores'][-1] if hdata['scores'] else 100.0
        status = "BLOCKED" if final_score <= 20 else ("RATE LIMITED" if final_score <= 50 else "SAFE")
        
        # Color codes for terminal if desired, but standard text is safe
        print(f"  {label.ljust(25)} : Score {final_score:5.1f}  ->  [{status}]")
    print("=" * 60 + "\n")

if __name__ == '__main__':
    main()
