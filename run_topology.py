#!/usr/bin/env python3
"""
Launch script for the Zero Trust Mininet topology.

Usage:
    sudo python3 run_topology.py [controller_ip] [controller_port]

Defaults:
    controller_ip:   127.0.0.1
    controller_port:  6633
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.topology.network_topo import run_interactive, start_network


def run_automated(controller_ip='127.0.0.1', controller_port=6633):
    """Run the network automatically to generate normal and anomalous traffic."""
    net = start_network(controller_ip, controller_port)
    
    from mininet.log import info
    import time
    import random
    
    # Shuffle hosts h1, h2, h4 to prove the attacker is not hardcoded
    all_hosts = [net.get('h1'), net.get('h2'), net.get('h4')]
    random.shuffle(all_hosts)
    normal1, normal2, attacker = all_hosts
    server = net.get('h3')
    
    info('\n*** Starting Server...\n')
    server.cmd('python3 -m http.server 80 &')
    time.sleep(1)
    
    info(f'\n*** Generating normal traffic ({normal1.name} and {normal2.name})...\n')
    normal1.cmd(f'python3 src/traffic/normal_traffic.py {normal1.IP()} {server.IP()} 30 &')
    normal2.cmd(f'python3 src/traffic/normal_traffic.py {normal2.IP()} {server.IP()} 30 &')
    
    info(f'\n*** Generating anomalous traffic (Attacker: {attacker.name})...\n')
    attacker.cmd(f'python3 src/traffic/anomalous_traffic.py {attacker.IP()} {server.IP()} all 30')
    
    info('\n*** Traffic generation complete. Stopping network...\n')
    try:
        server.cmd('kill %1 2>/dev/null; true')
    except Exception:
        pass  # Server process may already be dead
    net.stop()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Zero Trust Mininet Topology")
    parser.add_argument('--ip', default='127.0.0.1', help='Controller IP')
    parser.add_argument('--port', type=int, default=6633, help='Controller Port')
    parser.add_argument('--generate-data', action='store_true', help='Auto-generate traffic data')
    args = parser.parse_args()

    print("=" * 60)
    print("  Zero Trust SDN Network - Mininet Topology")
    print("=" * 60)
    print(f"  Controller: {args.ip}:{args.port}")
    print(f"  Hosts: h1 (Employee), h2 (Employee), h3 (Server), h4 (Attacker)")
    print("=" * 60)
    print()

    if args.generate_data:
        run_automated(args.ip, args.port)
    else:
        run_interactive(args.ip, args.port)
