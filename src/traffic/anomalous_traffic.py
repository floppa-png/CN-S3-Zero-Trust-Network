"""
Anomalous Traffic Generator for Zero Trust Network.

Generates attack/suspicious traffic patterns:
- Port scanning (sequential and random)
- Data exfiltration (large outbound transfers)
- Session hijacking simulation (sudden behavior change)
- Brute force login attempts
- Slow lateral movement
"""

import time
import random
import threading
import sys
import os
import signal
import json
import socket
from datetime import datetime


ATTACK_PROFILES = {
    'port_scan': {
        'description': 'Sequential port scanning',
        'port_range': (1, 1024),
        'interval': lambda: random.uniform(0.001, 0.005),  # 200-1000 pps
        'duration': 30,
    },
    'data_exfiltration': {
        'description': 'Large data transfer to external host',
        'dst_port': 8443,
        'packet_size': 65000,
        'interval': lambda: random.uniform(0.001, 0.005), # 200-1000 pps
        'duration': 20,
    },
    'brute_force': {
        'description': 'Rapid SSH login attempts',
        'dst_port': 22,
        'interval': lambda: random.uniform(0.002, 0.008), # 125-500 pps
        'duration': 15,
    },
    'lateral_movement': {
        'description': 'Slow, stealthy probing of multiple hosts',
        'ports': [22, 80, 443, 3389, 5900, 8080],
        'interval_range': (0.01, 0.05),  # Faster so it shows up in demo
        'duration': 60,
    },
    'session_hijack': {
        'description': 'Sudden behavior change mid-session',
        'normal_duration': 15,
        'attack_duration': 15,
    },
    'ldos_attack': {
        'description': 'Low-Rate DoS: periodic high-bursts to evade average-rate detection',
        'burst_duration': lambda: random.uniform(0.5, 1.5),
        'quiet_duration': lambda: random.uniform(2.0, 4.0),
        'dst_port': 80,
    },
}


class AnomalousTrafficGenerator:
    """Generates attack/anomalous network traffic."""

    def __init__(self, src_ip, dst_ip, log_dir=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'collected'
        )
        self.running = False
        self.threads = []
        self.traffic_log = []

    def _log(self, attack_type, packets, bytes_count, dst_port=None):
        self.traffic_log.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'attack_type': attack_type, 'dst_port': dst_port,
            'packets': packets, 'bytes': bytes_count,
            'label': 'anomalous',
        })

    def port_scan(self, duration=30):
        """Sequential port scan — classic reconnaissance."""
        print(f"[ATTACK] Port scan: {self.src_ip} -> {self.dst_ip}")
        profile = ATTACK_PROFILES['port_scan']
        end_time = time.time() + duration

        port = profile['port_range'][0]
        while self.running and time.time() < end_time and port <= profile['port_range'][1]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.dst_ip, port))
                self._log('port_scan', 1, 64, port)
                sock.close()
            except Exception:
                pass
            port += 1
            interval = profile['interval']() if callable(profile['interval']) else profile['interval']
            time.sleep(interval)

        print(f"[ATTACK] Port scan complete (scanned to port {port})")

    def data_exfiltration(self, duration=20):
        """Large data transfers simulating data theft."""
        print(f"[ATTACK] Data exfiltration: {self.src_ip} -> {self.dst_ip}")
        profile = ATTACK_PROFILES['data_exfiltration']
        end_time = time.time() + duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = os.urandom(min(profile['packet_size'], 65507))
                sock.sendto(data, (self.dst_ip, profile['dst_port']))
                self._log('data_exfiltration', 1, len(data), profile['dst_port'])
                sock.close()
            except Exception:
                pass
            interval = profile['interval']() if callable(profile['interval']) else profile['interval']
            time.sleep(interval)

        print(f"[ATTACK] Data exfiltration complete")

    def brute_force_ssh(self, duration=15):
        """Rapid SSH connection attempts simulating credential stuffing."""
        print(f"[ATTACK] Brute force SSH: {self.src_ip} -> {self.dst_ip}")
        profile = ATTACK_PROFILES['brute_force']
        end_time = time.time() + duration
        attempts = 0

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect_ex((self.dst_ip, profile['dst_port']))
                # Send fake SSH banner
                sock.send(b'SSH-2.0-attacker\r\n')
                self._log('brute_force', 1, 128, profile['dst_port'])
                sock.close()
                attempts += 1
            except Exception:
                pass
            interval = profile['interval']() if callable(profile['interval']) else profile['interval']
            time.sleep(interval)

        print(f"[ATTACK] Brute force complete ({attempts} attempts)")

    def lateral_movement(self, target_ips=None, duration=60):
        """Slow, stealthy probing of multiple hosts and ports."""
        if target_ips is None:
            target_ips = [self.dst_ip]

        print(f"[ATTACK] Lateral movement from {self.src_ip}")
        profile = ATTACK_PROFILES['lateral_movement']
        end_time = time.time() + duration

        while self.running and time.time() < end_time:
            target = random.choice(target_ips)
            port = random.choice(profile['ports'])
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect_ex((target, port))
                sock.send(os.urandom(64))
                self._log('lateral_movement', 1, 64, port)
                sock.close()
            except Exception:
                pass
            time.sleep(random.uniform(*profile['interval_range']))

        print(f"[ATTACK] Lateral movement complete")

    def session_hijack(self, duration=30):
        """Normal traffic first, then sudden switch to attack patterns."""
        profile = ATTACK_PROFILES['session_hijack']
        normal_dur = min(profile['normal_duration'], duration // 2)
        attack_dur = duration - normal_dur

        # Phase 1: Act normal
        print(f"[ATTACK] Session hijack Phase 1: Acting normal for {normal_dur}s")
        end_time = time.time() + normal_dur
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect_ex((self.dst_ip, 80))
                sock.send(os.urandom(random.randint(64, 512)))
                self._log('session_hijack_normal', 1, 256, 80)
                sock.close()
            except Exception:
                pass
            time.sleep(random.uniform(1.0, 3.0))

        # Phase 2: Switch to attack behavior
        print(f"[ATTACK] Session hijack Phase 2: Attack mode for {attack_dur}s")
        end_time = time.time() + attack_dur
        while self.running and time.time() < end_time:
            try:
                port = random.randint(1, 65535)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((self.dst_ip, port))
                sock.send(os.urandom(random.randint(1000, 65000)))
                self._log('session_hijack_attack', 1, 32000, port)
                sock.close()
            except Exception:
                pass
            time.sleep(0.05)

        print(f"[ATTACK] Session hijack complete")

    def ldos_attack(self, duration=60):
        """Low-Rate DoS: periodic bursts of traffic separated by long quiet periods."""
        print(f"[ATTACK] LDoS attack: {self.src_ip} -> {self.dst_ip}")
        profile = ATTACK_PROFILES['ldos_attack']
        end_time = time.time() + duration
        burst_dur = profile['burst_duration']() if callable(profile['burst_duration']) else profile['burst_duration']
        quiet_dur = profile['quiet_duration']() if callable(profile['quiet_duration']) else profile['quiet_duration']
        
        while self.running and time.time() < end_time:
            # Burst Phase
            burst_end = time.time() + burst_dur
            packets_sent = 0
            while self.running and time.time() < burst_end and time.time() < end_time:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    sock.connect_ex((self.dst_ip, profile['dst_port']))
                    sock.send(os.urandom(1024))
                    sock.close()
                    packets_sent += 1
                except Exception:
                    pass
                time.sleep(0.01) # Send fast during burst
            
            self._log('ldos_burst', packets_sent, packets_sent * 1024, profile['dst_port'])
            
            # Quiet Phase
            quiet_end = time.time() + quiet_dur
            while self.running and time.time() < quiet_end and time.time() < end_time:
                time.sleep(0.1) # Stay silent to drop the average rate
                
        print(f"[ATTACK] LDoS attack complete")

    def run_attack(self, attack_name, duration=None, **kwargs):
        """Run a specific attack profile."""
        attacks = {
            'port_scan': self.port_scan,
            'data_exfiltration': self.data_exfiltration,
            'brute_force': self.brute_force_ssh,
            'lateral_movement': self.lateral_movement,
            'session_hijack': self.session_hijack,
            'ldos_attack': self.ldos_attack,
        }
        if attack_name not in attacks:
            print(f"Unknown attack: {attack_name}")
            return
        dur = duration or ATTACK_PROFILES[attack_name].get('duration', 30)
        attacks[attack_name](duration=dur, **kwargs)

    def start_all(self, duration=60):
        """Run all attack profiles sequentially."""
        self.running = True
        attacks = ['port_scan', 'brute_force', 'data_exfiltration',
                   'session_hijack', 'lateral_movement', 'ldos_attack']
        per_attack = duration // len(attacks)
        for name in attacks:
            if not self.running:
                break
            self.run_attack(name, duration=per_attack)

    def stop(self):
        self.running = False

    def save_log(self, filename=None):
        if not filename:
            filename = os.path.join(
                self.log_dir,
                f'anomalous_{self.src_ip}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            )
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(self.traffic_log, f, indent=2)
        print(f"[ATTACK] Log saved: {filename}")


def main():
    src_ip = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.4'
    dst_ip = sys.argv[2] if len(sys.argv) > 2 else '10.0.0.3'
    attack = sys.argv[3] if len(sys.argv) > 3 else 'all'
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 60
    log_dir = sys.argv[5] if len(sys.argv) > 5 else None

    gen = AnomalousTrafficGenerator(src_ip, dst_ip, log_dir=log_dir)
    gen.running = True
    signal.signal(signal.SIGINT, lambda s, f: (gen.stop(), gen.save_log(), sys.exit(0)))

    print(f"[ATTACK] Generating anomalous traffic: {src_ip} -> {dst_ip}")
    if attack == 'all':
        gen.start_all(duration=duration)
    else:
        gen.run_attack(attack, duration=duration)
    gen.save_log()


if __name__ == '__main__':
    main()
