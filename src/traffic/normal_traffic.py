"""
Normal Traffic Generator for Zero Trust Network.

Generates legitimate-looking traffic patterns from employee hosts:
- HTTP requests, DNS queries, SSH sessions, HTTPS browsing
- Periodic, bursty but bounded patterns
"""

import subprocess
import time
import random
import threading
import sys
import os
import signal
import json
import socket
from datetime import datetime


NORMAL_PROFILES = {
    'web_browsing': {
        'dst_port': 80, 'protocol': 'tcp',
        'packet_size_range': (64, 1500),
        'interval_range': (2.0, 10.0),
        'burst_size_range': (1, 2),
    },
    'dns_query': {
        'dst_port': 53, 'protocol': 'udp',
        'packet_size_range': (40, 128),
        'interval_range': (5.0, 15.0),
        'burst_size_range': (1, 1),
    },
    'ssh_session': {
        'dst_port': 22, 'protocol': 'tcp',
        'packet_size_range': (64, 512),
        'interval_range': (1.0, 5.0),
        'burst_size_range': (1, 3),
    },
    'https_browsing': {
        'dst_port': 443, 'protocol': 'tcp',
        'packet_size_range': (64, 1500),
        'interval_range': (2.0, 8.0),
        'burst_size_range': (1, 4),
    },
}


class NormalTrafficGenerator:
    """Generates normal/legitimate network traffic."""

    def __init__(self, src_ip, dst_ip, log_dir=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'collected'
        )
        self.running = False
        self.threads = []
        self.traffic_log = []

    def _log(self, profile, packets, bytes_count):
        self.traffic_log.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'profile': profile, 'packets': packets,
            'bytes': bytes_count, 'label': 'normal',
        })

    def generate_tcp(self, dst_port, pkt_size, count=1):
        for _ in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.dst_ip, dst_port))
                sock.send(os.urandom(pkt_size))
                self._log('tcp', 1, pkt_size)
                sock.close()
            except (ConnectionRefusedError, socket.timeout, OSError):
                self._log('tcp_attempt', 1, 64)

    def generate_udp(self, dst_port, pkt_size, count=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(count):
                sock.sendto(os.urandom(pkt_size), (self.dst_ip, dst_port))
                self._log('udp', 1, pkt_size)
            sock.close()
        except Exception:
            pass

    def generate_icmp(self, count=3):
        try:
            subprocess.run(
                ['ping', '-c', str(count), '-s', '64', self.dst_ip],
                capture_output=True, timeout=30
            )
            self._log('icmp', count, 64 * count)
        except Exception:
            pass

    def run_profile(self, profile_name, duration=60):
        profile = NORMAL_PROFILES[profile_name]
        end_time = time.time() + duration
        print(f"[NORMAL] Starting '{profile_name}': {self.src_ip} -> {self.dst_ip}")

        while self.running and time.time() < end_time:
            pkt_size = random.randint(*profile['packet_size_range'])
            burst = random.randint(*profile['burst_size_range'])
            interval = random.uniform(*profile['interval_range'])

            if profile['protocol'] == 'tcp':
                self.generate_tcp(profile['dst_port'], pkt_size, burst)
            else:
                self.generate_udp(profile['dst_port'], pkt_size, burst)

            time.sleep(interval)

        print(f"[NORMAL] Finished '{profile_name}'")

    def start_all(self, duration=60):
        self.running = True
        for name in NORMAL_PROFILES:
            t = threading.Thread(target=self.run_profile, args=(name, duration), daemon=True)
            self.threads.append(t)
            t.start()
        # Periodic pings
        t = threading.Thread(target=self._ping_loop, args=(duration,), daemon=True)
        self.threads.append(t)
        t.start()

    def _ping_loop(self, duration):
        end_time = time.time() + duration
        while self.running and time.time() < end_time:
            self.generate_icmp(count=1)
            time.sleep(random.uniform(5.0, 15.0))

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=5)

    def save_log(self, filename=None):
        if not filename:
            filename = os.path.join(
                self.log_dir,
                f'normal_{self.src_ip}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            )
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(self.traffic_log, f, indent=2)
        print(f"[NORMAL] Log saved: {filename}")

    def wait(self, duration):
        time.sleep(duration)
        self.stop()


def main():
    src_ip = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.1'
    dst_ip = sys.argv[2] if len(sys.argv) > 2 else '10.0.0.3'
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    log_dir = sys.argv[4] if len(sys.argv) > 4 else None

    gen = NormalTrafficGenerator(src_ip, dst_ip, log_dir=log_dir)
    signal.signal(signal.SIGINT, lambda s, f: (gen.stop(), gen.save_log(), sys.exit(0)))

    print(f"[NORMAL] Generating traffic: {src_ip} -> {dst_ip} for {duration}s")
    gen.start_all(duration=duration)
    gen.wait(duration)
    gen.save_log()


if __name__ == '__main__':
    main()
