"""
Feature Extractor for Zero Trust Trust Engine.

Extracts per-layer behavioral features from flow statistics
collected by the SDN controller. Produces a feature vector per
host at configurable intervals.

Features extracted across three layers:
- Network Layer: packet rate, byte rate, flow duration, unique destinations
- Transport Layer: port diversity, connection patterns
- Application Layer: payload sizes, request frequency, protocol distribution
"""

import time
import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import datetime


class FeatureExtractor:
    """
    Extract behavioral features from flow statistics.

    Takes raw flow stats from the SDN controller and produces
    a feature vector per host for the trust scoring model.
    """

    # Feature names for the output vector
    FEATURE_NAMES = [
        # Network Layer
        'packet_rate',           # packets per second
        'byte_rate',             # bytes per second
        'avg_packet_size',       # average packet size
        'flow_duration',         # how long the flow has been active
        'unique_dst_ips',        # number of unique destination IPs
        'unique_dst_ports',      # number of unique destination ports

        # Transport Layer
        'port_diversity',        # entropy of destination ports
        'tcp_ratio',             # fraction of TCP flows
        'udp_ratio',             # fraction of UDP flows
        'small_packet_ratio',    # fraction of small packets (<128 bytes)
        'large_packet_ratio',    # fraction of large packets (>1024 bytes)

        # Application Layer
        'connection_frequency',  # new connections per second
        'avg_flow_duration',     # average duration of flows
        'burst_score',           # measure of traffic burstiness
        'bytes_per_flow',        # average bytes per flow
        'flow_count',            # total number of active flows
    ]

    def __init__(self, window_size=10):
        """
        Args:
            window_size: Number of seconds for the sliding window
        """
        self.window_size = window_size
        # History per host: {ip: [list of flow stat snapshots]}
        self.history = defaultdict(list)
        # Previous stats for computing deltas
        self.prev_stats = defaultdict(dict)

    def extract_features(self, host_ip, flow_stats):
        """
        Extract features for a specific host from flow statistics.

        Args:
            host_ip: IP address of the host to extract features for
            flow_stats: Dict of all flow stats from the controller
                        Format: {dpid: {flow_key: stats_dict}}

        Returns:
            numpy array of features, or None if insufficient data
        """
        now = time.time()

        # Collect all flows involving this host (as source)
        host_flows = []
        for dpid, flows in flow_stats.items():
            for flow_key, stats in flows.items():
                if isinstance(flow_key, str):
                    src_ip = flow_key.split('->')[0]
                elif isinstance(flow_key, tuple):
                    src_ip = flow_key[0]
                else:
                    continue

                if src_ip == host_ip:
                    host_flows.append(stats)

        if not host_flows:
            # Return None to indicate no activity, preserving previous trust score
            return None

        # Store snapshot for history
        self.history[host_ip].append({
            'timestamp': now,
            'flows': host_flows,
        })

        # Keep only recent history
        cutoff = now - self.window_size * 6  # Keep 6 windows
        self.history[host_ip] = [
            s for s in self.history[host_ip] if s['timestamp'] > cutoff
        ]

        # ========== Network Layer Features ==========
        total_packets = sum(f.get('packet_count', 0) for f in host_flows)
        total_bytes = sum(f.get('byte_count', 0) for f in host_flows)
        durations = [
            f.get('last_seen', now) - f.get('first_seen', now)
            for f in host_flows
        ]
        max_duration = max(durations) if durations else 1
        max_duration = max(max_duration, 1)  # Avoid division by zero

        # Don't score until flows have stabilized (at least 10 seconds).
        # Early flow data has artificially high packet_rate and
        # connection_frequency that triggers false positives.
        if max_duration < 10:
            return None

        packet_rate = total_packets / max_duration
        byte_rate = total_bytes / max_duration
        avg_packet_size = total_bytes / max(total_packets, 1)
        flow_duration = max_duration

        # Unique destinations
        dst_ips = set()
        dst_ports = set()
        for f in host_flows:
            dst_ip = f.get('dst_ip', '')
            dst_ips.add(dst_ip)
            dst_port = f.get('dst_port', 0)
            if dst_port:
                dst_ports.add(dst_port)

        unique_dst_ips = len(dst_ips)
        unique_dst_ports = len(dst_ports)

        # ========== Transport Layer Features ==========
        # Port diversity (Shannon entropy)
        if dst_ports:
            port_counts = defaultdict(int)
            for f in host_flows:
                p = f.get('dst_port', 0)
                if p:
                    port_counts[p] += 1
            total_port_flows = sum(port_counts.values())
            if total_port_flows > 0:
                probs = [c / total_port_flows for c in port_counts.values()]
                port_diversity = -sum(p * np.log2(p + 1e-10) for p in probs)
            else:
                port_diversity = 0
        else:
            port_diversity = 0

        # Protocol ratios
        tcp_count = sum(1 for f in host_flows if f.get('protocol') == 'tcp')
        udp_count = sum(1 for f in host_flows if f.get('protocol') == 'udp')
        total_flows = len(host_flows)
        tcp_ratio = tcp_count / max(total_flows, 1)
        udp_ratio = udp_count / max(total_flows, 1)

        # Packet size distribution
        packet_sizes = [f.get('byte_count', 0) / max(f.get('packet_count', 1), 1)
                        for f in host_flows]
        small_packets = sum(1 for s in packet_sizes if s < 128)
        large_packets = sum(1 for s in packet_sizes if s > 1024)
        small_packet_ratio = small_packets / max(len(packet_sizes), 1)
        large_packet_ratio = large_packets / max(len(packet_sizes), 1)

        # ========== Application Layer Features ==========
        connection_frequency = total_flows / max_duration
        avg_flow_dur = np.mean(durations) if durations else 0

        # Burstiness: coefficient of variation of packet counts
        pkt_counts = [f.get('packet_count', 0) for f in host_flows]
        if len(pkt_counts) > 1 and np.mean(pkt_counts) > 0:
            burst_score = np.std(pkt_counts) / np.mean(pkt_counts)
        else:
            burst_score = 0

        bytes_per_flow = total_bytes / max(total_flows, 1)
        flow_count = total_flows

        # Build feature vector
        features = np.array([
            packet_rate,
            byte_rate,
            avg_packet_size,
            flow_duration,
            unique_dst_ips,
            unique_dst_ports,
            port_diversity,
            tcp_ratio,
            udp_ratio,
            small_packet_ratio,
            large_packet_ratio,
            connection_frequency,
            avg_flow_dur,
            burst_score,
            bytes_per_flow,
            flow_count,
        ])

        return features

    def get_feature_dataframe(self, host_ip, flow_stats):
        """Return features as a labeled pandas DataFrame row."""
        features = self.extract_features(host_ip, flow_stats)
        if features is None:
            return None
        return pd.DataFrame([features], columns=self.FEATURE_NAMES)

    @staticmethod
    def get_feature_names():
        """Return the list of feature names."""
        return FeatureExtractor.FEATURE_NAMES.copy()
