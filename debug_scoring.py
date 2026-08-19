#!/usr/bin/env python3
"""Debug script to understand why normal users get flagged."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
from src.trust_engine.trust_scorer import TrustScorer
from src.trust_engine.feature_extractor import FeatureExtractor

scorer = TrustScorer()
synthetic = scorer.generate_synthetic_training_data()
scorer.train(synthetic)

# Simulate what a NORMAL employee's features actually look like
# Based on controller_state: packets=186, bytes=32558, duration=37
normal_features = np.array([
    186/37,      # packet_rate = 5.03
    32558/37,    # byte_rate = 880
    32558/186,   # avg_packet_size = 175
    37,          # flow_duration
    1,           # unique_dst_ips
    0,           # unique_dst_ports (L3 only)
    0,           # port_diversity
    0,           # tcp_ratio
    0,           # udp_ratio
    1.0,         # small_packet_ratio (175 < 128? no... actually 175 > 128, so 0)
    0,           # large_packet_ratio (175 > 1024? no)
    1/37,        # connection_frequency = 0.027
    37,          # avg_flow_duration
    0,           # burst_score (only 1 flow)
    32558,       # bytes_per_flow
    1,           # flow_count
])

# Actually recompute small/large packet ratio correctly
avg_pkt_size = 32558/186  # = 175
small_packet_ratio = 1.0 if avg_pkt_size < 128 else 0.0
large_packet_ratio = 1.0 if avg_pkt_size > 1024 else 0.0
normal_features[9] = small_packet_ratio
normal_features[10] = large_packet_ratio

print("=== NORMAL EMPLOYEE FEATURES ===")
for name, val in zip(FeatureExtractor.FEATURE_NAMES, normal_features):
    print(f"  {name:25s} = {val:.4f}")

# Score it raw (no EMA)
raw = scorer.model.score_samples(scorer.scaler.transform(normal_features.reshape(1,-1)))[0]
mapped = scorer._map_to_trust_score(raw)
print(f"\nRaw IF score: {raw:.4f}")
print(f"Mapped trust score (no EMA): {mapped:.2f}")

# Now simulate repeated evaluations with EMA
print("\n=== SIMULATING REPEATED EVALUATIONS (like policy engine does) ===")
for i in range(10):
    score = scorer.score(normal_features, host_ip='10.0.0.1')
    print(f"  Eval {i+1}: trust_score = {score:.2f}")

# Now test attacker features
print("\n=== ATTACKER FEATURES ===")
attacker_features = np.array([
    25958/37,    # packet_rate = 701 (MASSIVE)
    38984529/37, # byte_rate = 1053636 (MASSIVE)
    38984529/25958, # avg_packet_size = 1502 (MAX)
    37,          # flow_duration
    1,           # unique_dst_ips
    0,           # unique_dst_ports
    0,           # port_diversity
    0,           # tcp_ratio
    0,           # udp_ratio
    0,           # small_packet_ratio (1502 is NOT < 128)
    1.0,         # large_packet_ratio (1502 > 1024 = YES)
    1/37,        # connection_frequency
    37,          # avg_flow_duration
    0,           # burst_score
    38984529,    # bytes_per_flow (MASSIVE)
    1,           # flow_count
])

for name, val in zip(FeatureExtractor.FEATURE_NAMES, attacker_features):
    print(f"  {name:25s} = {val:.4f}")

raw_atk = scorer.model.score_samples(scorer.scaler.transform(attacker_features.reshape(1,-1)))[0]
mapped_atk = scorer._map_to_trust_score(raw_atk)
print(f"\nRaw IF score: {raw_atk:.4f}")
print(f"Mapped trust score (no EMA): {mapped_atk:.2f}")
