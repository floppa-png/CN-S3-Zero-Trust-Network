"""
Trust Scorer - Hybrid anomaly detection.

Produces a continuous trust score (0-100) per host based on
behavioral features. Uses a two-stage approach:
1. Isolation Forest for general anomaly detection
2. Rate-based hard rules that override IF for L3-only data

Score interpretation:
    0-19:  Highly anomalous (block)
    20-49: Suspicious (restrict)
    50-79: Moderate concern (rate limit)
    80-100: Fully trusted (allow)
"""

import os
import json
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from datetime import datetime

from .feature_extractor import FeatureExtractor


class TrustScorer:
    """
    AI-driven trust scoring engine using Isolation Forest.

    The model is trained on "normal" baseline traffic and then
    used to continuously score live traffic. The anomaly score
    from the Isolation Forest is mapped to a 0-100 trust scale.
    """

    # Thresholds for rate-based anomaly detection (L3 features)
    # These are the TRUE differentiators between normal and attack traffic.
    NORMAL_PACKET_RATE_MAX = 100       # Normal users send < 100 pps
    NORMAL_BYTE_RATE_MAX = 100000      # Normal users send < 100 KB/s
    NORMAL_BYTES_PER_FLOW_MAX = 500000 # Normal flows < 500 KB total

    def __init__(self, model_dir=None, contamination=0.01):
        """
        Args:
            model_dir: Directory to save/load trained models
            contamination: Expected fraction of anomalies in training data
        """
        self.model_dir = model_dir or os.path.join(
            os.path.dirname(__file__), '..', '..', 'models'
        )
        self.contamination = contamination

        # ML components
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()

        # Score history per host
        self.score_history = defaultdict(list)

        # Exponential moving average factor for smoothing
        self.ema_alpha = 0.4

        # Previous scores for smoothing
        self.prev_scores = defaultdict(lambda: 100.0)

        # Training data buffer
        self.training_buffer = []

        self.is_trained = False

    def train(self, training_data, feature_names=None):
        """
        Train the Isolation Forest on normal baseline traffic.

        Args:
            training_data: numpy array or DataFrame of normal features
                           Shape: (n_samples, n_features)
            feature_names: Optional list of feature names
        """
        if isinstance(training_data, pd.DataFrame):
            X = training_data.values
        else:
            X = np.array(training_data)

        if len(X) < 10:
            print(f"[TRUST] Warning: Only {len(X)} training samples. "
                  f"Need more data for reliable model.")

        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        print(f"[TRUST] Model trained on {len(X)} samples, "
              f"{X.shape[1]} features")

        return self

    def _rate_based_score(self, features):
        """
        Score based purely on traffic rate features.
        This is the primary scoring mechanism for L3-only data.
        Returns a trust score 0-100, or None if rates are normal.
        """
        packet_rate = features[0]    # index 0: packet_rate
        byte_rate = features[1]      # index 1: byte_rate
        bytes_per_flow = features[14] # index 14: bytes_per_flow

        # Check if ANY rate metric is clearly anomalous
        anomaly_signals = 0
        severity = 0.0

        if packet_rate > self.NORMAL_PACKET_RATE_MAX:
            anomaly_signals += 1
            # How many times over the limit? 700/100 = 7x over
            ratio = packet_rate / self.NORMAL_PACKET_RATE_MAX
            severity += min(ratio, 10)
        
        if byte_rate > self.NORMAL_BYTE_RATE_MAX:
            anomaly_signals += 1
            ratio = byte_rate / self.NORMAL_BYTE_RATE_MAX
            severity += min(ratio, 10)
        
        if bytes_per_flow > self.NORMAL_BYTES_PER_FLOW_MAX:
            anomaly_signals += 1
            ratio = bytes_per_flow / self.NORMAL_BYTES_PER_FLOW_MAX
            severity += min(ratio, 10)

        if anomaly_signals == 0:
            # All rates are within normal bounds — user is fully trusted
            return 100.0

        # At least one rate is anomalous — the more signals and severity, the lower the score
        # Even 1 signal at 1.5x over the limit should drop score significantly
        # severity is sum of ratios (each 1-10), anomaly_signals is 1-3
        # Example: pkt_rate=167 -> ratio=1.67, 1 signal -> score = max(0, 100 - 1.67*30) = 50
        # Example: pkt_rate=700 -> ratio=7.0, 1 signal -> score = max(0, 100 - 7.0*30) = 0
        trust_score = max(0, 100 - (severity * 30))
        return float(trust_score)

    def score(self, features, host_ip=None):
        """
        Score a feature vector and return a trust score (0-100).

        Uses a hybrid approach:
        1. Rate-based thresholds detect anomalous traffic rates
        2. If rates are normal, the user is fully trusted (score=100)
           because with L3-only data, traffic rate is the primary
           discriminating feature between normal and attack traffic
        3. The Isolation Forest model is maintained for future L4 data
        4. Apply EMA smoothing (asymmetric: instant UP, smooth DOWN)

        Args:
            features: numpy array of shape (n_features,) or (1, n_features)
            host_ip: Optional host IP for score smoothing

        Returns:
            float: Trust score between 0 and 100
        """
        features_arr = np.array(features).flatten()

        # Rate-based scoring: primary mechanism for L3 data
        trust_score = self._rate_based_score(features_arr)

        # Apply asymmetric EMA smoothing
        if host_ip:
            prev = self.prev_scores[host_ip]
            if trust_score >= prev:
                # Score is same or improving — trust immediately
                smoothed = trust_score
            else:
                # Score is dropping — smooth the descent
                smoothed = (self.ema_alpha * trust_score +
                            (1 - self.ema_alpha) * prev)
            self.prev_scores[host_ip] = smoothed
            trust_score = smoothed

            # Store history
            self.score_history[host_ip].append({
                'timestamp': datetime.now().isoformat(),
                'trust_score': float(trust_score),
            })
            # Keep last 1000 entries
            if len(self.score_history[host_ip]) > 1000:
                self.score_history[host_ip] = self.score_history[host_ip][-1000:]

        return float(trust_score)

    def _map_to_trust_score(self, raw_score):
        """
        Map Isolation Forest raw score to 0-100 trust score.

        IF score_samples() returns:
            Positive values -> normal (inliers)
            Negative values -> anomalous (outliers)
            Typical range: roughly -0.5 to 0.5
        """
        # Very generous sigmoid: benefit of the doubt for IF-only scoring.
        # Only flag if the IF is EXTREMELY confident it's anomalous.
        # raw_score=0 -> ~95, raw_score=-0.2 -> ~80, raw_score=-0.5 -> ~10
        mapped = 100.0 / (1.0 + np.exp(-12 * (raw_score + 0.2)))
        return float(np.clip(mapped, 0, 100))

    def score_from_flows(self, host_ip, flow_stats):
        """
        End-to-end: extract features from flow stats and score.

        Args:
            host_ip: IP address of the host
            flow_stats: Flow statistics from the SDN controller

        Returns:
            float: Trust score (0-100)
        """
        features = self.feature_extractor.extract_features(host_ip, flow_stats)
        if features is None:
            return self.prev_scores.get(host_ip, 100.0)
        return self.score(features, host_ip=host_ip)

    def add_training_sample(self, features, label='normal'):
        """Buffer a training sample for later model training."""
        self.training_buffer.append({
            'features': features.tolist() if isinstance(features, np.ndarray) else features,
            'label': label,
            'timestamp': datetime.now().isoformat(),
        })

    def train_from_buffer(self):
        """Train the model using buffered normal samples."""
        normal_samples = [
            s['features'] for s in self.training_buffer
            if s['label'] == 'normal'
        ]
        if len(normal_samples) < 10:
            print(f"[TRUST] Not enough normal samples ({len(normal_samples)}). "
                  f"Need at least 10.")
            return False

        X = np.array(normal_samples)
        self.train(X)
        return True

    def save_model(self, filename=None):
        """Save the trained model and scaler to disk."""
        if not self.is_trained:
            print("[TRUST] No trained model to save")
            return

        os.makedirs(self.model_dir, exist_ok=True)
        if not filename:
            filename = os.path.join(self.model_dir, 'trust_model.joblib')

        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'contamination': self.contamination,
            'feature_names': FeatureExtractor.FEATURE_NAMES,
        }, filename)
        print(f"[TRUST] Model saved to {filename}")

    def load_model(self, filename=None):
        """Load a previously trained model."""
        if not filename:
            filename = os.path.join(self.model_dir, 'trust_model.joblib')

        if not os.path.exists(filename):
            print(f"[TRUST] No model found at {filename}")
            return False

        data = joblib.load(filename)
        self.model = data['model']
        self.scaler = data['scaler']
        self.contamination = data.get('contamination', 0.1)
        self.is_trained = True
        print(f"[TRUST] Model loaded from {filename}")
        return True

    def get_score_history(self, host_ip=None):
        """Get score history for a host or all hosts."""
        if host_ip:
            return self.score_history.get(host_ip, [])
        return dict(self.score_history)

    def generate_synthetic_training_data(self, n_normal=500, n_anomalous=50):
        """
        Generate synthetic training data for initial model training.
        Uses realistic feature distributions centered on actual
        employee behavior observed from the L3 SDN controller.
        """
        np.random.seed(42)

        # Normal traffic features centered around actual employee behavior
        # observed from the SDN controller (L3 only, no port/protocol data)
        normal_data = np.column_stack([
            np.random.normal(8, 4, n_normal).clip(0.5, 50),    # packet_rate
            np.random.normal(1200, 600, n_normal).clip(50, 5000), # byte_rate
            np.random.normal(150, 40, n_normal).clip(50, 1500),  # avg_packet_size
            np.random.uniform(10, 60, n_normal),                 # flow_duration
            np.ones(n_normal),                                   # unique_dst_ips
            np.zeros(n_normal),                                  # unique_dst_ports
            np.zeros(n_normal),                                  # port_diversity
            np.zeros(n_normal),                                  # tcp_ratio
            np.zeros(n_normal),                                  # udp_ratio
            np.random.choice([0.0, 1.0], n_normal, p=[0.5, 0.5]),  # small_packet_ratio
            np.random.choice([0.0, 1.0], n_normal, p=[0.8, 0.2]),  # large_packet_ratio
            np.random.uniform(0.01, 0.15, n_normal),             # connection_frequency
            np.random.uniform(10, 60, n_normal),                 # avg_flow_duration
            np.zeros(n_normal),                                  # burst_score
            np.random.uniform(5000, 60000, n_normal),            # bytes_per_flow
            np.ones(n_normal),                                   # flow_count
        ])

        print(f"[TRUST] Generated {n_normal} synthetic normal samples")
        return normal_data
