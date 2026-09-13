#!/usr/bin/env python3
"""
Train the Trust Scorer on live normal Mininet traffic.

This script captures live flow stats from the SDN controller while
only normal traffic is running, extracts features, trains the ML model,
and saves it to the models/ directory.
"""

import time
import os
import sys
import json

# Add project root to path
project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_dir)

from src.trust_engine.trust_scorer import TrustScorer
from src.trust_engine.feature_extractor import FeatureExtractor

DATA_DIR = os.path.join(project_dir, 'data')
STATE_FILE = os.path.join(DATA_DIR, 'controller_state.json')

def fetch_flow_stats():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
            return state.get('flow_stats', {})
    except Exception as e:
        print(f"Error reading state: {e}")
    return {}

def main():
    print("=" * 60)
    print("  Live Training: Zero Trust ML Model")
    print("=" * 60)
    print("Instructions:")
    print("1. Ensure Ryu controller is running (run_controller.py)")
    print("2. Ensure Mininet is running (run_topology.py)")
    print("3. Start normal traffic ONLY (e.g., normal_traffic.py)")
    print("=" * 60)
    
    samples_needed = 20
    scorer = TrustScorer()
    extractor = FeatureExtractor()
    
    print(f"Capturing {samples_needed} normal baseline samples...")
    
    samples_collected = 0
    hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3'] # Assume these are normal
    
    while samples_collected < samples_needed:
        flow_stats = fetch_flow_stats()
        if not flow_stats:
            time.sleep(2)
            continue
            
        for host in hosts:
            if samples_collected >= samples_needed:
                break
            features = extractor.extract_features(host, flow_stats)
            if features is not None:
                scorer.add_training_sample(features, label='normal')
                samples_collected += 1
                print(f"Captured sample {samples_collected}/{samples_needed} from {host}")
        
        time.sleep(2)
        
    print("\nTraining Isolation Forest model...")
    if scorer.train_from_buffer():
        scorer.save_model()
        print("\n[SUCCESS] Model successfully trained on live traffic and saved to models/trust_model.joblib!")
        print("You can now restart the policy engine to use this trained model.")
    else:
        print("\n[FAILED] Could not train model. Not enough valid samples.")

if __name__ == '__main__':
    main()
