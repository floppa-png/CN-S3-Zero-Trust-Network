"""
Policy Engine for Zero Trust Network.

Maps trust scores to graduated enforcement actions and
communicates decisions to the SDN controller.

Supports two communication modes:
1. File-based IPC (reads controller_state.json, writes controller_commands.json)
2. REST API (when the Flask REST server is running)

Trust Score -> Action mapping:
    80-100: ALLOW     (full access)
    50-79:  RATE_LIMIT (step-up auth / throttle)
    20-49:  RESTRICT  (limited destinations)
    0-19:   BLOCK     (drop all traffic)
"""

import json
import os
import time
import threading
from collections import defaultdict
from datetime import datetime

from .feature_extractor import FeatureExtractor
from .trust_scorer import TrustScorer

THRESHOLDS = {'allow': 80, 'rate_limit': 50, 'restrict': 20, 'block': 0}


class PolicyEngine:
    """Continuous trust evaluation and enforcement engine."""

    def __init__(self, data_dir=None, eval_interval=5, hosts=None,
                 use_rest=False, controller_url='http://127.0.0.1:8080'):
        self.data_dir = data_dir or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data'
        )
        self.state_file = os.path.join(self.data_dir, 'controller_state.json')
        self.commands_file = os.path.join(self.data_dir, 'controller_commands.json')

        self.eval_interval = eval_interval
        self.hosts = hosts or ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.use_rest = use_rest
        self.controller_url = controller_url

        self.feature_extractor = FeatureExtractor()
        self.trust_scorer = TrustScorer()
        self.decision_log = []
        self.running = False
        self.thread = None
        self.current_scores = {ip: 100.0 for ip in self.hosts}
        self.current_actions = {ip: 'allow' for ip in self.hosts}

        os.makedirs(self.data_dir, exist_ok=True)

    def initialize_model(self, training_data=None):
        if self.trust_scorer.load_model():
            print("[POLICY] Loaded existing trust model from disk.")
        elif training_data is not None:
            self.trust_scorer.train(training_data)
        else:
            print("[POLICY] No trained model found. Generating synthetic baseline...")
            synthetic = self.trust_scorer.generate_synthetic_training_data()
            self.trust_scorer.train(synthetic)
        print("[POLICY] Trust model initialized")

    def determine_action(self, score):
        if score >= THRESHOLDS['allow']:
            return 'allow'
        elif score >= THRESHOLDS['rate_limit']:
            return 'rate_limit'
        elif score >= THRESHOLDS['restrict']:
            return 'restrict'
        return 'block'

    def fetch_flow_stats(self):
        """Read flow stats from controller state file."""
        if self.use_rest:
            return self._fetch_rest()
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                return state.get('flow_stats', {})
        except (json.JSONDecodeError, IOError):
            pass
        return {}

    def _fetch_rest(self):
        import requests
        try:
            resp = requests.get(f'{self.controller_url}/trust/flows', timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def push_trust_decision(self, ip, score):
        """Push a score update to the controller."""
        cmd = {
            'type': 'update_score',
            'ip': ip,
            'score': float(score),
            'timestamp': time.time(),
        }

        if self.use_rest:
            import requests
            try:
                requests.post(
                    f'{self.controller_url}/trust/scores',
                    json={'ip': ip, 'score': score}, timeout=5
                )
            except Exception:
                pass
        else:
            try:
                commands = []
                if os.path.exists(self.commands_file):
                    with open(self.commands_file, 'r') as f:
                        commands = json.load(f)
                commands.append(cmd)
                with open(self.commands_file, 'w') as f:
                    json.dump(commands, f)
            except (json.JSONDecodeError, IOError):
                with open(self.commands_file, 'w') as f:
                    json.dump([cmd], f)

    def evaluate_host(self, host_ip, flow_stats):
        features = self.feature_extractor.extract_features(host_ip, flow_stats)
        if features is None:
            trust_score = self.current_scores.get(host_ip, 100.0)
        else:
            trust_score = self.trust_scorer.score(features, host_ip=host_ip)
            
        action = self.determine_action(trust_score)

        return {
            'timestamp': datetime.now().isoformat(),
            'host_ip': host_ip,
            'trust_score': round(trust_score, 2),
            'action': action,
            'features': features.tolist() if features is not None else [],
        }

    def evaluation_loop(self):
        print(f"[POLICY] Evaluation loop started (interval={self.eval_interval}s)")
        while self.running:
            try:
                flow_stats = self.fetch_flow_stats()
                for host_ip in self.hosts:
                    decision = self.evaluate_host(host_ip, flow_stats)
                    self.current_scores[host_ip] = decision['trust_score']
                    self.current_actions[host_ip] = decision['action']
                    self.push_trust_decision(host_ip, decision['trust_score'])
                    self.decision_log.append(decision)

                    if decision['action'] != 'allow':
                        print(f"[POLICY] {host_ip}: score={decision['trust_score']:.1f} "
                              f"action={decision['action']}")

                if len(self.decision_log) > 10000:
                    self.decision_log = self.decision_log[-5000:]
            except Exception as e:
                print(f"[POLICY] Error: {e}")
            time.sleep(self.eval_interval)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=self.evaluation_loop, daemon=True, name='PolicyEngine'
        )
        self.thread.start()
        print("[POLICY] Engine started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)
        print("[POLICY] Engine stopped")

    def get_status(self):
        return {
            'scores': dict(self.current_scores),
            'actions': dict(self.current_actions),
            'total_decisions': len(self.decision_log),
            'model_trained': self.trust_scorer.is_trained,
        }

    def get_decision_log(self, host_ip=None, limit=100):
        log = self.decision_log
        if host_ip:
            log = [d for d in log if d['host_ip'] == host_ip]
        return log[-limit:]

    def save_decision_log(self, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(self.decision_log, f, indent=2)
        print(f"[POLICY] Log saved: {filename}")
