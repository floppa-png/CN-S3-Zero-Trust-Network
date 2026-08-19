#!/usr/bin/env python3
"""
Launch script for the Trust Policy Engine.

Connects to the running Ryu SDN controller, continuously
evaluates host trust scores, and enforces decisions.

Usage:
    ./venv/bin/python run_policy_engine.py [controller_url] [interval]

Defaults:
    controller_url: http://127.0.0.1:8080
    interval:       5 (seconds)
"""

import sys
import os
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.trust_engine.policy_engine import PolicyEngine


def main():
    controller_url = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8080'
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    print("=" * 60)
    print("  Zero Trust Policy Engine")
    print("=" * 60)
    print(f"  Controller URL: {controller_url}")
    print(f"  Eval interval:  {interval}s")
    print("=" * 60)

    engine = PolicyEngine(
        controller_url=controller_url,
        eval_interval=interval,
    )

    # Initialize with synthetic baseline (will be replaced with real data)
    engine.initialize_model()

    def shutdown(sig, frame):
        print("\n[POLICY] Shutting down...")
        engine.stop()
        # Save decision log
        log_path = os.path.join(
            os.path.dirname(__file__), 'data', 'processed', 'decisions.json'
        )
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        engine.save_decision_log(log_path)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    engine.start()

    # Keep main thread alive
    print("[POLICY] Engine running. Press Ctrl+C to stop.")
    try:
        while True:
            import time
            time.sleep(10)
            status = engine.get_status()
            print(f"[POLICY] Status: {status['scores']}")
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == '__main__':
    main()
