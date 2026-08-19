"""
REST API Server for the Zero Trust SDN System.

Flask-based REST API that reads controller state and pushes
commands to the SDN controller via shared JSON files.

Endpoints:
    GET  /trust/scores    - View all trust scores
    POST /trust/scores    - Update a host's trust score
    GET  /trust/flows     - View flow statistics
    GET  /trust/actions   - View enforcement actions
    GET  /trust/status    - Full system status
"""

import json
import os
import time
from flask import Flask, jsonify, request

# Shared state files
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data')
STATE_FILE = os.path.join(DATA_DIR, 'controller_state.json')
COMMANDS_FILE = os.path.join(DATA_DIR, 'controller_commands.json')

os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)


def read_state():
    """Read the current controller state."""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return {
        'trust_scores': {}, 'enforcement_actions': {},
        'blocked_hosts': [], 'flow_stats': {}, 'switch_count': 0,
    }


def push_command(cmd):
    """Push a command to the controller."""
    try:
        commands = []
        if os.path.exists(COMMANDS_FILE):
            with open(COMMANDS_FILE, 'r') as f:
                commands = json.load(f)
        commands.append(cmd)
        with open(COMMANDS_FILE, 'w') as f:
            json.dump(commands, f)
    except Exception as e:
        print(f"Error pushing command: {e}")


@app.route('/trust/scores', methods=['GET'])
def get_scores():
    state = read_state()
    return jsonify(state.get('trust_scores', {}))


@app.route('/trust/scores', methods=['POST'])
def update_score():
    data = request.get_json()
    if not data or 'ip' not in data or 'score' not in data:
        return jsonify({'error': 'Missing ip or score'}), 400

    cmd = {
        'type': 'update_score',
        'ip': data['ip'],
        'score': float(data['score']),
        'timestamp': time.time(),
    }
    push_command(cmd)
    return jsonify({'status': 'queued', 'command': cmd})


@app.route('/trust/flows', methods=['GET'])
def get_flows():
    state = read_state()
    return jsonify(state.get('flow_stats', {}))


@app.route('/trust/actions', methods=['GET'])
def get_actions():
    state = read_state()
    return jsonify(state.get('enforcement_actions', {}))


@app.route('/trust/status', methods=['GET'])
def get_status():
    state = read_state()
    return jsonify(state)


if __name__ == '__main__':
    print("=" * 60)
    print("  Zero Trust REST API Server")
    print("=" * 60)
    print("  Port: 8080")
    print("  Endpoints:")
    print("    GET  /trust/scores")
    print("    POST /trust/scores")
    print("    GET  /trust/flows")
    print("    GET  /trust/actions")
    print("    GET  /trust/status")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8080, debug=False)
