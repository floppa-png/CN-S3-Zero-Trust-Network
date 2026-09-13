#!/bin/bash

echo "========================================================="
echo " Starting Zero Trust SDN Single-Command Demo"
echo "========================================================="

# Ensure dependencies
echo "[*] Ensuring dependencies..."
./venv/bin/python -m pip install matplotlib > /dev/null 2>&1

# Clear old state files to prevent graph oscillation from previous runs
rm -f data/controller_state.json data/controller_commands.json data/processed/decisions.json

# Kill any zombie processes from previous runs that might be hogging ports or keeping old memory state
echo "[*] Cleaning up any old zombie processes..."
pkill -f run_controller.py
pkill -f run_policy_engine.py
sudo mn -c > /dev/null 2>&1
sleep 2

# Clean up redundant/unused files as requested
rm -f ldos_detection_results.png generate_chart.py plot_trust_scores.py debug_scoring.py start_simulation.sh multi_attack_detection_results.png

# 1. Start Controller
echo "[1/4] Starting SDN Controller (Background)..."
./venv/bin/python run_controller.py > /dev/null 2>&1 &
CTRL_PID=$!
sleep 3

# 2. Start Policy Engine
echo "[2/4] Starting Policy Engine (Background)..."
./venv/bin/python run_policy_engine.py > policy_engine.log 2>&1 &
POLICY_PID=$!
sleep 2

# 3. Start Mininet with Traffic Generation
echo "[3/4] Starting Mininet & Traffic Generators (Requires sudo)..."
echo "      (Traffic will run for 60 seconds automatically)"
sudo python3 run_topology.py --generate-data 2>/dev/null

# 4. Graceful Shutdown to save data
echo "[*] Shutting down services to save logs..."
kill -INT $POLICY_PID
kill -INT $CTRL_PID
# Also ensure mininet cleans up
sudo mn -c > /dev/null 2>&1
sleep 3

# 5. Plot Results
echo "[4/4] Generating LDoS Detection Graph..."
./venv/bin/python plot_results.py

echo "========================================================="
echo " Demo complete!"
echo " Check the 'output/' folder for the generated graphs:"
echo "  - output/multi_attack_detection_results.png"
echo "  - output/all_users_trust_scores.png"
echo "========================================================="
