#!/bin/bash
# Automatically get the directory of the script and cd into it
cd "$(dirname "$0")"

echo "Starting Controller..."
./venv/bin/python run_controller.py > controller.log 2>&1 &
CTRL_PID=$!
sleep 3

echo "Starting Policy Engine..."
./venv/bin/python run_policy_engine.py > policy_engine.log 2>&1 &
POLICY_PID=$!
sleep 2

echo "Cleaning up Mininet..."
echo "3498" | sudo -S mn -c 2>/dev/null

echo "Running Mininet and generating traffic..."
echo "3498" | sudo -S /usr/bin/python3 run_topology.py --generate-data

echo "Stopping services..."
kill -SIGINT $POLICY_PID
kill $CTRL_PID
echo "3498" | sudo -S mn -c 2>/dev/null

echo "Organizing collected data..."
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUT_DIR="data/collected/$TIMESTAMP"
mkdir -p "$OUT_DIR"

# Move generated mininet JSON traffic logs
mv anomalous_*.json normal_*.json "$OUT_DIR"/ 2>/dev/null
mv data/collected/*.json "$OUT_DIR"/ 2>/dev/null

# Wait for policy engine to save decisions.json (it needs time after SIGINT)
echo "Waiting for policy engine to save decisions..."
for i in $(seq 1 10); do
    if [ -f "data/processed/decisions.json" ]; then
        echo "decisions.json found after ${i}s"
        break
    fi
    sleep 1
done

# Copy logs, commands, and state files for documentation
cp controller.log "$OUT_DIR"/ 2>/dev/null
cp policy_engine.log "$OUT_DIR"/ 2>/dev/null
cp data/controller_state.json "$OUT_DIR"/ 2>/dev/null
cp data/controller_commands.json "$OUT_DIR"/ 2>/dev/null
mv data/processed/decisions.json "$OUT_DIR"/ 2>/dev/null

# Generate the visual charts inside the timestamped folder
./venv/bin/python generate_chart.py "$OUT_DIR"
./venv/bin/python plot_trust_scores.py "$OUT_DIR"

echo "Traffic data, logs, and charts saved to $OUT_DIR/"

echo "Data generation complete!"
