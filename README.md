# AI-Driven, SDN-Enforced Continuous Trust Scoring for Zero Trust Networks

> **Group 13** — CN Project (25AID202 - Introduction to Computer Networks)
>
> Mrityunjay V | Pavithiran P | Sanjit KR | Vishal B

## Overview

This system implements a **continuous trust scoring architecture** that bridges
the gap between one-time login authentication and true session-long Zero Trust
verification. Instead of trusting a session after a single login check, our
system continuously evaluates host behavior and enforces access decisions in
real-time through an SDN controller.

### Architecture

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Employee │  │ Employee │  │  Server  │  │ Attacker │
│   h1     │  │   h2     │  │   h3     │  │   h4     │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     └─────────────┴──────┬──────┴─────────────┘
                          │
                    ┌─────┴─────┐
                    │ OVS Switch│  (OpenFlow 1.3)
                    │    s1     │
                    └─────┬─────┘
                          │
                    ┌─────┴─────┐
                    │    Ryu    │  SDN Controller
                    │ Controller│  + REST API
                    └─────┬─────┘
                          │
                    ┌─────┴─────┐
                    │  Trust    │  Feature Extraction
                    │  Engine   │  + Isolation Forest
                    └─────┬─────┘
                          │
                    ┌─────┴─────┐
                    │  Policy   │  Score → Action
                    │  Engine   │  (allow/block/...)
                    └───────────┘
```

## Quick Start

### 1. Start the SDN Controller
```bash
./venv/bin/ryu-manager src/sdn_controller/trust_controller.py \
    --ofp-tcp-listen-port 6633 --wsapi-port 8080
```

### 2. Start the Mininet Topology (in another terminal)
```bash
sudo ./venv/bin/python run_topology.py
```

### 3. Start the Policy Engine (in another terminal)
```bash
./venv/bin/python run_policy_engine.py
```

### 4. Generate Traffic (from the Mininet CLI)
```
# Normal traffic from employee h1
mininet> h1 python3 src/traffic/normal_traffic.py 10.0.0.1 10.0.0.3 60 &

# Attack traffic from h4
mininet> h4 python3 src/traffic/anomalous_traffic.py 10.0.0.4 10.0.0.3 60 &
```

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/trust/scores` | GET | View all trust scores |
| `/trust/scores` | POST | Update a host's trust score |
| `/trust/flows` | GET | View flow statistics |
| `/trust/actions` | GET | View enforcement actions |
| `/trust/status` | GET | Full system status |

## Project Structure

```
zero_trust_sdn/
├── src/
│   ├── topology/          # Mininet network topology
│   ├── traffic/           # Normal + anomalous traffic generators
│   ├── sdn_controller/    # Ryu OpenFlow controller
│   ├── trust_engine/      # Feature extraction + ML scoring + policy
│   ├── explainability/    # SHAP explainer (Phase 4)
│   └── dashboard/         # Streamlit dashboard (Phase 5)
├── data/                  # Collected and processed data
├── models/                # Saved ML models
├── run_topology.py        # Launch Mininet
├── run_controller.py      # Launch Ryu controller
├── run_policy_engine.py   # Launch trust evaluation
└── requirements.txt
```

## Trust Score Scale

| Score | Action | Description |
|-------|--------|-------------|
| 80-100 | ALLOW | Full access, no restrictions |
| 50-79 | RATE_LIMIT | Bandwidth throttle / step-up auth |
| 20-49 | RESTRICT | Limited destinations only |
| 0-19 | BLOCK | Drop all traffic |
