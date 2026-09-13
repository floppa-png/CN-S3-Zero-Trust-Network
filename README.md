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

## Quick Start (One-Click Demo)

We have fully automated the entire orchestration (Controller, Policy Engine, Mininet, and Traffic Generation) into a single executable script.

```bash
chmod +x demo.sh
./demo.sh
```

**What the script does automatically:**
1. Boots the SDN Controller (Ryu) in the background.
2. Boots the Trust Policy Engine in the background.
3. Starts the Mininet Topology (requires sudo password).
4. Automatically generates normal employee traffic and randomized multi-vector attack traffic (LDoS, Port Scans, etc.) for 60 seconds.
5. Cleans up all background processes safely.
6. Generates two visual proof graphs in the `output/` directory and a Terminal Scorecard.

## Project Structure

```
zero_trust_sdn/
├── src/
│   ├── topology/          # Mininet network topology
│   ├── traffic/           # Multithreaded traffic generators (Normal & Attack)
│   ├── sdn_controller/    # Ryu OpenFlow controller
│   └── trust_engine/      # Feature extraction + ML scoring + policy enforcement
├── data/                  # Timestamped packet logs and decision states
├── output/                # Generated visualizations of the attack and trust scores
├── demo.sh                # Main automated orchestration script
├── plot_results.py        # Graph generator script
├── instruction.txt        # Demo workflow guide for presentation
└── requirements.txt
```

## Trust Score Scale

| Score | Action | Description |
|-------|--------|-------------|
| 80-100 | ALLOW | Full access, no restrictions |
| 50-79 | RATE_LIMIT | Bandwidth throttle / step-up auth |
| 20-49 | RESTRICT | Limited destinations only |
| 0-19 | BLOCK | Drop all traffic |
