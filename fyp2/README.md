# Zero-Day Attack Detection System

## Self-Supervised Behavioral Graph-Based Detection with Continual Learning

**Anna University Final Year Project - Phase 2**

---

## 📋 Project Overview

This project implements a **zero-day attack detection system** that can identify previously unseen attacks without requiring attack labels for training. It combines three state-of-the-art approaches from recent research:

1. **Self-Supervised Learning** - No attack labels needed
2. **Heterogeneous Temporal Graphs** - Captures system behavior relationships
3. **Continual Learning** - Adapts to new attacks without forgetting

---

## 🎯 Three-Phase Implementation

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Core Detection System |
| **Phase 2** | 🔄 Pending | Attack Progression + MITRE + Explainability |
| **Phase 3** | 🔄 Pending | Continual Learning + Evaluation + API |

---

## 📦 Phase 1: Core Detection System

### What's Implemented

1. **Data Collection** (`src/data/collector.py`)
   - Simulated syscall event collector
   - Attack pattern simulator

2. **Graph Construction** (`src/data/graph_builder.py`)
   - Converts events to heterogeneous graphs
   - 3 node types: PROCESS, FILE, SOCKET
   - 5 edge types: executes, reads, writes, spawns, connects

3. **Graph Autoencoder** (`src/models/autoencoder.py`)
   - GCN-based encoder
   - Inner product decoder
   - Self-supervised training

4. **Anomaly Detection** (`src/detection/enhanced_detector.py`)
   - Hybrid detector (structural + reconstruction)
   - Z-score based anomaly scoring
   - Alert generation

### Running Phase 1

#### Option 1: Simulated Demo (Quick Test)
```bash
# Install dependencies
pip install -r requirements.txt

# Run the demo
python run_phase1.py
```

#### Option 2: Real-Time Monitoring (Live System)
```bash
# Install dependencies (includes psutil & watchdog)
pip install -r requirements.txt

# Test real-time collector
python test_realtime.py

# Run real-time detection
python run_realtime_demo.py
```

**Real-Time Mode Features:**
- ✅ Monitors actual system processes
- ✅ Tracks real network connections
- ✅ Detects live anomalies on your system
- ✅ Works on Windows and Linux
- ⚠️  Requires active system usage to collect events

### Expected Output
- 100% detection rate on simulated attacks
- 0% false positive rate on normal behavior
- Visualization saved to `phase1_results.png`

---

## 🔬 Technical Details

### Model Architecture
```
Input: 6-dim node features
  ↓
GCN Layer 1: 6 → 64
  ↓ ReLU + Dropout
GCN Layer 2: 64 → 32
  ↓
Inner Product Decoder
  ↓
Reconstructed Adjacency Matrix
```

### Detection Method
1. **Structural Features**: Node type distribution, degree statistics
2. **Reconstruction Error**: How well the model reconstructs the graph
3. **Z-Score Threshold**: Flag as anomaly if score > μ + 2.5σ

---

## 📅 Upcoming Phases

### Phase 2: Attack Progression + Explainability
- Attack stage identification (Reconnaissance → Exploitation → Exfiltration)
- MITRE ATT&CK mapping
- Explainable alerts (which nodes/edges are suspicious)

### Phase 3: Continual Learning
- Experience replay for new attack patterns
- Elastic Weight Consolidation (prevent forgetting)
- Full evaluation framework
- REST API for integration

---

## 📚 Research Papers Referenced

1. **Continual Learning for IDS** - IEEE Access 2025 (IIT Bhubaneswar)
2. **Zero-Day Detection with Autoencoders** - PLOS ONE 2025
3. **Self-Supervised Heterogeneous Hypergraph Learning** - WSDM 2025

---

## 🏗️ Project Structure

```
project/
├── src/
│   ├── data/
│   │   ├── schemas.py        # Data structures
│   │   ├── collector.py      # Event collection
│   │   ├── attack_simulator.py  # Attack generation
│   │   └── graph_builder.py  # Graph construction
│   ├── models/
│   │   ├── autoencoder.py    # Graph Autoencoder
│   │   └── trainer.py        # Training logic
│   ├── detection/
│   │   ├── detector.py       # Basic detector
│   │   └── enhanced_detector.py  # Hybrid detector
│   └── visualization/
│       └── __init__.py       # Plotting functions
├── run_phase1.py             # Phase 1 demo
├── requirements.txt          # Dependencies
└── README.md                 # This file
```

---

## 👨‍🎓 Author

Anna University Final Year Project

---

## 📄 License

Academic use only.
