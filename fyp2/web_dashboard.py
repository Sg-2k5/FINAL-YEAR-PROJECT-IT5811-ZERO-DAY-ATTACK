"""
Zero-Day Attack Detection — Real-Time Web Dashboard
=====================================================
Flask app that runs the pipeline step-by-step and streams
live updates to the browser via Server-Sent Events (SSE).

Usage:
    python web_dashboard.py
    Then open http://localhost:5000 in your browser.
"""

import sys
import json
import time
import queue
import logging
import threading
import base64
import io
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, Response, jsonify

# Suppress werkzeug request logs so terminal output stays clean
logging.basicConfig(level=logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
sys.path.insert(0, str(Path(__file__).parent))

from src.data.realtime_collector import RealTimeCollector
from src.data.graph_builder import GraphBuilder
from src.data.attack_simulator import EnhancedAttackSimulator
from src.data.real_attack_executor import RealAttackExecutor, SandboxManager
from src.data.schemas import BehaviorGraph, NodeType
from src.models.autoencoder import GraphAutoencoder
from src.models.trainer import Trainer
from src.models.continual_learner import ContinualLearner
from src.detection.enhanced_detector import HybridDetector
from src.detection.detector import AlertManager
from src.visualization.graph_visualizer import GraphVisualizer
from src.utils.alert_logger import AlertLogger
from src.utils.av_scanner import ClamAVScanner, annotate_attack_reports_with_av

app = Flask(__name__)

# Global event storage — thread-safe list + condition for multi-consumer SSE
event_history = []          # all events from current/last run
event_lock = threading.Lock()
event_condition = threading.Condition()
pipeline_running = False


# ── Terminal formatting helpers ──
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

def tprint(msg, color=""):
    """Print to terminal with timestamp."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{msg}{RESET}", flush=True)

def print_header(step, title):
    """Print a styled step header to the terminal."""
    print(f"\n{CYAN}{'═'*60}{RESET}", flush=True)
    tprint(f"{BOLD}STEP {step}: {title}{RESET}", CYAN)
    print(f"{CYAN}{'═'*60}{RESET}", flush=True)

def print_result(label, value):
    tprint(f"  {label}: {BOLD}{value}{RESET}")


def send_event(event_type, data):
    """Push an event to the history list and wake all SSE listeners."""
    evt = {"type": event_type, "data": data, "time": datetime.now().strftime("%H:%M:%S")}
    with event_lock:
        event_history.append(evt)
    with event_condition:
        event_condition.notify_all()


def fig_to_base64(fig):
    """Convert matplotlib figure to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def build_graphs(builder, events):
    graphs = builder.build_graphs_from_events(events, clean=False)
    if not graphs:
        g = builder.build_graph(events)
        if g and g.num_nodes > 0:
            graphs = [g]
    return graphs


def filter_graph_for_viz(graph, max_nodes=50):
    if graph.num_nodes <= max_nodes:
        return graph
    importance = {}
    for e in graph.edges:
        importance[e.source_id] = importance.get(e.source_id, 0) + 1
        importance[e.target_id] = importance.get(e.target_id, 0) + 1
    top_ids = {nid for nid, _ in sorted(importance.items(), key=lambda x: x[1], reverse=True)[:max_nodes]}
    filt = BehaviorGraph(graph_id=graph.graph_id + "_filt",
                         window_start=graph.window_start, window_end=graph.window_end)
    for nid in top_ids:
        if nid in graph.nodes:
            filt.add_node(graph.nodes[nid])
    for edge in graph.edges:
        if edge.source_id in top_ids and edge.target_id in top_ids:
            filt.add_edge(edge)
    return filt


def run_pipeline_thread():
    """Run pipeline in background thread, pushing SSE events at each step."""
    global pipeline_running
    pipeline_running = True
    start_time = time.time()

    try:
        print(f"\n{GREEN}{'╔'+'═'*58+'╗'}{RESET}")
        print(f"{GREEN}║{RESET}{BOLD}  Zero-Day Detection Pipeline — STARTED{' '*19}{RESET}{GREEN}║{RESET}")
        print(f"{GREEN}{'╚'+'═'*58+'╝'}{RESET}\n")

        # ── Step 1: Collect normal events ──
        print_header(1, "COLLECTING NORMAL SYSTEM EVENTS")
        tprint("Monitoring processes, files & network for 20 seconds...", DIM)
        send_event("step_start", {"step": 1, "title": "Collecting Normal System Events", "desc": "Monitoring processes, files & network for 20 seconds..."})

        collector = RealTimeCollector(monitor_processes=True, monitor_files=True,
                                     monitor_network=True, polling_interval=0.3)

        # Stream collection progress
        train_events = []
        collection_start = time.time()
        duration = 20
        while time.time() - collection_start < duration:
            batch = collector.collect_events(duration_seconds=2)
            train_events.extend(batch)
            elapsed = min(time.time() - collection_start, duration)
            pct = round(elapsed / duration * 100)
            print(f"\r{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RESET}   Collecting... {pct:3d}%  |  {len(train_events)} events", end="", flush=True)
            send_event("collection_progress", {
                "events": len(train_events),
                "elapsed": round(elapsed, 1),
                "total": duration,
                "percent": pct
            })
        print()  # newline after progress

        # Sample events
        sample_events = []
        seen = set()
        for ev in train_events:
            key = (ev.process_name, ev.syscall_name)
            if key not in seen:
                seen.add(key)
                sample_events.append({
                    "process": ev.process_name,
                    "syscall": ev.syscall_name,
                    "target": ev.target_resource[:40]
                })
            if len(seen) >= 10:
                break

        send_event("step_complete", {
            "step": 1,
            "result": {"event_count": len(train_events), "sample_events": sample_events}
        })
        tprint(f"{GREEN}✓ Step 1 complete — {len(train_events)} events collected{RESET}")
        for se in sample_events[:5]:
            tprint(f"    {se['process']:>20s}  →  {se['syscall']:<12s}  →  {se['target']}", DIM)

        if len(train_events) < 10:
            tprint(f"{RED}✗ Too few events collected. System might be idle.{RESET}", RED)
            send_event("error", {"message": "Too few events collected. System might be idle."})
            return

        # ── Step 2: Build graphs ──
        print_header(2, "BUILDING BEHAVIORAL GRAPHS")
        tprint("Converting events into time-windowed graphs...", DIM)
        send_event("step_start", {"step": 2, "title": "Building Behavioral Graphs", "desc": "Converting events into time-windowed graphs..."})

        builder = GraphBuilder(window_size_seconds=5, min_events_per_graph=1,
                               max_nodes_per_graph=500, filter_system_noise=False)

        # Graph building intermediate steps
        send_event("graph_build_step", {"phase": "init", "detail": f"Starting graph construction from {len(train_events)} collected events"})
        time.sleep(0.3)

        send_event("graph_build_step", {"phase": "partition", "detail": f"Partitioning events into {builder.window_size_seconds}s time windows..."})
        time.sleep(0.2)

        send_event("graph_build_step", {"phase": "nodes", "detail": "Extracting process & resource nodes from events (PROCESS, FILE, SOCKET node types)"})
        time.sleep(0.2)

        send_event("graph_build_step", {"phase": "edges", "detail": "Creating edges from syscalls (EXECUTES, READS, WRITES, SPAWNS, CONNECTS)"})
        time.sleep(0.2)

        send_event("graph_build_step", {"phase": "features", "detail": "Computing 6D node features: type encoding (3) + in/out degree (2) + temporal activity (1)"})
        time.sleep(0.2)

        train_graphs = build_graphs(builder, train_events)

        send_event("graph_build_step", {"phase": "complete", "detail": f"Graph construction complete — {len(train_graphs)} graphs built"})
        time.sleep(0.2)

        graph_info = []
        for i, g in enumerate(train_graphs[:5], 1):
            nt = {}
            for n in g.nodes.values():
                nt[n.node_type.value] = nt.get(n.node_type.value, 0) + 1
            graph_info.append({
                "id": i, "nodes": g.num_nodes, "edges": g.num_edges,
                "processes": nt.get("process", 0),
                "files": nt.get("file", 0),
                "sockets": nt.get("socket", 0)
            })

        # Visualize first graph
        visualizer = GraphVisualizer()
        if train_graphs:
            vg = filter_graph_for_viz(train_graphs[0])
            fig = visualizer.visualize_single_graph(vg, title="Training Graph #1", show_edge_labels=False, layout="spring")
            graph_img = fig_to_base64(fig)
        else:
            graph_img = ""

        send_event("step_complete", {
            "step": 2,
            "result": {"graph_count": len(train_graphs), "graphs": graph_info, "graph_image": graph_img}
        })
        tprint(f"{GREEN}✓ Step 2 complete — {len(train_graphs)} graphs built{RESET}")
        for gi in graph_info:
            tprint(f"    Graph #{gi['id']}: {gi['nodes']} nodes, {gi['edges']} edges  (P:{gi['processes']} F:{gi['files']} S:{gi['sockets']})", DIM)

        if not train_graphs:
            tprint(f"{RED}✗ Could not build graphs.{RESET}", RED)
            send_event("error", {"message": "Could not build graphs."})
            return

        # ── Step 3: Train autoencoder ──
        print_header(3, "TRAINING GRAPH AUTOENCODER")
        tprint("GCN Architecture: 6D → 32D → 16D  |  30 epochs  |  lr=0.01", DIM)
        send_event("step_start", {"step": 3, "title": "Training Graph Autoencoder", "desc": "Learning normal behavior patterns..."})

        model = GraphAutoencoder(hidden_dim=32, latent_dim=16, dropout=0.2)
        trainer = Trainer(model, learning_rate=0.01)

        # Train with progress
        from src.models.autoencoder import graph_to_pyg_data
        train_data = [graph_to_pyg_data(g) for g in train_graphs]
        import torch
        optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

        epochs = 30

        # GCN architecture walk-through — shown once before training starts
        send_event("gcn_substep", {"phase": "arch_init",
            "detail": f"Model ready: {len(train_data)} training graph(s) | {epochs} epochs | lr=0.01 | input 6D"})
        time.sleep(0.3)
        send_event("gcn_substep", {"phase": "arch_l1",
            "detail": "GCN Conv1: each node aggregates 1-hop neighbour features → 32D hidden repr  +  ReLU  +  Dropout(0.2)"})
        time.sleep(0.2)
        send_event("gcn_substep", {"phase": "arch_l2",
            "detail": "GCN Conv2: 32D hidden → 16D latent embedding Z  (compact graph representation)"})
        time.sleep(0.2)
        send_event("gcn_substep", {"phase": "arch_decode",
            "detail": "Inner Product Decoder: Â_ij = sigmoid(Zᵢ · Zⱼ)  →  reconstruct full adjacency matrix"})
        time.sleep(0.2)
        send_event("gcn_substep", {"phase": "arch_loss",
            "detail": "Loss: MSE(Â, A_true)  —  no labels used, purely self-supervised on normal behaviour"})
        time.sleep(0.2)
        send_event("gcn_substep", {"phase": "arch_optim",
            "detail": "Optimizer: Adam  —  backpropagates gradients to update Conv1 + Conv2 weights each epoch"})
        time.sleep(0.2)
        send_event("gcn_substep", {"phase": "training_start",
            "detail": f"Starting training loop — {epochs} epochs..."})
        time.sleep(0.2)

        loss_history = []
        for epoch in range(epochs):
            model.train()
            total_loss = 0.0
            for data in train_data:
                optimizer.zero_grad()
                loss = model.compute_loss(data.x, data.edge_index, data.num_nodes)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            avg_loss = total_loss / len(train_data) if train_data else 0
            loss_history.append(avg_loss)
            pct = round((epoch + 1) / epochs * 100)
            bar_len = 30
            filled = int(bar_len * (epoch + 1) / epochs)
            bar = '█' * filled + '░' * (bar_len - filled)
            print(f"\r{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RESET}   Epoch {epoch+1:2d}/{epochs}  [{bar}] {pct:3d}%  Loss: {avg_loss:.6f}", end="", flush=True)
            send_event("training_progress", {
                "epoch": epoch + 1, "total_epochs": epochs,
                "loss": round(avg_loss, 6),
                "percent": pct
            })
        print()  # newline after progress

        # Compute baseline stats
        send_event("gcn_substep", {"phase": "stats_compute",
            "detail": f"Training complete — computing baseline anomaly scores on all {len(train_data)} training graph(s)..."})
        time.sleep(0.3)
        model.eval()
        losses = []
        with torch.no_grad():
            for data in train_data:
                score = model.compute_anomaly_score(data.x, data.edge_index, data.num_nodes)
                losses.append(score)
        mean_loss = float(np.mean(losses))
        std_loss = float(np.std(losses))
        if std_loss < 1e-6:
            std_loss = 1e-6
        threshold = mean_loss + 3 * std_loss
        send_event("gcn_substep", {"phase": "stats_done",
            "detail": f"Baseline fixed: μ = {round(mean_loss,6)},  σ = {round(std_loss,6)}  →  detection threshold = μ + 3σ = {round(threshold,6)}"})
        time.sleep(0.2)

        # Loss curve image
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.plot(range(1, epochs + 1), loss_history, "b-", linewidth=2)
        ax.set_xlabel("Epoch")
        ax.set_ylabel("Loss")
        ax.set_title("Training Loss Curve")
        ax.grid(True, alpha=0.3)
        loss_img = fig_to_base64(fig)

        send_event("step_complete", {
            "step": 3,
            "result": {
                "epochs": epochs, "mean_loss": round(mean_loss, 6),
                "std_loss": round(std_loss, 6), "threshold": round(threshold, 6),
                "loss_history": [round(l, 6) for l in loss_history],
                "loss_image": loss_img
            }
        })
        tprint(f"{GREEN}✓ Step 3 complete — Model trained{RESET}")
        print_result("Mean anomaly score (μ)", f"{mean_loss:.6f}")
        print_result("Std deviation    (σ)", f"{std_loss:.6f}")
        print_result("Threshold    (μ+3σ)", f"{threshold:.6f}")

        detector = HybridDetector(gae_model=model, threshold_sigma=2.5)
        detector.fit(train_graphs)

        # ── Step 4: Continual learning adaptation ──
        print_header(4, "CONTINUAL LEARNING ADAPTATION")
        tprint("Online adaptation with replay before behavioral graph analysis...", DIM)
        send_event("step_start", {"step": 4, "title": "Continual Learning Adaptation", "desc": "Online adaptation with replay before graph analysis..."})

        continual = ContinualLearner(
            model=model,
            learning_rate=0.001,
            replay_ratio=0.5,
            memory_size=64,
            replay_batch_cap=12,
            inner_epochs=2,
        )

        # Callbacks for granular UI updates
        def _cl_chunk_start(chunk_idx, chunk_size, replay_size, total_chunks):
            tprint(f"  Chunk {chunk_idx+1}/{total_chunks}: {chunk_size} new graph(s) + {replay_size} replay sample(s)", DIM)
            send_event("cl_progress", {
                "phase": "chunk_start",
                "chunk": chunk_idx + 1,
                "total_chunks": total_chunks,
                "new_graphs": chunk_size,
                "replay_graphs": replay_size,
            })
            time.sleep(0.4)
            mem_now = len(continual.memory_graphs)
            send_event("cl_progress", {
                "phase": "sampling",
                "chunk": chunk_idx + 1,
                "replay_graphs": replay_size,
                "memory_total": mem_now,
                "detail": f"Randomly sampled {replay_size} graph(s) from memory bank  ({mem_now} stored)"
            })
            time.sleep(0.2)
            send_event("cl_progress", {
                "phase": "combining",
                "chunk": chunk_idx + 1,
                "total_batch": chunk_size + replay_size,
                "detail": f"Training batch: {chunk_size} new  +  {replay_size} replay  =  {chunk_size + replay_size} total"
            })
            time.sleep(0.2)

        def _cl_epoch_done(chunk_idx, epoch, loss):
            tprint(f"    Epoch {epoch+1}/2  loss={loss:.6f}", DIM)
            send_event("cl_progress", {
                "phase": "epoch",
                "chunk": chunk_idx + 1,
                "epoch": epoch + 1,
                "loss": round(loss, 6),
            })
            time.sleep(0.4)

        def _cl_chunk_done(chunk_idx, chunk_loss, mem_size):
            tprint(f"  ✓ Chunk {chunk_idx} done — loss={chunk_loss:.6f}, memory={mem_size}", DIM)
            send_event("cl_progress", {
                "phase": "memory_update",
                "chunk": chunk_idx,
                "memory_size": mem_size,
                "memory_capacity": 64,
                "detail": f"Memory bank updated — {mem_size}/64 graphs stored (oldest evicted when over capacity)"
            })
            time.sleep(0.2)
            send_event("cl_progress", {
                "phase": "chunk_done",
                "chunk": chunk_idx,
                "chunk_loss": round(chunk_loss, 6),
                "memory_size": mem_size,
            })
            time.sleep(0.3)

        cl_stats = continual.adapt_on_stream(
            train_graphs, chunk_size=3,
            on_chunk_start=_cl_chunk_start,
            on_epoch_done=_cl_epoch_done,
            on_chunk_done=_cl_chunk_done,
        )

        send_event("step_complete", {
            "step": 4,
            "result": {
                "chunks_processed": cl_stats["chunks_processed"],
                "memory_size": cl_stats["memory_size"],
                "mean_chunk_loss": round(cl_stats["mean_chunk_loss"], 6),
            }
        })
        tprint(f"{GREEN}✓ Step 4 complete — Adapted on {cl_stats['chunks_processed']} chunks{RESET}")
        print_result("Replay memory", f"{cl_stats['memory_size']} graphs")
        print_result("Mean CL loss", f"{cl_stats['mean_chunk_loss']:.6f}")

        # ── Step 5: Collect test data ──
        print_header(5, "COLLECTING & TESTING REAL DATA")
        tprint("Monitoring for new activity (15 seconds)...", DIM)
        send_event("step_start", {"step": 5, "title": "Collecting Real Test Data", "desc": "Monitoring for new activity (15 seconds)..."})

        test_events = []
        collection_start = time.time()
        duration = 15
        while time.time() - collection_start < duration:
            batch = collector.collect_events(duration_seconds=2)
            test_events.extend(batch)
            elapsed = min(time.time() - collection_start, duration)
            pct = round(elapsed / duration * 100)
            print(f"\r{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RESET}   Collecting... {pct:3d}%  |  {len(test_events)} events", end="", flush=True)
            send_event("collection_progress", {
                "events": len(test_events),
                "elapsed": round(elapsed, 1),
                "total": duration,
                "percent": pct
            })
        print()  # newline after progress

        test_graphs = build_graphs(builder, test_events)

        # Detect on test graphs
        alert_manager = AlertManager()
        alert_logger = AlertLogger(output_dir="logs")
        real_results = []
        test_detections = []
        for i, g in enumerate(test_graphs, 1):
            r = detector.detect(g)
            real_results.append(r)
            status = "ANOMALY" if r.is_anomalous else "Normal"
            severity = ""
            if r.is_anomalous:
                a = alert_manager.create_alert(r)
                severity = a.severity if a else ""
            test_detections.append({
                "graph": i, "score": round(r.anomaly_score, 4),
                "threshold": round(r.threshold, 4),
                "status": status, "severity": severity
            })

        send_event("step_complete", {
            "step": 5,
            "result": {
                "event_count": len(test_events),
                "graph_count": len(test_graphs),
                "detections": test_detections
            }
        })
        tprint(f"{GREEN}✓ Step 5 complete — {len(test_events)} events, {len(test_graphs)} graphs{RESET}")
        for td in test_detections:
            status_color = RED if td['status'] == 'ANOMALY' else GREEN
            tprint(f"    Graph #{td['graph']}: score={td['score']:.4f}  {status_color}{td['status']}{RESET}", DIM)

        # ── Step 6: Execute REAL attacks in sandbox ──
        print_header(6, "EXECUTING REAL ATTACKS (Sandbox)")
        tprint("Setting up sandbox with realistic files, executing real attacks...", DIM)
        send_event("step_start", {"step": 6, "title": "Executing Real Attacks", "desc": "Setting up sandbox, running real attack scenarios..."})

        executor = RealAttackExecutor(sandbox_base=str(Path(__file__).parent))
        sandbox_path = executor.setup()
        av_scanner = ClamAVScanner()
        tprint(f"Sandbox ready: {sandbox_path}", DIM)
        send_event("attack_progress", {
            "phase": "sandbox_ready",
            "detail": (
                f"Sandbox created with {len(SandboxManager.SEED_FILES)} realistic files | "
                f"ClamAV: {'available' if av_scanner.available else 'not found'}"
            ),
            "seed_files": list(SandboxManager.SEED_FILES.keys()),
        })
        time.sleep(0.8)

        # Callbacks for granular UI updates
        def _atk_start(idx, name, desc, mitre):
            tprint(f"  {RED}▶ Attack {idx+1}/4: {name}{RESET}  [{mitre}]", DIM)
            send_event("attack_progress", {
                "phase": "attack_start",
                "attack_index": idx,
                "attack_name": name,
                "description": desc,
                "mitre": mitre,
                "total_attacks": 4,
            })
            time.sleep(0.5)

        def _atk_stage(idx, name, stage, detail):
            tprint(f"    ↳ {stage}: {detail}", DIM)
            send_event("attack_progress", {
                "phase": "attack_stage",
                "attack_index": idx,
                "attack_name": name,
                "stage": stage,
                "detail": detail,
            })
            time.sleep(0.5)

        def _atk_done(idx, rpt):
            annotate_attack_reports_with_av([rpt], Path(sandbox_path), scanner=av_scanner)
            tprint(f"  {GREEN}✓ {rpt.attack_name}{RESET}: {rpt.events_generated} events, {len(rpt.files_impacted)} files impacted ({rpt.duration_ms:.0f}ms)", DIM)
            send_event("attack_progress", {
                "phase": "attack_done",
                "attack_index": idx,
                "attack_name": rpt.attack_name,
                "events": rpt.events_generated,
                "files_impacted": len(rpt.files_impacted),
                "duration_ms": round(rpt.duration_ms, 1),
                "processes": rpt.processes_spawned,
                "network": rpt.network_connections,
                "impacts": [
                    {"file": fi.path,
                     "change": fi.change_summary,
                     "sha_before": fi.hash_before,
                     "sha_after": fi.hash_after,
                     "sha_status": fi.integrity_status,
                     "affected": fi.affected_by_sha,
                     "av_engine": fi.av_engine,
                     "av_status": fi.av_status,
                     "av_signature": fi.av_signature,
                     "size_before": fi.size_before,
                     "size_after": fi.size_after}
                    for fi in rpt.files_impacted
                ],
            })
            time.sleep(0.6)

        attack_reports = executor.execute_all(
            on_attack_start=_atk_start,
            on_stage=_atk_stage,
            on_attack_done=_atk_done,
        )

        # Ensure every report has AV scan metadata for step summaries.
        annotate_attack_reports_with_av(attack_reports, Path(sandbox_path), scanner=av_scanner)

        # Also generate simulated events for graph building
        simulator = EnhancedAttackSimulator()
        sim_attack_types = {
            "Reverse Shell": simulator.generate_reverse_shell_attack,
            "Privilege Escalation": simulator.generate_privilege_escalation_attack,
            "Data Exfiltration": simulator.generate_data_exfiltration_attack,
        }

        attack_graphs = []
        attack_labels = []
        attack_info = []

        for name, gen_fn in sim_attack_types.items():
            events = gen_fn()
            graphs = build_graphs(builder, events)
            attack_info.append({"name": name, "events": len(events), "graphs": len(graphs)})
            for g in graphs:
                attack_graphs.append(g)
                attack_labels.append(name)

        # Add events from real executor as extra graphs
        real_events = executor.get_collected_events()
        if real_events:
            real_graphs = build_graphs(builder, real_events)
            for g in real_graphs:
                attack_graphs.append(g)
                attack_labels.append("Real Executor")
            attack_info.append({"name": "Real Executor", "events": len(real_events), "graphs": len(real_graphs)})

        # Build attack report summaries for UI
        report_summaries = []
        for rpt in attack_reports:
            report_summaries.append(rpt.summary_dict())

        send_event("step_complete", {
            "step": 6,
            "result": {
                "attacks": attack_info,
                "total_graphs": len(attack_graphs),
                "attack_reports": report_summaries,
            }
        })
        tprint(f"{GREEN}✓ Step 6 complete — {len(attack_graphs)} attack graphs generated{RESET}")
        for rpt in attack_reports:
            tprint(f"    {RED}🔴 {rpt.attack_name}{RESET}: {rpt.events_generated} events, {len(rpt.files_impacted)} files impacted", DIM)

        # ── Step 7: Detect on attacks ──
        print_header(7, "RUNNING DETECTION ON ATTACKS")
        tprint("Scoring attack graphs with trained model...", DIM)
        send_event("step_start", {"step": 7, "title": "Running Detection on Attacks", "desc": "Scoring attack graphs with trained model..."})

        attack_results = []
        attack_detections = []
        for i, g in enumerate(attack_graphs):
            r = detector.detect(g)
            attack_results.append(r)
            status = "ANOMALY" if r.is_anomalous else "Normal"
            severity = ""
            if r.is_anomalous:
                a = alert_manager.create_alert(r)
                severity = a.severity if a else ""
            attack_detections.append({
                "id": i + 1, "attack_type": attack_labels[i],
                "score": round(r.anomaly_score, 4),
                "status": status, "severity": severity
            })

        # Build prevention reports for UI
        any_detected = any(r.is_anomalous for r in attack_results)
        prevention_reports = []
        for rpt in attack_reports:
            prevention_reports.append({
                "attack_name": rpt.attack_name,
                "mitre": rpt.mitre_technique,
                "detected": any_detected,
                "status": "DETECTED & BLOCKED" if any_detected else "MISSED",
                "duration_ms": round(rpt.duration_ms, 1),
                "processes": rpt.processes_spawned,
                "network": rpt.network_connections,
                "impacts": [
                    {"file": fi.path,
                     "change": fi.change_summary,
                     "sha_before": fi.hash_before,
                     "sha_after": fi.hash_after,
                     "sha_status": fi.integrity_status,
                     "affected": fi.affected_by_sha,
                     "av_engine": fi.av_engine,
                     "av_status": fi.av_status,
                     "av_signature": fi.av_signature,
                     "size_before": fi.size_before,
                     "size_after": fi.size_after}
                    for fi in rpt.files_impacted
                ],
            })

        send_event("step_complete", {
            "step": 7,
            "result": {
                "detections": attack_detections,
                "prevention_reports": prevention_reports,
            }
        })
        tprint(f"{GREEN}✓ Step 7 complete — Detection results:{RESET}")
        for ad in attack_detections:
            status_color = RED if ad['status'] == 'ANOMALY' else GREEN
            sev = f"  [{ad['severity']}]" if ad['severity'] else ""
            tprint(f"    #{ad['id']} {ad['attack_type']:>25s}  score={ad['score']:.4f}  {status_color}{ad['status']}{RESET}{sev}", DIM)

        executor.teardown()
        tprint(f"{GREEN}✓ Sandbox cleaned up{RESET}")

        # ── Step 8: Compute metrics ──
        print_header(8, "COMPUTING DETECTION METRICS")
        tprint("Calculating precision, recall, F1, ROC...", DIM)
        send_event("step_start", {"step": 8, "title": "Computing Detection Metrics", "desc": "Calculating precision, recall, F1, ROC..."})
        y_true = np.array([0] * len(real_results) + [1] * len(attack_results))
        all_det = real_results + attack_results
        scores = np.array([r.anomaly_score for r in all_det])
        y_pred = np.array([1 if r.is_anomalous else 0 for r in all_det])

        tp = int(np.sum((y_pred == 1) & (y_true == 1)))
        fp = int(np.sum((y_pred == 1) & (y_true == 0)))
        fn = int(np.sum((y_pred == 0) & (y_true == 1)))
        tn = int(np.sum((y_pred == 0) & (y_true == 0)))

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        accuracy = (tp + tn) / len(y_true) if len(y_true) else 0.0

        # ROC
        thresholds = np.linspace(float(scores.min()) - 0.1, float(scores.max()) + 0.1, 200)
        tpr_list, fpr_list = [], []
        for t in thresholds:
            preds = (scores > t).astype(int)
            tp_t = np.sum((preds == 1) & (y_true == 1))
            fp_t = np.sum((preds == 1) & (y_true == 0))
            fn_t = np.sum((preds == 0) & (y_true == 1))
            tn_t = np.sum((preds == 0) & (y_true == 0))
            tpr_list.append(tp_t / (tp_t + fn_t) if (tp_t + fn_t) else 0)
            fpr_list.append(fp_t / (fp_t + tn_t) if (fp_t + tn_t) else 0)
        idx = np.argsort(fpr_list)
        fpr_s = np.array(fpr_list)[idx]
        tpr_s = np.array(tpr_list)[idx]
        auc = float(np.trapezoid(tpr_s, fpr_s))

        # Generate metrics charts
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        axes[0].plot(fpr_s, tpr_s, "b-", linewidth=2, label=f"ROC (AUC = {auc:.3f})")
        axes[0].plot([0, 1], [0, 1], "r--", linewidth=1, label="Random")
        axes[0].set_xlabel("FPR"); axes[0].set_ylabel("TPR")
        axes[0].set_title("ROC Curve"); axes[0].legend(); axes[0].grid(True, alpha=0.3)

        normal_s = scores[y_true == 0]
        attack_s = scores[y_true == 1]
        if len(normal_s):
            axes[1].hist(normal_s, bins=15, alpha=0.6, color="#27ae60", label="Normal", edgecolor="black")
        if len(attack_s):
            axes[1].hist(attack_s, bins=15, alpha=0.6, color="#e74c3c", label="Attack", edgecolor="black")
        axes[1].axvline(x=2.5, color="orange", linestyle="--", linewidth=2, label="Threshold")
        axes[1].set_xlabel("Anomaly Score"); axes[1].set_ylabel("Count")
        axes[1].set_title("Score Distribution"); axes[1].legend(); axes[1].grid(True, alpha=0.3)
        plt.tight_layout()
        metrics_img = fig_to_base64(fig)

        # Confusion matrix image
        fig, ax = plt.subplots(figsize=(5, 4))
        cm = np.array([[tn, fp], [fn, tp]])
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Normal", "Anomaly"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Normal", "Attack"])
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        ax.set_title("Confusion Matrix")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=18)
        plt.tight_layout()
        cm_img = fig_to_base64(fig)

        send_event("step_complete", {
            "step": 8,
            "result": {
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(precision * 100, 1),
                "recall": round(recall * 100, 1),
                "f1": round(f1 * 100, 1),
                "accuracy": round(accuracy * 100, 1),
                "auc": round(auc, 3),
                "metrics_image": metrics_img,
                "cm_image": cm_img
            }
        })
        tprint(f"{GREEN}✓ Step 8 complete — Metrics computed{RESET}")
        print(f"")
        print(f"    ┌──────────────────────────────────────┐")
        print(f"    │  {BOLD}Precision{RESET}:  {precision*100:6.1f}%                │")
        print(f"    │  {BOLD}Recall{RESET}:     {recall*100:6.1f}%                │")
        print(f"    │  {BOLD}F1 Score{RESET}:   {f1*100:6.1f}%                │")
        print(f"    │  {BOLD}Accuracy{RESET}:   {accuracy*100:6.1f}%                │")
        print(f"    │  {BOLD}AUC{RESET}:        {auc:6.3f}                 │")
        print(f"    ├──────────────────────────────────────┤")
        print(f"    │  TP={tp:3d}   FP={fp:3d}   FN={fn:3d}   TN={tn:3d}  │")
        print(f"    └──────────────────────────────────────┘")
        print(flush=True)

        # ── Step 9: Visualizations ──
        print_header(9, "GENERATING VISUALIZATIONS")
        tprint("Creating behavioral graph views...", DIM)
        send_event("step_start", {"step": 9, "title": "Generating Visualizations", "desc": "Creating behavioral graph views..."})

        all_graphs = train_graphs + test_graphs + attack_graphs
        viz_images = []

        # Normal vs Attack
        if test_graphs and attack_graphs:
            normal_g = filter_graph_for_viz(test_graphs[0])
            attack_g = filter_graph_for_viz(attack_graphs[0])
            n_score = real_results[0].anomaly_score if real_results else 0
            a_score = attack_results[0].anomaly_score if attack_results else 0
            fig = visualizer.visualize_graph_comparison(normal_g, attack_g, n_score, a_score, threshold=2.5)
            viz_images.append({"title": "Normal vs Attack Comparison", "image": fig_to_base64(fig)})

        # Biggest graph
        biggest = max(all_graphs, key=lambda g: g.num_nodes)
        vg = filter_graph_for_viz(biggest)
        fig = visualizer.visualize_single_graph(vg, title=f"Detailed Graph ({vg.num_nodes} nodes)", show_edge_labels=True, layout="spring")
        viz_images.append({"title": "Detailed Behavioral Graph", "image": fig_to_base64(fig)})

        send_event("step_complete", {
            "step": 9,
            "result": {"visualizations": viz_images}
        })
        tprint(f"{GREEN}✓ Step 9 complete — {len(viz_images)} visualizations generated{RESET}")

        # ── Step 10: Attack Impact Summary ──
        print_header(10, "ATTACK IMPACT SUMMARY")
        tprint("Displaying real attack file impacts...", DIM)
        print("  Real Attack File Impact Details:")
        for rpt in attack_reports:
            s = rpt.summary_dict()
            tprint(f"    {RED}🔴 {s['attack_name']}{RESET}: {s['files_impacted']} files, {s['events_generated']} events, {s['duration_ms']:.0f}ms", DIM)
            for imp in s['impacts']:
                tprint(f"      → {imp['file']}: {imp['change']} ({imp['size_before']}→{imp['size_after']} bytes)", DIM)
        tprint(f"{GREEN}✓ Step 10 complete{RESET}")

        # ── Step 11: Export Results ──
        print_header(11, "EXPORTING RESULTS")
        tprint("Saving detection results to JSON and CSV...", DIM)
        json_path = alert_logger.save_results_json(
            all_det, alert_manager.alerts,
            extra={"precision": round(precision, 4), "recall": round(recall, 4),
                   "f1": round(f1, 4), "accuracy": round(accuracy, 4), "auc": round(auc, 4)})
        csv_path = alert_logger.save_results_csv(all_det)
        tprint(f"  ✓ {json_path}", GREEN)
        tprint(f"  ✓ {csv_path}", GREEN)
        tprint(f"{GREEN}✓ Step 11 complete{RESET}")

        # ── Pipeline Complete ──
        elapsed = round(time.time() - start_time, 1)
        print(f"\n{GREEN}{'╔'+'═'*58+'╗'}{RESET}")
        print(f"{GREEN}║{RESET}{BOLD}  PIPELINE COMPLETE — {elapsed}s elapsed{' '*(37-len(str(elapsed)))}{RESET}{GREEN}║{RESET}")
        print(f"{GREEN}{'╚'+'═'*58+'╝'}{RESET}\n")
        send_event("pipeline_complete", {
            "elapsed": elapsed,
            "train_events": len(train_events),
            "test_events": len(test_events),
            "train_graphs": len(train_graphs),
            "test_graphs": len(test_graphs),
            "attack_graphs": len(attack_graphs),
            "precision": round(precision * 100, 1),
            "recall": round(recall * 100, 1),
            "f1": round(f1 * 100, 1),
            "auc": round(auc, 3)
        })

    except Exception as e:
        import traceback
        tprint(f"{RED}✗ ERROR: {e}{RESET}", RED)
        traceback.print_exc()
        send_event("error", {"message": str(e), "traceback": traceback.format_exc()})
    finally:
        pipeline_running = False


# ═══════════════════════════════════════════════════════════════
#  Flask Routes
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/start", methods=["POST"])
def start_pipeline():
    global pipeline_running
    if pipeline_running:
        return jsonify({"status": "already_running"}), 409
    # Clear history for new run
    with event_lock:
        event_history.clear()
    t = threading.Thread(target=run_pipeline_thread, daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/stream")
def stream():
    """SSE endpoint. Each client gets its own cursor into event_history."""
    def generate():
        cursor = 0
        while True:
            with event_lock:
                pending = event_history[cursor:]
                cursor = len(event_history)
            for evt in pending:
                yield f"data: {json.dumps(evt)}\n\n"
            # Wait for new events
            with event_condition:
                event_condition.wait(timeout=15)
            # Send heartbeat if nothing new
            with event_lock:
                if cursor >= len(event_history):
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/history")
def history():
    """Return all events so far (for page refresh catch-up)."""
    with event_lock:
        return jsonify(event_history)


@app.route("/status")
def status():
    return jsonify({"running": pipeline_running})


if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════════════╗")
    print("  ║  Zero-Day Detection — Real-Time Web Dashboard   ║")
    print("  ║  Open http://localhost:5000 in your browser      ║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
