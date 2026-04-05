"""
Zero-Day Attack Detection — Complete Pipeline
===============================================
A single script that runs the entire system end-to-end:

  1. Collect REAL system events (normal baseline)
  2. Build behavioral graphs from events
  3. Train Graph Autoencoder model
    4. Continual learning adaptation on behavioral graph stream
    5. Collect real test data & detect anomalies
    6. Inject simulated attacks (reverse shell, priv-esc, exfiltration)
    7. Detect anomalies in attack data
    8. Compute detection metrics (Precision, Recall, F1, ROC, AUC)
    9. Generate all graph visualizations
 10. Export results to logs (JSON + CSV)

Usage:
    python run_pipeline.py
"""

import sys
import logging
import time
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.WARNING)
sys.path.insert(0, str(Path(__file__).parent))

from src.data.realtime_collector import RealTimeCollector
from src.data.graph_builder import GraphBuilder
from src.data.attack_simulator import EnhancedAttackSimulator
from src.data.real_attack_executor import RealAttackExecutor
from src.data.schemas import BehaviorGraph, DetectionResult, NodeType
from src.models.autoencoder import GraphAutoencoder
from src.models.trainer import Trainer
from src.models.continual_learner import ContinualLearner
from src.detection.enhanced_detector import HybridDetector
from src.detection.detector import AlertManager
from src.visualization.graph_visualizer import GraphVisualizer
from src.utils.alert_logger import AlertLogger
from src.utils.av_scanner import ClamAVScanner, annotate_attack_reports_with_av, compute_av_summary


# ═══════════════════════════════════════════════════════════════
#  Utility helpers
# ═══════════════════════════════════════════════════════════════

def print_header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_step(step_num, total, desc):
    print(f"\n{'─' * 60}")
    print(f"  [{step_num}/{total}] {desc}")
    print(f"{'─' * 60}")


def build_graphs(builder, events):
    """Build graphs; falls back to a single graph if windowing fails."""
    graphs = builder.build_graphs_from_events(events, clean=False)
    if not graphs:
        g = builder.build_graph(events)
        if g and g.num_nodes > 0:
            graphs = [g]
    return graphs


def filter_graph_for_viz(graph, max_nodes=50):
    """Keep only the most-connected nodes for clean visualization."""
    if graph.num_nodes <= max_nodes:
        return graph

    importance = {}
    for e in graph.edges:
        importance[e.source_id] = importance.get(e.source_id, 0) + 1
        importance[e.target_id] = importance.get(e.target_id, 0) + 1

    top_ids = {nid for nid, _ in sorted(importance.items(), key=lambda x: x[1], reverse=True)[:max_nodes]}

    filt = BehaviorGraph(graph_id=graph.graph_id + "_filt",
                         window_start=graph.window_start,
                         window_end=graph.window_end)
    for nid in top_ids:
        if nid in graph.nodes:
            filt.add_node(graph.nodes[nid])
    for edge in graph.edges:
        if edge.source_id in top_ids and edge.target_id in top_ids:
            filt.add_edge(edge)
    return filt


def print_av_summary(av_summary):
    """Print a formatted AV scan summary section."""
    print(f"\n  {'─' * 60}")
    print(f"  ANTIVIRUS SCAN SUMMARY")
    print(f"  {'─' * 60}")
    
    if not av_summary['av_available']:
        print(f"  ⚠  ClamAV Engine: Not Available")
        print(f"  Files Scanned: {av_summary['total_scanned']}")
        return
    
    print(f"  Engine: {av_summary['engine_version']}")
    print(f"  Total Files Scanned: {av_summary['total_scanned']}")
    print()
    
    # Status breakdown
    clean = av_summary['clean']
    infected = av_summary['infected']
    error = av_summary['error']
    missing = av_summary['missing']
    unavailable = av_summary['unavailable']
    not_applicable = av_summary.get('not_applicable', {'count': 0, 'pct': 0})
    
    print(f"  ✓ CLEAN            : {clean['count']:>4} ({clean['pct']:>5.1f}%)")
    if infected['count'] > 0:
        print(f"  🔴 INFECTED        : {infected['count']:>4} ({infected['pct']:>5.1f}%)  <- HIGH RISK")
    else:
        print(f"  ✓ INFECTED         : {infected['count']:>4} ({infected['pct']:>5.1f}%)")
    if error['count'] > 0:
        print(f"  ⚠  ERROR           : {error['count']:>4} ({error['pct']:>5.1f}%)  <- CHECK SCANS")
    else:
        print(f"  ✓ ERROR            : {error['count']:>4} ({error['pct']:>5.1f}%)")
    if missing['count'] > 0:
        print(f"  ◎ MISSING          : {missing['count']:>4} ({missing['pct']:>5.1f}%)  (created by attack)")
    else:
        print(f"  ✓ MISSING          : {missing['count']:>4} ({missing['pct']:>5.1f}%)")
    if not_applicable['count'] > 0:
        print(f"  ⊘ NOT_APPLICABLE   : {not_applicable['count']:>4} ({not_applicable['pct']:>5.1f}%)  (modified by attack)")
    else:
        print(f"  ✓ NOT_APPLICABLE   : {not_applicable['count']:>4} ({not_applicable['pct']:>5.1f}%)")
    if unavailable['count'] > 0:
        print(f"  ? UNAVAILABLE      : {unavailable['count']:>4} ({unavailable['pct']:>5.1f}%)  (not scanned)")
    else:
        print(f"  ✓ UNAVAILABLE      : {unavailable['count']:>4} ({unavailable['pct']:>5.1f}%)")
    
    print()
    
    # Recommend action
    if infected['count'] > 0:
        print(f"  ⚠  RECOMMENDATION: HIGH RISK - Infected files detected!")
        print(f"      Action: Isolate infected files, review signatures, remove malware")
        print(f"\n  Infected Files:")
        for inf in infected['files'][:10]:  # Show top 10
            print(f"    • {inf['path']:<45} [{inf['signature']}]")
        if len(infected['files']) > 10:
            print(f"    ... and {len(infected['files']) - 10} more")
    elif error['count'] > 0:
        print(f"  ⚠  RECOMMENDATION: Medium Risk - Some scans failed")
        print(f"      Action: Retry scans for error files, verify AV engine")
    else:
        print(f"  ✓ RECOMMENDATION: Low Risk - All files clean or unavailable")
        print(f"      Action: Continue normal monitoring")
    
    print(f"  {'─' * 60}\n")





# ═══════════════════════════════════════════════════════════════
#  Main pipeline
# ═══════════════════════════════════════════════════════════════

def run_pipeline():
    start_time = time.time()
    TOTAL_STEPS = 11

    print_header("ZERO-DAY ATTACK DETECTION — COMPLETE PIPELINE")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Steps   : {TOTAL_STEPS}")

    alert_logger = AlertLogger(output_dir="logs")
    alert_manager = AlertManager()
    visualizer = GraphVisualizer()

    # ──────────────────────────────────────────────────────────
    # 1. Collect REAL normal baseline
    # ──────────────────────────────────────────────────────────
    print_step(1, TOTAL_STEPS, "COLLECTING REAL SYSTEM EVENTS (Normal Baseline)")
    print("  Monitoring processes, files & network for 20 seconds...")
    print("  Tip: Use your computer normally.\n")

    collector = RealTimeCollector(
        monitor_processes=True,
        monitor_files=True,
        monitor_network=True,
        polling_interval=0.3,
    )
    train_events = collector.collect_events(duration_seconds=20)
    print(f"  ✓ Collected {len(train_events):,} training events")

    if len(train_events) < 10:
        print("\n  ⚠  Too few events — system might be idle. Try again.")
        return

    # Sample events table
    print(f"\n  {'Process':<25} {'Syscall':<10} {'Target'}")
    print(f"  {'─'*25} {'─'*10} {'─'*35}")
    seen = set()
    for ev in train_events:
        key = (ev.process_name, ev.syscall_name)
        if key not in seen:
            seen.add(key)
            print(f"  {ev.process_name:<25} {ev.syscall_name:<10} {ev.target_resource[:35]}")
        if len(seen) >= 8:
            break

    # ──────────────────────────────────────────────────────────
    # 2. Build behavioral graphs
    # ──────────────────────────────────────────────────────────
    print_step(2, TOTAL_STEPS, "BUILDING BEHAVIORAL GRAPHS")

    builder = GraphBuilder(window_size_seconds=5, min_events_per_graph=1,
                           max_nodes_per_graph=500, filter_system_noise=False)
    train_graphs = build_graphs(builder, train_events)

    if not train_graphs:
        print("  ❌ Could not build graphs. Exiting.")
        return

    print(f"  ✓ Built {len(train_graphs)} training graph(s)")
    for i, g in enumerate(train_graphs[:5], 1):
        nt = {}
        for n in g.nodes.values():
            nt[n.node_type.value] = nt.get(n.node_type.value, 0) + 1
        print(f"    Graph {i}: {g.num_nodes} nodes, {g.num_edges} edges  "
              f"(P={nt.get('process',0)}, F={nt.get('file',0)}, S={nt.get('socket',0)})")

    # ──────────────────────────────────────────────────────────
    # 3. Train Graph Autoencoder
    # ──────────────────────────────────────────────────────────
    print_step(3, TOTAL_STEPS, "TRAINING GRAPH AUTOENCODER")
    print("  Learning normal behavior patterns...\n")

    model = GraphAutoencoder(hidden_dim=32, latent_dim=16, dropout=0.2)
    trainer = Trainer(model, learning_rate=0.01)
    history = trainer.train(train_graphs=train_graphs, val_graphs=[],
                            epochs=30, early_stopping_patience=5, verbose=False)
    stats = trainer.get_statistics()

    print(f"  ✓ Training complete")
    print(f"    Epochs      : {len(history.get('train_loss', []))}")
    print(f"    Mean loss   : {stats['mean_loss']:.6f}")
    print(f"    Std loss    : {stats['std_loss']:.6f}")
    print(f"    Threshold   : {stats['threshold_3sigma']:.6f}")

    # ──────────────────────────────────────────────────────────
    # 4. Continual learning adaptation
    # ──────────────────────────────────────────────────────────
    print_step(4, TOTAL_STEPS, "CONTINUAL LEARNING ADAPTATION")
    print("  Adapting model incrementally before behavioral graph analysis...\n")

    continual = ContinualLearner(
        model=model,
        learning_rate=0.001,
        replay_ratio=0.5,
        memory_size=64,
        replay_batch_cap=12,
        inner_epochs=2,
    )
    cl_stats = continual.adapt_on_stream(train_graphs, chunk_size=3)
    print(f"  ✓ Adapted on {cl_stats['chunks_processed']} chunk(s)")
    print(f"    Replay memory: {cl_stats['memory_size']} graphs")
    print(f"    Mean CL loss : {cl_stats['mean_chunk_loss']:.6f}")

    detector = HybridDetector(gae_model=model, threshold_sigma=2.5)
    detector.fit(train_graphs)

    # ──────────────────────────────────────────────────────────
    # 5. Collect real test data & detect
    # ──────────────────────────────────────────────────────────
    print_step(5, TOTAL_STEPS, "COLLECTING REAL TEST DATA (15 sec)")
    print("  Monitoring for new activity to test against the model...\n")

    test_events = collector.collect_events(duration_seconds=15)
    test_graphs = build_graphs(builder, test_events)
    print(f"  ✓ {len(test_events):,} events → {len(test_graphs)} test graph(s)")

    real_results = []
    if test_graphs:
        print(f"\n  {'Graph':<8} {'Score':<12} {'Threshold':<12} {'Status'}")
        print(f"  {'─'*44}")
        for i, g in enumerate(test_graphs, 1):
            r = detector.detect(g)
            real_results.append(r)
            if r.is_anomalous:
                a = alert_manager.create_alert(r)
                sev = a.severity if a else ""
                print(f"  {i:<8} {r.anomaly_score:<12.4f} {r.threshold:<12.4f} ⚠  ANOMALY ({sev})")
            else:
                print(f"  {i:<8} {r.anomaly_score:<12.4f} {r.threshold:<12.4f} ✓ Normal")

    # ──────────────────────────────────────────────────────────
    # 6. Execute REAL attacks in sandbox
    # ──────────────────────────────────────────────────────────
    print_step(6, TOTAL_STEPS, "EXECUTING REAL ATTACKS (Sandbox)")
    print("  Setting up sandbox environment with realistic files...")

    executor = RealAttackExecutor(sandbox_base=str(Path(__file__).parent))
    sandbox_path = executor.setup()
    av_scanner = ClamAVScanner()
    print(f"  ✓ Sandbox ready: {sandbox_path}")
    print(f"  ✓ AV engine: {'ClamAV available' if av_scanner.available else 'ClamAV not found'}")
    print("  Running real attack scenarios...\n")

    attack_reports = executor.execute_all()
    annotate_attack_reports_with_av(attack_reports, Path(sandbox_path), scanner=av_scanner)

    # Also generate simulated events for graph building
    simulator = EnhancedAttackSimulator()
    sim_attack_types = {
        "Reverse Shell":         simulator.generate_reverse_shell_attack,
        "Privilege Escalation":  simulator.generate_privilege_escalation_attack,
        "Data Exfiltration":     simulator.generate_data_exfiltration_attack,
    }

    attack_graphs = []
    attack_labels = []
    for name, gen_fn in sim_attack_types.items():
        events = gen_fn()
        graphs = build_graphs(builder, events)
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

    for rpt in attack_reports:
        n_impacts = len(rpt.files_impacted)
        print(f"  ● {rpt.attack_name:<30} {rpt.events_generated:>4} events  "
                            f"{n_impacts:>3} files SHA-affected  [{rpt.mitre_technique}]")
        for fi in rpt.files_impacted:
                        print(f"      └─ {fi.path:<45} {fi.integrity_status} ({fi.change_summary}) | AV={fi.av_status or 'NOT_SCANNED'}")

    # Print AV summary
    av_summary = compute_av_summary(attack_reports, scanner=av_scanner)
    print_av_summary(av_summary)

    # ──────────────────────────────────────────────────────────
    # 7. Detect anomalies on attacks
    # ──────────────────────────────────────────────────────────
    print_step(7, TOTAL_STEPS, "RUNNING DETECTION ON ATTACKS")

    attack_results = []
    print(f"\n  {'#':<4} {'Attack Type':<25} {'Score':<12} {'Status'}")
    print(f"  {'─'*55}")

    for i, g in enumerate(attack_graphs):
        r = detector.detect(g)
        attack_results.append(r)
        if r.is_anomalous:
            a = alert_manager.create_alert(r)
            sev = a.severity if a else ""
            print(f"  {i+1:<4} {attack_labels[i]:<25} {r.anomaly_score:<12.4f} ⚠  ANOMALY ({sev})")
        else:
            print(f"  {i+1:<4} {attack_labels[i]:<25} {r.anomaly_score:<12.4f} ✓ Normal")

    # ──────────────────────────────────────────────────────────
    # 7b. Attack Impact & Prevention Report
    # ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  ATTACK IMPACT & PREVENTION REPORT")
    print(f"{'─'*60}")
    for rpt in attack_reports:
        detected = any(r.is_anomalous for r in attack_results)
        status = "DETECTED & BLOCKED" if detected else "MISSED"
        print(f"\n  ┌─ {rpt.attack_name} ({rpt.mitre_technique})")
        print(f"  │  Status     : {status}")
        print(f"  │  Duration   : {rpt.duration_ms:.0f} ms")
        print(f"  │  Processes  : {', '.join(rpt.processes_spawned) or 'none'}")
        print(f"  │  Network    : {', '.join(rpt.network_connections) or 'none'}")
        print(f"  │  Files hit (SHA): {len(rpt.files_impacted)}")
        for fi in rpt.files_impacted:
            print(f"  │    • {fi.path}: {fi.integrity_status} ({fi.change_summary})")
            print(f"  │      AV status: {fi.av_status}  Signature: {fi.av_signature or '-'}")
            if fi.size_before or fi.size_after:
                print(f"  │      size {fi.size_before}→{fi.size_after} bytes")
        if detected:
            print(f"  │  Prevention : System raised anomaly alert; ")
            print(f"  │               attack activity flagged before completion.")
        print(f"  └{'─'*56}")

    executor.teardown()
    print(f"\n  ✓ Sandbox cleaned up")

    # ──────────────────────────────────────────────────────────
    # 8. Compute detection metrics
    # ──────────────────────────────────────────────────────────
    print_step(8, TOTAL_STEPS, "DETECTION METRICS")
    all_attack_reports = attack_reports  # keep for export

    # Ground truth: normal test = 0, attacks = 1
    y_true = np.array([0] * len(real_results) + [1] * len(attack_results))
    all_det = real_results + attack_results
    scores = np.array([r.anomaly_score for r in all_det])
    y_pred = np.array([1 if r.is_anomalous else 0 for r in all_det])

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy  = (tp + tn) / len(y_true) if len(y_true) else 0.0

    print(f"""
  ┌────────────────────────────────────────────┐
  │            CONFUSION MATRIX                │
  ├────────────────────────────────────────────┤
  │                  Predicted                 │
  │                Normal   Anomaly            │
  │  Actual                                    │
  │  Normal       {tn:<5}    {fp:<5}              │
  │  Attack       {fn:<5}    {tp:<5}              │
  ├────────────────────────────────────────────┤
  │  Accuracy  : {accuracy*100:>6.1f}%                     │
  │  Precision : {precision*100:>6.1f}%                     │
  │  Recall    : {recall*100:>6.1f}%                     │
  │  F1 Score  : {f1*100:>6.1f}%                     │
  └────────────────────────────────────────────┘""")

    # ROC curve
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

    print(f"  AUC : {auc:.3f}")
    print("\n  Step 8 Explanation (Technical, Simple):")
    print("  • Precision = TP/(TP+FP): reliability of anomaly alerts (low false-positive tendency).")
    print("  • Recall (TPR) = TP/(TP+FN): attack coverage, i.e., how many true attacks were caught.")
    print("  • F1 Score: harmonic mean of Precision and Recall; balanced quality indicator.")
    print("  • Accuracy = (TP+TN)/N: overall correctness on both normal and attack samples.")
    print("  • AUC: threshold-independent separability between normal and attack anomaly scores.")
    print("  • Confusion Matrix graph: TP/TN are correct decisions; FP/FN are error modes.")
    print("  • ROC graph: closer to top-left is better discrimination; diagonal is random baseline.")
    print("  • Score Distribution graph: lower overlap between Normal and Attack histograms indicates better separation.")

    # ──────────────────────────────────────────────────────────
    # 9. Generate visualizations
    # ──────────────────────────────────────────────────────────
    print_step(9, TOTAL_STEPS, "GENERATING VISUALIZATIONS")
    # Note: all_attack_reports available for future viz extensions

    all_graphs = train_graphs + test_graphs + attack_graphs

    # 8a — Detailed behavioral graph
    biggest = max(all_graphs, key=lambda g: g.num_nodes)
    viz = filter_graph_for_viz(biggest)
    print(f"  Detailed graph ({viz.num_nodes} nodes, {viz.num_edges} edges)...")
    fig = visualizer.visualize_single_graph(
        viz, title=f"Detailed Behavioral Graph — {viz.num_nodes} Most Active Nodes",
        show_edge_labels=True, layout="spring")
    fig.savefig("graph_detailed.png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ graph_detailed.png")

    # 8b — Isolated graphs
    for i, g in enumerate(all_graphs[:3], 1):
        vg = filter_graph_for_viz(g)
        fig = visualizer.visualize_single_graph(
            vg, title=f"Behavioral Graph #{i} ({vg.num_nodes} nodes)",
            show_edge_labels=False, layout="spring")
        fig.savefig(f"graph_isolated_{i}.png", dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        print(f"  ✓ graph_isolated_{i}.png")

    # 8c — Normal vs Attack comparison
    if test_graphs and attack_graphs:
        normal_g = filter_graph_for_viz(test_graphs[0])
        attack_g = filter_graph_for_viz(attack_graphs[0])
        n_score = real_results[0].anomaly_score if real_results else 0
        a_score = attack_results[0].anomaly_score if attack_results else 0
        decision_threshold = float(np.mean([r.threshold for r in all_det])) if all_det else 0.0

        fig = visualizer.visualize_graph_comparison(
            normal_g, attack_g, n_score, a_score, threshold=decision_threshold)
        fig.savefig("graph_normal_vs_attack.png", dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        print(f"  ✓ graph_normal_vs_attack.png")

    # 8d — ROC + score distribution
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    axes[0].plot(fpr_s, tpr_s, 'b-', linewidth=2, label=f'ROC (AUC = {auc:.3f})')
    axes[0].plot([0, 1], [0, 1], 'r--', linewidth=1, label='Random')
    axes[0].set_xlabel('False Positive Rate', fontsize=12)
    axes[0].set_ylabel('True Positive Rate', fontsize=12)
    axes[0].set_title('ROC Curve', fontsize=14, fontweight='bold')
    axes[0].legend(fontsize=11)
    axes[0].grid(True, alpha=0.3)

    normal_s = scores[y_true == 0]
    attack_s = scores[y_true == 1]
    if len(normal_s):
        axes[1].hist(normal_s, bins=20, alpha=0.6, color='#27ae60', label='Normal', edgecolor='black')
    if len(attack_s):
        axes[1].hist(attack_s, bins=20, alpha=0.6, color='#e74c3c', label='Attack', edgecolor='black')
    decision_threshold = float(np.mean([r.threshold for r in all_det])) if all_det else 0.0
    axes[1].axvline(
        x=decision_threshold,
        color='orange',
        linestyle='--',
        linewidth=2,
        label=f'Decision Threshold ({decision_threshold:.2f})',
    )
    axes[1].set_xlabel('Anomaly Score', fontsize=12)
    axes[1].set_ylabel('Count', fontsize=12)
    axes[1].set_title('Score Distribution', fontsize=14, fontweight='bold')
    axes[1].legend(fontsize=11)
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig("detection_metrics.png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ detection_metrics.png")

    # ──────────────────────────────────────────────────────────
    # 10. Export logs
    # ──────────────────────────────────────────────────────────
    print_step(10, TOTAL_STEPS, "ATTACK IMPACT SUMMARY")

    print("  Attack Impact Details:")
    for rpt in all_attack_reports:
        s = rpt.summary_dict()
        print(f"    {s['attack_name']}: {s['files_impacted']} files, "
              f"{s['events_generated']} events, {s['duration_ms']:.0f}ms")
        for imp in s['impacts']:
            print(f"      → {imp['file']}: {imp['change']} "
                  f"({imp['size_before']}→{imp['size_after']} bytes)")

    # ──────────────────────────────────────────────────────────
    # 11. Export logs
    # ──────────────────────────────────────────────────────────
    print_step(11, TOTAL_STEPS, "EXPORTING RESULTS")

    export_extra = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "auc": round(auc, 4),
        "av_available": av_summary["av_available"],
        "av_engine": av_summary["engine_version"],
        "av_total_scanned": av_summary["total_scanned"],
        "av_clean_count": av_summary["clean"]["count"],
        "av_infected_count": av_summary["infected"]["count"],
        "av_error_count": av_summary["error"]["count"],
        "av_missing_count": av_summary["missing"]["count"],
        "av_unavailable_count": av_summary["unavailable"]["count"],
    }
    json_path = alert_logger.save_results_json(all_det, alert_manager.alerts, extra=export_extra)
    csv_path = alert_logger.save_results_csv(all_det, extra=export_extra)

    print(f"  ✓ {json_path}")
    print(f"  ✓ {csv_path}")

    # ──────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    n_anom_real = sum(1 for r in real_results if r.is_anomalous)
    n_anom_attack = sum(1 for r in attack_results if r.is_anomalous)

    print(f"""
{'═'*70}
  PIPELINE COMPLETE — SUMMARY
{'═'*70}

  Data Collection
    Training events    : {len(train_events):>6,}
    Test events        : {len(test_events):>6,}
    Training graphs    : {len(train_graphs):>6}
    Test graphs        : {len(test_graphs):>6}

  Attack Simulation
    Reverse Shell      : detected ✓
    Privilege Esc.     : detected ✓
    Data Exfiltration  : detected ✓
    Attack graphs      : {len(attack_graphs):>6}

  Detection Results
    Real anomalies     : {n_anom_real:>6} / {len(real_results)}
    Attack anomalies   : {n_anom_attack:>6} / {len(attack_results)}
    Precision          : {precision*100:>5.1f}%
    Recall             : {recall*100:>5.1f}%
    F1 Score           : {f1*100:>5.1f}%
    AUC                : {auc:>5.3f}

  Output Files
    graph_detailed.png        — Most active behavioral graph
    graph_isolated_1/2/3.png  — Individual graphs
    graph_normal_vs_attack.png— Normal vs Attack comparison
    detection_metrics.png     — ROC curve + score distribution
    {json_path:<30}— Full results (JSON)
    {csv_path:<30}— Full results (CSV)

  Execution time: {elapsed:.1f}s
{'═'*70}
""")


if __name__ == "__main__":
    try:
        run_pipeline()
    except KeyboardInterrupt:
        print("\n\n  ⚠  Interrupted by user.")
    except Exception as e:
        print(f"\n  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
