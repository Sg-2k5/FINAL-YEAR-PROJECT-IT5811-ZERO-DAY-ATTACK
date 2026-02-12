"""
Visualization Module for Phase 1
================================
Provides visualization of detection results and graphs.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from typing import List, Optional, Dict
import networkx as nx

from ..data.schemas import BehaviorGraph, DetectionResult, NodeType


def visualize_behavior_graph(graph: BehaviorGraph, title: str = "Behavior Graph"):
    """
    Visualize a single behavior graph.
    
    Different colors for different node types:
    - PROCESS: Blue
    - FILE: Green  
    - SOCKET: Red
    """
    G = nx.DiGraph()
    
    # Color map for node types
    color_map = {
        NodeType.PROCESS: '#3498db',  # Blue
        NodeType.FILE: '#27ae60',     # Green
        NodeType.SOCKET: '#e74c3c'    # Red
    }
    
    # Add nodes
    node_colors = []
    node_labels = {}
    for node_id, node in graph.nodes.items():
        G.add_node(node_id)
        node_colors.append(color_map.get(node.node_type, '#95a5a6'))
        # Short label
        label = node.name.split('/')[-1] if '/' in node.name else node.name
        if len(label) > 12:
            label = label[:10] + '..'
        node_labels[node_id] = label
    
    # Add edges
    for edge in graph.edges:
        G.add_edge(edge.source_id, edge.target_id)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Layout
    pos = nx.spring_layout(G, k=2, iterations=50)
    
    # Draw
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.8, ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, alpha=0.5, ax=ax)
    nx.draw_networkx_labels(G, pos, node_labels, font_size=8, ax=ax)
    
    # Legend
    legend_elements = [
        mpatches.Patch(color='#3498db', label='Process'),
        mpatches.Patch(color='#27ae60', label='File'),
        mpatches.Patch(color='#e74c3c', label='Socket')
    ]
    ax.legend(handles=legend_elements, loc='upper left')
    
    ax.set_title(f"{title}\nNodes: {graph.num_nodes}, Edges: {graph.num_edges}")
    plt.tight_layout()
    
    return fig


def visualize_detection_results(results: List[DetectionResult], threshold: float):
    """
    Visualize detection results showing anomaly scores vs threshold.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    scores = [r.anomaly_score for r in results]
    labels = ['Anomaly' if r.is_anomalous else 'Normal' for r in results]
    colors = ['#e74c3c' if r.is_anomalous else '#27ae60' for r in results]
    
    # Bar chart
    ax1 = axes[0]
    x = range(len(results))
    bars = ax1.bar(x, scores, color=colors, alpha=0.7)
    ax1.axhline(y=threshold, color='red', linestyle='--', linewidth=2, label=f'Threshold (μ+3σ): {threshold:.2f}')
    ax1.set_xlabel('Graph Index')
    ax1.set_ylabel('Anomaly Score')
    ax1.set_title('Anomaly Scores per Graph')
    ax1.legend()
    
    # Add labels
    for bar, label in zip(bars, labels):
        height = bar.get_height()
        ax1.annotate(label,
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, rotation=45)
    
    # Score distribution
    ax2 = axes[1]
    ax2.hist(scores, bins=20, color='#3498db', alpha=0.7, edgecolor='black')
    ax2.axvline(x=threshold, color='red', linestyle='--', linewidth=2, label=f'Threshold: {threshold:.2f}')
    ax2.set_xlabel('Anomaly Score')
    ax2.set_ylabel('Frequency')
    ax2.set_title('Score Distribution')
    ax2.legend()
    
    plt.tight_layout()
    return fig


def visualize_training_history(history: Dict[str, List[float]]):
    """
    Visualize training loss over epochs.
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    
    epochs = range(1, len(history['train_loss']) + 1)
    
    ax.plot(epochs, history['train_loss'], 'b-', linewidth=2, label='Training Loss', marker='o', markersize=4)
    
    if 'val_loss' in history and history['val_loss']:
        ax.plot(epochs, history['val_loss'], 'r--', linewidth=2, label='Validation Loss', marker='s', markersize=4)
    
    ax.set_xlabel('Epoch')
    ax.set_ylabel('Loss (Reconstruction Error)')
    ax.set_title('Training Progress')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return fig


def create_detection_dashboard(
    results: List[DetectionResult],
    threshold: float,
    history: Optional[Dict[str, List[float]]] = None
):
    """
    Create a comprehensive dashboard showing all detection metrics.
    """
    # Determine number of subplots
    n_plots = 3 if history else 2
    fig, axes = plt.subplots(1, n_plots, figsize=(6 * n_plots, 5))
    
    if n_plots == 2:
        axes = [axes[0], axes[1], None]
    
    # 1. Score bar chart
    ax1 = axes[0]
    scores = [r.anomaly_score for r in results]
    colors = ['#e74c3c' if r.is_anomalous else '#27ae60' for r in results]
    
    x = range(len(results))
    ax1.bar(x, scores, color=colors, alpha=0.7)
    ax1.axhline(y=threshold, color='red', linestyle='--', linewidth=2)
    ax1.set_xlabel('Graph Index')
    ax1.set_ylabel('Anomaly Score')
    ax1.set_title('Detection Results')
    
    # 2. Summary metrics
    ax2 = axes[1]
    ax2.axis('off')
    
    n_total = len(results)
    n_anomalies = sum(1 for r in results if r.is_anomalous)
    n_normal = n_total - n_anomalies
    
    summary_text = f"""
    DETECTION SUMMARY
    {'='*30}
    
    Total Graphs Analyzed: {n_total}
    Normal: {n_normal} ({100*n_normal/n_total:.1f}%)
    Anomalous: {n_anomalies} ({100*n_anomalies/n_total:.1f}%)
    
    Threshold: {threshold:.4f}
    Min Score: {min(scores):.4f}
    Max Score: {max(scores):.4f}
    Mean Score: {np.mean(scores):.4f}
    """
    
    ax2.text(0.1, 0.5, summary_text, transform=ax2.transAxes, 
             fontsize=12, verticalalignment='center',
             fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
    ax2.set_title('Summary')
    
    # 3. Training history (if provided)
    if history and axes[2] is not None:
        ax3 = axes[2]
        epochs = range(1, len(history['train_loss']) + 1)
        ax3.plot(epochs, history['train_loss'], 'b-', label='Train')
        if history.get('val_loss'):
            ax3.plot(epochs, history['val_loss'], 'r--', label='Val')
        ax3.set_xlabel('Epoch')
        ax3.set_ylabel('Loss')
        ax3.set_title('Training History')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return fig
