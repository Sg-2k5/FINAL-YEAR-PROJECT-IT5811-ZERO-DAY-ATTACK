"""
Enhanced Behavioral Graph Visualization
========================================
Creates clear, informative visualizations of behavior graphs.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
from typing import List, Dict, Optional
import numpy as np

from ..data.schemas import BehaviorGraph, NodeType, EdgeType


class GraphVisualizer:
    """Enhanced visualizer for behavioral graphs"""
    
    # Color scheme
    NODE_COLORS = {
        NodeType.PROCESS: '#3498db',  # Blue
        NodeType.FILE: '#27ae60',     # Green
        NodeType.SOCKET: '#e74c3c'    # Red
    }
    
    EDGE_COLORS = {
        EdgeType.EXECUTES: '#9b59b6',   # Purple
        EdgeType.READS: '#2ecc71',      # Light green
        EdgeType.WRITES: '#e67e22',     # Orange
        EdgeType.SPAWNS: '#3498db',     # Blue
        EdgeType.CONNECTS: '#e74c3c'    # Red
    }
    
    def visualize_single_graph(
        self, 
        graph: BehaviorGraph, 
        title: str = "Behavioral Graph",
        show_edge_labels: bool = True,
        layout: str = 'hierarchical'
    ):
        """
        Create a detailed visualization of a single behavioral graph.
        
        Args:
            graph: BehaviorGraph to visualize
            title: Title for the plot
            show_edge_labels: Whether to show edge type labels
            layout: Layout algorithm ('hierarchical', 'spring', 'circular')
        """
        fig, ax = plt.subplots(figsize=(14, 10))
        
        G = nx.DiGraph()
        
        # Build NetworkX graph
        node_colors = []
        node_labels = {}
        node_sizes = []
        
        for node_id, node in graph.nodes.items():
            G.add_node(node_id, node_type=node.node_type)
            node_colors.append(self.NODE_COLORS.get(node.node_type, '#95a5a6'))
            
            # Create readable labels
            label = self._format_node_label(node.name, node.node_type)
            node_labels[node_id] = label
            
            # Size based on node type (processes larger)
            size = 1200 if node.node_type == NodeType.PROCESS else 800
            node_sizes.append(size)
        
        # Add edges with types
        edge_labels = {}
        edge_colors_list = []
        
        for edge in graph.edges:
            G.add_edge(edge.source_id, edge.target_id, edge_type=edge.edge_type)
            if show_edge_labels:
                edge_labels[(edge.source_id, edge.target_id)] = edge.edge_type.value
            edge_colors_list.append(self.EDGE_COLORS.get(edge.edge_type, '#7f8c8d'))
        
        # Choose layout
        if layout == 'hierarchical':
            pos = self._hierarchical_layout(G, graph)
        elif layout == 'circular':
            pos = nx.circular_layout(G)
        else:  # spring
            pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
        
        # Draw nodes
        nx.draw_networkx_nodes(
            G, pos, 
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.9,
            edgecolors='black',
            linewidths=2,
            ax=ax
        )
        
        # Draw edges with arrows
        nx.draw_networkx_edges(
            G, pos,
            edge_color=edge_colors_list,
            arrows=True,
            arrowsize=20,
            arrowstyle='->',
            width=2,
            alpha=0.7,
            connectionstyle='arc3,rad=0.1',
            ax=ax
        )
        
        # Draw labels
        nx.draw_networkx_labels(
            G, pos, 
            node_labels,
            font_size=9,
            font_weight='bold',
            font_family='sans-serif',
            ax=ax
        )
        
        # Draw edge labels
        if show_edge_labels and edge_labels:
            nx.draw_networkx_edge_labels(
                G, pos,
                edge_labels,
                font_size=8,
                font_color='#2c3e50',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7),
                ax=ax
            )
        
        # Create legends
        # Node type legend
        node_legend_elements = [
            mpatches.Patch(color=self.NODE_COLORS[NodeType.PROCESS], label='Process'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.FILE], label='File'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.SOCKET], label='Socket/Network')
        ]
        
        # Edge type legend
        edge_legend_elements = [
            mpatches.Patch(color=self.EDGE_COLORS[EdgeType.EXECUTES], label='executes'),
            mpatches.Patch(color=self.EDGE_COLORS[EdgeType.READS], label='reads'),
            mpatches.Patch(color=self.EDGE_COLORS[EdgeType.WRITES], label='writes'),
            mpatches.Patch(color=self.EDGE_COLORS[EdgeType.SPAWNS], label='spawns'),
            mpatches.Patch(color=self.EDGE_COLORS[EdgeType.CONNECTS], label='connects')
        ]
        
        # Add legends
        node_legend = ax.legend(
            handles=node_legend_elements,
            loc='upper left',
            title='Node Types',
            frameon=True,
            fancybox=True,
            shadow=True
        )
        ax.add_artist(node_legend)
        
        ax.legend(
            handles=edge_legend_elements,
            loc='upper right',
            title='Edge Types (Actions)',
            frameon=True,
            fancybox=True,
            shadow=True
        )
        
        # Title with graph stats
        stats_text = (
            f"{title}\n"
            f"ID: {graph.graph_id} | "
            f"Nodes: {graph.num_nodes} | "
            f"Edges: {graph.num_edges} | "
            f"Window: {graph.window_start:.1f}s - {graph.window_end:.1f}s"
        )
        ax.set_title(stats_text, fontsize=14, fontweight='bold', pad=20)
        
        ax.axis('off')
        plt.tight_layout()
        
        return fig
    
    def visualize_graph_comparison(
        self,
        normal_graph: BehaviorGraph,
        anomaly_graph: BehaviorGraph,
        normal_score: float,
        anomaly_score: float,
        threshold: float
    ):
        """
        Compare normal vs anomalous behavior graphs side by side.
        """
        fig, axes = plt.subplots(1, 2, figsize=(20, 9))
        
        # Visualize both graphs
        for idx, (graph, score, label, ax) in enumerate([
            (normal_graph, normal_score, "Normal Behavior", axes[0]),
            (anomaly_graph, anomaly_score, "Anomalous Behavior", axes[1])
        ]):
            G = nx.DiGraph()
            node_colors = []
            node_labels = {}
            
            for node_id, node in graph.nodes.items():
                G.add_node(node_id)
                node_colors.append(self.NODE_COLORS.get(node.node_type, '#95a5a6'))
                node_labels[node_id] = self._format_node_label(node.name, node.node_type)
            
            for edge in graph.edges:
                G.add_edge(edge.source_id, edge.target_id)
            
            pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
            
            # Draw
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=800, 
                                   alpha=0.9, edgecolors='black', linewidths=2, ax=ax)
            nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, 
                                   arrowsize=15, width=2, alpha=0.6, ax=ax)
            nx.draw_networkx_labels(G, pos, node_labels, font_size=8, 
                                    font_weight='bold', ax=ax)
            
            # Title with score
            is_anomaly = score > threshold
            color = '#e74c3c' if is_anomaly else '#27ae60'
            status = "⚠️ ANOMALY DETECTED" if is_anomaly else "✓ NORMAL"
            
            title_text = (
                f"{label}\n"
                f"{status}\n"
                f"Score: {score:.3f} (Threshold: {threshold:.3f})\n"
                f"Nodes: {graph.num_nodes} | Edges: {graph.num_edges}"
            )
            ax.set_title(title_text, fontsize=12, fontweight='bold', 
                        color=color, pad=15)
            ax.axis('off')
        
        # Add shared legend
        legend_elements = [
            mpatches.Patch(color=self.NODE_COLORS[NodeType.PROCESS], label='Process'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.FILE], label='File'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.SOCKET], label='Socket')
        ]
        fig.legend(handles=legend_elements, loc='lower center', ncol=3, 
                   frameon=True, fancybox=True, shadow=True, fontsize=11)
        
        plt.tight_layout(rect=[0, 0.05, 1, 1])
        
        return fig
    
    def visualize_graph_sequence(
        self,
        graphs: List[BehaviorGraph],
        scores: List[float],
        threshold: float,
        max_graphs: int = 6
    ):
        """
        Visualize a sequence of graphs showing temporal behavior progression.
        """
        n_graphs = min(len(graphs), max_graphs)
        cols = 3
        rows = (n_graphs + cols - 1) // cols
        
        fig, axes = plt.subplots(rows, cols, figsize=(18, 6 * rows))
        if rows == 1:
            axes = axes.reshape(1, -1)
        axes = axes.flatten()
        
        for idx in range(n_graphs):
            ax = axes[idx]
            graph = graphs[idx]
            score = scores[idx]
            
            G = nx.DiGraph()
            node_colors = []
            node_labels = {}
            
            for node_id, node in graph.nodes.items():
                G.add_node(node_id)
                node_colors.append(self.NODE_COLORS.get(node.node_type, '#95a5a6'))
                node_labels[node_id] = self._format_node_label(node.name, node.node_type)
            
            for edge in graph.edges:
                G.add_edge(edge.source_id, edge.target_id)
            
            pos = nx.spring_layout(G, k=1.5, iterations=30, seed=42)
            
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=400,
                                   alpha=0.9, edgecolors='black', linewidths=1.5, ax=ax)
            nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True,
                                   arrowsize=10, width=1.5, alpha=0.5, ax=ax)
            nx.draw_networkx_labels(G, pos, node_labels, font_size=7, ax=ax)
            
            # Status
            is_anomaly = score > threshold
            color = '#e74c3c' if is_anomaly else '#27ae60'
            status = "⚠️ ANOMALY" if is_anomaly else "✓ Normal"
            
            ax.set_title(f"Graph {idx+1}: {status}\nScore: {score:.3f}",
                        fontsize=10, fontweight='bold', color=color)
            ax.axis('off')
        
        # Hide unused subplots
        for idx in range(n_graphs, len(axes)):
            axes[idx].axis('off')
        
        # Add legend
        legend_elements = [
            mpatches.Patch(color=self.NODE_COLORS[NodeType.PROCESS], label='Process'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.FILE], label='File'),
            mpatches.Patch(color=self.NODE_COLORS[NodeType.SOCKET], label='Socket')
        ]
        fig.legend(handles=legend_elements, loc='lower center', ncol=3,
                   frameon=True, fancybox=True, fontsize=10)
        
        plt.suptitle('Behavioral Graph Sequence Over Time', 
                     fontsize=16, fontweight='bold', y=0.98)
        plt.tight_layout(rect=[0, 0.03, 1, 0.97])
        
        return fig
    
    def _format_node_label(self, name: str, node_type: NodeType) -> str:
        """Format node label to be readable"""
        if node_type == NodeType.PROCESS:
            # Just show process name
            return name.split('/')[-1] if '/' in name else name
        elif node_type == NodeType.FILE:
            # Show filename
            parts = name.split('/')
            if len(parts) > 2:
                return f".../{parts[-1]}"
            return name
        else:  # SOCKET
            # Show IP:port
            if ':' in name:
                return name.split(':')[-2] + ':' + name.split(':')[-1]
            return name
    
    def _hierarchical_layout(self, G: nx.DiGraph, graph: BehaviorGraph) -> Dict:
        """
        Create hierarchical layout with processes at top, resources below.
        """
        pos = {}
        
        # Separate nodes by type
        processes = [nid for nid, node in graph.nodes.items() 
                    if node.node_type == NodeType.PROCESS]
        files = [nid for nid, node in graph.nodes.items() 
                if node.node_type == NodeType.FILE]
        sockets = [nid for nid, node in graph.nodes.items() 
                  if node.node_type == NodeType.SOCKET]
        
        # Position processes at top
        for i, nid in enumerate(processes):
            x = i - len(processes) / 2
            pos[nid] = (x, 2)
        
        # Position files in middle
        for i, nid in enumerate(files):
            x = i - len(files) / 2
            pos[nid] = (x, 0)
        
        # Position sockets at bottom
        for i, nid in enumerate(sockets):
            x = i - len(sockets) / 2
            pos[nid] = (x, -2)
        
        return pos
