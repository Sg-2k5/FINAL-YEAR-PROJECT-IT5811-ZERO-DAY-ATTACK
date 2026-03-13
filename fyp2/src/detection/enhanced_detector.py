"""
Enhanced Anomaly Detection Module
=================================
Uses multiple features for anomaly detection, not just reconstruction error.

Features:
1. Graph structural features (node degree distribution, clustering)
2. Node feature statistics
3. Edge pattern analysis
4. Reconstruction error (original approach)

Combines these using an isolation forest or statistical Z-score approach.
"""

import torch
import numpy as np
from typing import List, Dict, Tuple
from collections import Counter
import logging

from ..data.schemas import BehaviorGraph, DetectionResult, Alert, NodeType, EdgeType
from ..models.autoencoder import graph_to_pyg_data

logger = logging.getLogger(__name__)


class StructuralFeatureExtractor:
    """
    Extracts structural features from behavior graphs for anomaly detection.
    
    These features capture graph-level patterns that differ between normal
    and attack behavior.
    """
    
    @staticmethod
    def extract_features(graph: BehaviorGraph) -> np.ndarray:
        """
        Extract structural features from a graph.
        
        Features (14 total):
        - [0-2]: Node type distribution (normalized counts)
        - [3]: Average in-degree
        - [4]: Average out-degree
        - [5]: Max in-degree
        - [6]: Max out-degree
        - [7]: Ratio of PROCESS nodes
        - [8]: Ratio of FILE nodes
        - [9]: Ratio of SOCKET nodes
        - [10]: Unique processes count (normalized)
        - [11]: Unique files count (normalized)
        - [12]: Unique sockets count (normalized)
        - [13]: Edge density
        """
        n_nodes = graph.num_nodes
        n_edges = graph.num_edges
        
        if n_nodes == 0:
            return np.zeros(14)
        
        # Count node types
        node_types = Counter(n.node_type for n in graph.nodes.values())
        n_process = node_types.get(NodeType.PROCESS, 0)
        n_file = node_types.get(NodeType.FILE, 0)
        n_socket = node_types.get(NodeType.SOCKET, 0)
        
        # Node type distribution (normalized)
        type_dist = np.array([n_process, n_file, n_socket]) / max(n_nodes, 1)
        
        # Compute degrees
        in_degrees = {nid: 0 for nid in graph.nodes}
        out_degrees = {nid: 0 for nid in graph.nodes}
        
        for edge in graph.edges:
            if edge.source_id in out_degrees:
                out_degrees[edge.source_id] += 1
            if edge.target_id in in_degrees:
                in_degrees[edge.target_id] += 1
        
        in_deg_values = list(in_degrees.values()) or [0]
        out_deg_values = list(out_degrees.values()) or [0]
        
        # Degree statistics
        avg_in_deg = np.mean(in_deg_values)
        avg_out_deg = np.mean(out_deg_values)
        max_in_deg = max(in_deg_values)
        max_out_deg = max(out_deg_values)
        
        # Normalize degrees by graph size
        avg_in_deg /= max(n_nodes, 1)
        avg_out_deg /= max(n_nodes, 1)
        max_in_deg /= max(n_nodes, 1)
        max_out_deg /= max(n_nodes, 1)
        
        # Count unique entities
        unique_processes = len([n for n in graph.nodes.values() if n.node_type == NodeType.PROCESS])
        unique_files = len([n for n in graph.nodes.values() if n.node_type == NodeType.FILE])
        unique_sockets = len([n for n in graph.nodes.values() if n.node_type == NodeType.SOCKET])
        
        # Normalize by total nodes
        unique_processes_norm = unique_processes / max(n_nodes, 1)
        unique_files_norm = unique_files / max(n_nodes, 1)
        unique_sockets_norm = unique_sockets / max(n_nodes, 1)
        
        # Edge density
        max_edges = n_nodes * (n_nodes - 1) if n_nodes > 1 else 1
        edge_density = n_edges / max_edges
        
        features = np.array([
            type_dist[0], type_dist[1], type_dist[2],       # Node type distribution
            avg_in_deg, avg_out_deg,                         # Average degrees
            max_in_deg, max_out_deg,                         # Max degrees
            type_dist[0], type_dist[1], type_dist[2],       # Ratios (same as dist)
            unique_processes_norm, unique_files_norm, unique_sockets_norm,  # Unique counts
            edge_density                                      # Density
        ])
        
        return features


class EnhancedAnomalyDetector:
    """
    Multi-feature anomaly detector.
    
    Combines structural features with learned patterns for better detection.
    Uses Z-score based anomaly detection across multiple features.
    """
    
    def __init__(self, threshold_sigma: float = 2.5):
        """
        Args:
            threshold_sigma: Number of standard deviations for anomaly threshold
        """
        self.threshold_sigma = threshold_sigma
        self.feature_extractor = StructuralFeatureExtractor()
        
        # Statistics learned from training
        self.feature_means: np.ndarray = None
        self.feature_stds: np.ndarray = None
        
        # Track detection stats
        self.total_detections = 0
        self.total_anomalies = 0
    
    def fit(self, graphs: List[BehaviorGraph]):
        """
        Learn normal behavior statistics from training graphs.
        
        Args:
            graphs: List of BENIGN behavior graphs
        """
        features_list = []
        
        for graph in graphs:
            features = self.feature_extractor.extract_features(graph)
            features_list.append(features)
        
        features_matrix = np.array(features_list)
        
        self.feature_means = np.mean(features_matrix, axis=0)
        self.feature_stds = np.std(features_matrix, axis=0)
        
        # Avoid division by zero
        self.feature_stds = np.where(self.feature_stds < 1e-6, 1e-6, self.feature_stds)
        
        logger.info(f"Fitted on {len(graphs)} graphs. Feature means: {self.feature_means}")
    
    def compute_anomaly_score(self, graph: BehaviorGraph) -> Tuple[float, Dict]:
        """
        Compute multi-dimensional anomaly score.
        
        Returns:
            score: Overall anomaly score (higher = more anomalous)
            details: Dictionary with per-feature z-scores
        """
        features = self.feature_extractor.extract_features(graph)
        
        # Compute Z-scores for each feature
        z_scores = np.abs((features - self.feature_means) / self.feature_stds)
        
        # Overall score is max Z-score (most anomalous feature)
        max_z = np.max(z_scores)
        mean_z = np.mean(z_scores)
        
        # Combined score (weighted average of max and mean)
        score = 0.7 * max_z + 0.3 * mean_z
        
        details = {
            'z_scores': z_scores.tolist(),
            'max_z': max_z,
            'mean_z': mean_z,
            'most_anomalous_feature_idx': int(np.argmax(z_scores)),
            'features': features.tolist()
        }
        
        return score, details
    
    def detect(self, graph: BehaviorGraph) -> DetectionResult:
        """
        Detect if a behavior graph is anomalous.
        
        Args:
            graph: BehaviorGraph to analyze
            
        Returns:
            DetectionResult with anomaly score and flag
        """
        score, details = self.compute_anomaly_score(graph)
        
        is_anomalous = score > self.threshold_sigma
        
        self.total_detections += 1
        if is_anomalous:
            self.total_anomalies += 1
            logger.warning(f"ANOMALY DETECTED: score={score:.4f}, max_z={details['max_z']:.4f}")
        
        return DetectionResult(
            graph_id=graph.graph_id,
            anomaly_score=score,
            threshold=self.threshold_sigma,
            is_anomalous=is_anomalous
        )
    
    def detect_batch(self, graphs: List[BehaviorGraph]) -> List[DetectionResult]:
        """Detect anomalies in multiple graphs"""
        return [self.detect(g) for g in graphs]
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_detections': self.total_detections,
            'total_anomalies': self.total_anomalies,
            'anomaly_rate': self.total_anomalies / self.total_detections if self.total_detections > 0 else 0,
            'threshold': self.threshold_sigma,
            'feature_means': self.feature_means.tolist() if self.feature_means is not None else None,
            'feature_stds': self.feature_stds.tolist() if self.feature_stds is not None else None
        }


class HybridDetector:
    """
    Combines Graph Autoencoder reconstruction error with structural feature analysis.
    
    This provides more robust detection by using multiple signals.
    """
    
    def __init__(
        self,
        gae_model,
        structural_weight: float = 0.6,
        reconstruction_weight: float = 0.4,
        threshold_sigma: float = 2.5
    ):
        """
        Args:
            gae_model: Trained Graph Autoencoder
            structural_weight: Weight for structural feature score
            reconstruction_weight: Weight for reconstruction error
            threshold_sigma: Z-score threshold for anomaly
        """
        self.gae_model = gae_model
        self.structural_weight = structural_weight
        self.reconstruction_weight = reconstruction_weight
        self.threshold_sigma = threshold_sigma
        
        self.structural_detector = EnhancedAnomalyDetector(threshold_sigma)
        
        # Reconstruction error statistics
        self.recon_mean: float = 0.0
        self.recon_std: float = 1.0
        
        # Track stats
        self.total_detections = 0
        self.total_anomalies = 0
    
    def fit(self, graphs: List[BehaviorGraph]):
        """Fit both detectors on training data"""
        # Fit structural detector
        self.structural_detector.fit(graphs)
        
        # Compute reconstruction error statistics
        recon_errors = []
        for graph in graphs:
            data = graph_to_pyg_data(graph)
            error = self.gae_model.compute_anomaly_score(
                data.x, data.edge_index, data.num_nodes
            )
            recon_errors.append(error)
        
        self.recon_mean = np.mean(recon_errors)
        self.recon_std = np.std(recon_errors)
        if self.recon_std < 1e-6:
            self.recon_std = 1e-6
        
        logger.info(f"Reconstruction error stats: μ={self.recon_mean:.4f}, σ={self.recon_std:.4f}")
    
    def detect(self, graph: BehaviorGraph) -> DetectionResult:
        """
        Detect anomaly using hybrid approach.
        """
        # 1. Structural feature score
        struct_score, _ = self.structural_detector.compute_anomaly_score(graph)
        
        # 2. Reconstruction error score
        data = graph_to_pyg_data(graph)
        recon_error = self.gae_model.compute_anomaly_score(
            data.x, data.edge_index, data.num_nodes
        )
        recon_z = abs(recon_error - self.recon_mean) / self.recon_std
        
        # 3. Combined score
        combined_score = (
            self.structural_weight * struct_score + 
            self.reconstruction_weight * recon_z
        )
        
        is_anomalous = combined_score > self.threshold_sigma
        
        self.total_detections += 1
        if is_anomalous:
            self.total_anomalies += 1
            logger.warning(f"ANOMALY: combined={combined_score:.4f}, structural={struct_score:.4f}, recon_z={recon_z:.4f}")
        
        return DetectionResult(
            graph_id=graph.graph_id,
            anomaly_score=combined_score,
            threshold=self.threshold_sigma,
            is_anomalous=is_anomalous
        )
    
    def detect_batch(self, graphs: List[BehaviorGraph]) -> List[DetectionResult]:
        return [self.detect(g) for g in graphs]
    
    def get_statistics(self) -> Dict:
        return {
            'total_detections': self.total_detections,
            'total_anomalies': self.total_anomalies,
            'anomaly_rate': self.total_anomalies / self.total_detections if self.total_detections > 0 else 0,
            'threshold': self.threshold_sigma,
            'recon_mean': self.recon_mean,
            'recon_std': self.recon_std
        }
