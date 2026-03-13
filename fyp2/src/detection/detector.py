"""
Anomaly Detector Module
=======================
Detects anomalous behavior using Graph Autoencoder reconstruction error.

Detection Rule (LOCKED):
    Flag as ANOMALOUS if: AnomalyScore > μ + 3σ

Where:
- AnomalyScore = ||G - Reconstructed(G)||₂
- μ = mean reconstruction error on training data
- σ = standard deviation of reconstruction error on training data
"""

import time
import uuid
from typing import List, Optional
import logging

from ..data.schemas import BehaviorGraph, DetectionResult, Alert
from ..models.autoencoder import GraphAutoencoder, graph_to_pyg_data

logger = logging.getLogger(__name__)

# Detection threshold multiplier (LOCKED)
THRESHOLD_SIGMA = 3.0


class AnomalyDetector:
    """
    Anomaly detector using Graph Autoencoder.
    
    Detects zero-day attacks by identifying behavior that deviates
    significantly from learned normal patterns.
    """
    
    def __init__(
        self,
        model: GraphAutoencoder,
        mean_loss: float = 0.0,
        std_loss: float = 1.0,
        threshold_sigma: float = THRESHOLD_SIGMA
    ):
        """
        Args:
            model: Trained GraphAutoencoder
            mean_loss: Mean reconstruction error from training (μ)
            std_loss: Std of reconstruction error from training (σ)
            threshold_sigma: Number of standard deviations for threshold
        """
        self.model = model
        self.mean_loss = mean_loss
        self.std_loss = std_loss
        self.threshold_sigma = threshold_sigma
        
        # Compute threshold: μ + 3σ
        self.threshold = self.mean_loss + self.threshold_sigma * self.std_loss
        
        # Statistics
        self.total_detections = 0
        self.total_anomalies = 0
        
        logger.info(f"Detector initialized. Threshold: {self.threshold:.6f} (μ={mean_loss:.6f}, σ={std_loss:.6f})")
    
    def set_statistics(self, mean_loss: float, std_loss: float):
        """Update detection statistics from training"""
        self.mean_loss = mean_loss
        self.std_loss = std_loss
        self.threshold = self.mean_loss + self.threshold_sigma * self.std_loss
        logger.info(f"Updated threshold: {self.threshold:.6f}")
    
    def detect(self, graph: BehaviorGraph) -> DetectionResult:
        """
        Detect if a behavior graph is anomalous.
        
        Args:
            graph: BehaviorGraph to analyze
            
        Returns:
            DetectionResult with anomaly score and flag
        """
        # Convert to PyG format
        data = graph_to_pyg_data(graph)
        
        # Compute anomaly score
        score = self.model.compute_anomaly_score(
            data.x, data.edge_index, data.num_nodes
        )
        
        # Check against threshold
        is_anomalous = score > self.threshold
        
        # Update statistics
        self.total_detections += 1
        if is_anomalous:
            self.total_anomalies += 1
            logger.warning(f"ANOMALY DETECTED in {graph.graph_id}: score={score:.4f} > threshold={self.threshold:.4f}")
        
        return DetectionResult(
            graph_id=graph.graph_id,
            anomaly_score=score,
            threshold=self.threshold,
            is_anomalous=is_anomalous
        )
    
    def detect_batch(self, graphs: List[BehaviorGraph]) -> List[DetectionResult]:
        """Detect anomalies in multiple graphs"""
        return [self.detect(g) for g in graphs]
    
    def get_statistics(self) -> dict:
        """Get detection statistics"""
        return {
            'total_detections': self.total_detections,
            'total_anomalies': self.total_anomalies,
            'anomaly_rate': self.total_anomalies / self.total_detections if self.total_detections > 0 else 0,
            'threshold': self.threshold,
            'mean_loss': self.mean_loss,
            'std_loss': self.std_loss
        }


class AlertManager:
    """
    Manages alerts generated from anomaly detection.
    """
    
    def __init__(self):
        self.alerts: List[Alert] = []
        self._alert_counter = 0
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        self._alert_counter += 1
        return f"ALERT-{int(time.time())}-{self._alert_counter:04d}"
    
    def create_alert(self, result: DetectionResult) -> Optional[Alert]:
        """
        Create alert from detection result if anomalous.
        
        Args:
            result: DetectionResult from detector
            
        Returns:
            Alert if anomalous, None otherwise
        """
        if not result.is_anomalous:
            return None
        
        alert = Alert.from_detection(result, self._generate_alert_id())
        self.alerts.append(alert)
        
        logger.warning(f"Alert created: {alert.alert_id} - Severity: {alert.severity}")
        
        return alert
    
    def get_alerts(self, severity: Optional[str] = None) -> List[Alert]:
        """Get alerts, optionally filtered by severity"""
        if severity:
            return [a for a in self.alerts if a.severity == severity]
        return self.alerts
    
    def get_recent_alerts(self, count: int = 10) -> List[Alert]:
        """Get most recent alerts"""
        return self.alerts[-count:]
    
    def generate_summary(self) -> str:
        """Generate alert summary"""
        if not self.alerts:
            return "No alerts generated."
        
        summary = []
        summary.append(f"Total Alerts: {len(self.alerts)}")
        summary.append("")
        
        # Count by severity
        severities = {}
        for alert in self.alerts:
            severities[alert.severity] = severities.get(alert.severity, 0) + 1
        
        summary.append("By Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severities:
                summary.append(f"  {sev}: {severities[sev]}")
        
        summary.append("")
        summary.append("Recent Alerts:")
        for alert in self.alerts[-5:]:
            summary.append(f"  [{alert.severity}] {alert.alert_id}: Score={alert.anomaly_score:.4f}")
        
        return "\n".join(summary)
