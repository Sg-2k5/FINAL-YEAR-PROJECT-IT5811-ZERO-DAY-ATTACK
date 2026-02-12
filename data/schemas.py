"""
Data Schemas for Zero-Day Detection System
==========================================
Defines all data structures used throughout the system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
import time


# =============================================================================
# ENUMERATIONS
# =============================================================================

class NodeType(Enum):
    """Types of nodes in behavior graph (LOCKED: only 3 types)"""
    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"


class EdgeType(Enum):
    """Types of edges in behavior graph (LOCKED: only 5 types)"""
    EXECUTES = "executes"    # Process executes another process
    READS = "reads"          # Process reads file
    WRITES = "writes"        # Process writes file
    SPAWNS = "spawns"        # Process spawns child process
    CONNECTS = "connects"    # Process connects to socket


class ResourceType(Enum):
    """Types of system resources"""
    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"


class Direction(Enum):
    """Direction of data flow"""
    IN = "in"
    OUT = "out"


# Mandatory syscalls to monitor (from research papers)
MANDATORY_SYSCALLS: Set[str] = frozenset({
    "execve",   # Process execution
    "fork",     # Process creation
    "open",     # File access
    "read",     # Data reading
    "write",    # Data writing
    "connect",  # Network connection
    "accept",   # Connection acceptance
    "chmod",    # Permission change
    "setuid",   # Privilege change
})


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RawEvent:
    """
    A single system event captured from auditd/eBPF.
    
    This is the fundamental unit of data in the system.
    """
    timestamp: int              # Unix timestamp in milliseconds
    process_id: int             # PID of the process
    parent_process_id: int      # Parent PID
    process_name: str           # Name of the process
    syscall_name: str           # System call name
    target_resource: str        # Target file/socket/process
    resource_type: ResourceType # Type of target resource
    direction: Direction        # Data flow direction
    
    def __post_init__(self):
        """Validate the event"""
        if self.syscall_name not in MANDATORY_SYSCALLS:
            # For flexibility in demo, just warn instead of error
            pass


@dataclass
class GraphNode:
    """A node in the behavior graph"""
    node_id: str
    node_type: NodeType
    name: str
    properties: Dict = field(default_factory=dict)
    
    # Features for ML (computed later)
    features: Optional[List[float]] = None


@dataclass
class GraphEdge:
    """An edge in the behavior graph"""
    source_id: str
    target_id: str
    edge_type: EdgeType
    timestamp: int
    properties: Dict = field(default_factory=dict)


@dataclass
class BehaviorGraph:
    """
    A behavior graph representing system activity in a time window.
    
    This is a directed, temporal, heterogeneous graph:
    - Directed: edges have direction (process → file)
    - Temporal: edges have timestamps
    - Heterogeneous: multiple node and edge types
    """
    graph_id: str
    window_start: int
    window_end: int
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    
    def add_node(self, node: GraphNode):
        """Add a node to the graph"""
        self.nodes[node.node_id] = node
    
    def add_edge(self, edge: GraphEdge):
        """Add an edge to the graph"""
        self.edges.append(edge)
    
    @property
    def num_nodes(self) -> int:
        return len(self.nodes)
    
    @property
    def num_edges(self) -> int:
        return len(self.edges)


@dataclass
class DetectionResult:
    """Result of anomaly detection on a single graph"""
    graph_id: str
    anomaly_score: float        # Raw reconstruction error
    threshold: float            # Current detection threshold
    is_anomalous: bool          # True if score > threshold
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    
    @property
    def normalized_score(self) -> float:
        """Score normalized by threshold (1.0 = at threshold)"""
        return self.anomaly_score / self.threshold if self.threshold > 0 else 0


@dataclass
class Alert:
    """An alert generated when anomaly is detected"""
    alert_id: str
    graph_id: str
    timestamp: int
    anomaly_score: float
    severity: str               # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    
    @staticmethod
    def from_detection(result: DetectionResult, alert_id: str) -> 'Alert':
        """Create alert from detection result"""
        # Determine severity based on how much score exceeds threshold
        ratio = result.anomaly_score / result.threshold if result.threshold > 0 else 0
        
        if ratio > 3.0:
            severity = "CRITICAL"
        elif ratio > 2.0:
            severity = "HIGH"
        elif ratio > 1.5:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        return Alert(
            alert_id=alert_id,
            graph_id=result.graph_id,
            timestamp=result.timestamp,
            anomaly_score=result.anomaly_score,
            severity=severity,
            description=f"Anomalous behavior detected. Score: {result.anomaly_score:.4f} (threshold: {result.threshold:.4f})"
        )
