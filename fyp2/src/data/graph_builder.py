"""
Graph Builder Module
====================
Constructs behavior graphs from system events.

Creates heterogeneous temporal graphs with:
- 3 Node types: PROCESS, FILE, SOCKET
- 5 Edge types: EXECUTES, READS, WRITES, SPAWNS, CONNECTS
"""

from typing import List, Dict, Tuple
import time
import hashlib

from .schemas import (
    RawEvent, BehaviorGraph, GraphNode, GraphEdge,
    NodeType, EdgeType, ResourceType
)


class GraphBuilder:
    """
    Builds behavior graphs from raw system events.
    
    Each graph represents activity within a time window.
    """
    
    # Mapping from syscall to edge type
    SYSCALL_TO_EDGE = {
        "execve": EdgeType.EXECUTES,
        "fork": EdgeType.SPAWNS,
        "open": EdgeType.READS,  # Default, may change based on flags
        "read": EdgeType.READS,
        "write": EdgeType.WRITES,
        "connect": EdgeType.CONNECTS,
        "accept": EdgeType.CONNECTS,
        "chmod": EdgeType.WRITES,
        "setuid": EdgeType.EXECUTES,
    }
    
    # Mapping from resource type to node type
    RESOURCE_TO_NODE = {
        ResourceType.PROCESS: NodeType.PROCESS,
        ResourceType.FILE: NodeType.FILE,
        ResourceType.SOCKET: NodeType.SOCKET,
    }
    
    def __init__(
        self, 
        window_size_seconds: int = 30,
        min_events_per_graph: int = 3,
        max_nodes_per_graph: int = 50,
        filter_system_noise: bool = True
    ):
        """
        Args:
            window_size_seconds: Time window size
            min_events_per_graph: Minimum events to create a graph
            max_nodes_per_graph: Maximum nodes (prevents overcrowding)
            filter_system_noise: Remove noisy system processes
        
        Original Args:
            window_size_seconds: Size of time window for each graph (default: 30s)
        """
        self.window_size_seconds = window_size_seconds
        self.window_size_ms = window_size_seconds * 1000
        self.min_events_per_graph = min_events_per_graph
        self.max_nodes_per_graph = max_nodes_per_graph
        self.filter_system_noise = filter_system_noise
        
        # Noisy system processes to filter (Windows)
        self.noise_processes = {
            'System', 'Registry', 'Idle',
            'dwm.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
            'services.exe', 'audiodg.exe'
        }
    
    def _generate_node_id(self, node_type: NodeType, name: str) -> str:
        """Generate unique node ID"""
        return f"{node_type.value}_{hashlib.md5(name.encode()).hexdigest()[:8]}"
    
    def _generate_graph_id(self, window_start: int) -> str:
        """Generate unique graph ID"""
        return f"graph_{window_start}"
    
    def build_graph(self, events: List[RawEvent]) -> BehaviorGraph:
        """
        Build a behavior graph from a list of events.
        
        Args:
            events: List of RawEvent objects (should be within same time window)
            
        Returns:
            BehaviorGraph representing the events
        """
        if not events:
            # Return empty graph
            now = int(time.time() * 1000)
            return BehaviorGraph(
                graph_id=self._generate_graph_id(now),
                window_start=now,
                window_end=now + self.window_size_ms
            )
        
        # Determine time window
        timestamps = [e.timestamp for e in events]
        window_start = min(timestamps)
        window_end = max(timestamps)
        
        graph = BehaviorGraph(
            graph_id=self._generate_graph_id(window_start),
            window_start=window_start,
            window_end=window_end
        )
        
        # Process each event
        for event in events:
            self._add_event_to_graph(graph, event)
        
        # Compute node features
        self._compute_node_features(graph)
        
        return graph
    
    def _add_event_to_graph(self, graph: BehaviorGraph, event: RawEvent):
        """Add a single event to the graph"""
        
        # 1. Add source node (the process that made the syscall)
        source_id = self._generate_node_id(NodeType.PROCESS, f"{event.process_name}_{event.process_id}")
        if source_id not in graph.nodes:
            graph.add_node(GraphNode(
                node_id=source_id,
                node_type=NodeType.PROCESS,
                name=event.process_name,
                properties={
                    "pid": event.process_id,
                    "ppid": event.parent_process_id
                }
            ))
        
        # 2. Add target node (the resource being accessed)
        target_node_type = self.RESOURCE_TO_NODE.get(event.resource_type, NodeType.FILE)
        target_id = self._generate_node_id(target_node_type, event.target_resource)
        
        if target_id not in graph.nodes:
            graph.add_node(GraphNode(
                node_id=target_id,
                node_type=target_node_type,
                name=event.target_resource,
                properties={}
            ))
        
        # 3. Add edge between source and target
        edge_type = self.SYSCALL_TO_EDGE.get(event.syscall_name, EdgeType.READS)
        
        graph.add_edge(GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            timestamp=event.timestamp,
            properties={
                "syscall": event.syscall_name,
                "direction": event.direction.value
            }
        ))
    
    def _compute_node_features(self, graph: BehaviorGraph):
        """
        Compute feature vectors for each node.
        
        Features (6 dimensions):
        - [0-2]: One-hot encoding of node type (PROCESS, FILE, SOCKET)
        - [3]: In-degree (normalized)
        - [4]: Out-degree (normalized)
        - [5]: Temporal activity (edges per second)
        """
        # Count degrees
        in_degrees = {nid: 0 for nid in graph.nodes}
        out_degrees = {nid: 0 for nid in graph.nodes}
        
        for edge in graph.edges:
            if edge.source_id in out_degrees:
                out_degrees[edge.source_id] += 1
            if edge.target_id in in_degrees:
                in_degrees[edge.target_id] += 1
        
        # Normalize
        max_in = max(in_degrees.values()) if in_degrees else 1
        max_out = max(out_degrees.values()) if out_degrees else 1
        
        # Time window duration
        duration_seconds = (graph.window_end - graph.window_start) / 1000.0
        if duration_seconds == 0:
            duration_seconds = 1.0
        
        # Compute features for each node
        for node_id, node in graph.nodes.items():
            # One-hot encoding
            type_encoding = [0.0, 0.0, 0.0]
            if node.node_type == NodeType.PROCESS:
                type_encoding[0] = 1.0
            elif node.node_type == NodeType.FILE:
                type_encoding[1] = 1.0
            else:  # SOCKET
                type_encoding[2] = 1.0
            
            # Degree features
            in_deg = in_degrees.get(node_id, 0) / max_in
            out_deg = out_degrees.get(node_id, 0) / max_out
            
            # Temporal activity
            total_edges = in_degrees.get(node_id, 0) + out_degrees.get(node_id, 0)
            temporal_activity = total_edges / duration_seconds
            # Normalize to [0, 1] assuming max 10 edges/second
            temporal_activity = min(temporal_activity / 10.0, 1.0)
            
            node.features = type_encoding + [in_deg, out_deg, temporal_activity]
    
    def _filter_events(self, events: List[RawEvent]) -> List[RawEvent]:
        """Filter out noisy system events for cleaner graphs"""
        if not self.filter_system_noise:
            return events
        
        filtered = []
        for event in events:
            # Skip noisy processes
            if event.process_name in self.noise_processes:
                continue
            
            # Skip generic file paths (only most noisy ones)
            if event.resource_type == ResourceType.FILE:
                lower_path = event.target_resource.lower()
                # Skip only very common DLL/temp files
                if any(skip in lower_path for skip in [
                    'apppatch', 'prefetch', 'thumbcache', 'iconcache'
                ]):
                    continue
            
            filtered.append(event)
        
        return filtered
    
    def build_graphs_from_events(self, events: List[RawEvent], clean: bool = False) -> List[BehaviorGraph]:
        """
        Build multiple graphs from events, splitting by time windows.
        
        Args:
            events: List of all events
            clean: Apply filtering to create cleaner graphs
            
        Returns:
            List of BehaviorGraph objects
        """
        if not events:
            return []
        
        # Filter noisy events if requested
        if clean:
            events = self._filter_events(events)
            if not events:
                return []
        
        # Sort by timestamp
        events = sorted(events, key=lambda e: e.timestamp)
        
        # Split into windows
        graphs = []
        current_window_events = []
        window_start = events[0].timestamp
        
        for event in events:
            if event.timestamp - window_start >= self.window_size_ms:
                # Build graph for current window if it has enough events
                if len(current_window_events) >= self.min_events_per_graph:
                    graph = self.build_graph(current_window_events)
                    # Only add if not too large
                    if graph.num_nodes <= self.max_nodes_per_graph:
                        graphs.append(graph)
                
                # Start new window
                current_window_events = [event]
                window_start = event.timestamp
            else:
                current_window_events.append(event)
        
        # Build graph for remaining events
        if len(current_window_events) >= self.min_events_per_graph:
            graph = self.build_graph(current_window_events)
            if graph.num_nodes <= self.max_nodes_per_graph:
                graphs.append(graph)
        
        return graphs
