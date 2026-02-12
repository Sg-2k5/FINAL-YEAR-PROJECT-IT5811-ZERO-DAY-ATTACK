"""
Graph Autoencoder Model
=======================
Self-supervised model for learning behavior graph representations.

Architecture:
- Encoder: 2-layer Graph Convolutional Network (GCN)
- Decoder: Inner product decoder for edge reconstruction

The model learns to reconstruct the adjacency matrix from node embeddings.
High reconstruction error indicates anomalous behavior.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
from typing import Tuple, Optional

# Feature dimensions (LOCKED)
NODE_FEATURE_DIM = 6  # 3 (type one-hot) + 3 (degree features)


class GraphEncoder(nn.Module):
    """
    Graph Convolutional Encoder.
    
    Takes node features and edge index, outputs node embeddings.
    """
    
    def __init__(
        self,
        input_dim: int = NODE_FEATURE_DIM,
        hidden_dim: int = 32,
        latent_dim: int = 16,
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        
        # GCN layers
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, latent_dim)
        
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through encoder.
        
        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
            
        Returns:
            Node embeddings [num_nodes, latent_dim]
        """
        # First GCN layer
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = self.dropout(h)
        
        # Second GCN layer
        z = self.conv2(h, edge_index)
        
        return z


class InnerProductDecoder(nn.Module):
    """
    Inner Product Decoder for edge reconstruction.
    
    Reconstructs adjacency matrix from node embeddings using inner product.
    """
    
    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Decode embeddings to adjacency matrix.
        
        Args:
            z: Node embeddings [num_nodes, latent_dim]
            
        Returns:
            Reconstructed adjacency [num_nodes, num_nodes]
        """
        # Inner product: A_ij = sigmoid(z_i · z_j)
        adj = torch.sigmoid(torch.mm(z, z.t()))
        return adj


class GraphAutoencoder(nn.Module):
    """
    Graph Autoencoder for Anomaly Detection.
    
    Combines encoder and decoder to learn graph representations.
    Anomaly score is the reconstruction error.
    """
    
    def __init__(
        self,
        input_dim: int = NODE_FEATURE_DIM,
        hidden_dim: int = 32,
        latent_dim: int = 16,
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.encoder = GraphEncoder(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            latent_dim=latent_dim,
            dropout=dropout
        )
        self.decoder = InnerProductDecoder()
        
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
    
    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Encode graph to latent representation"""
        return self.encoder(x, edge_index)
    
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """Decode latent representation to adjacency matrix"""
        return self.decoder(z)
    
    def forward(
        self, 
        x: torch.Tensor, 
        edge_index: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Full forward pass.
        
        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
            
        Returns:
            z: Node embeddings
            adj_pred: Reconstructed adjacency matrix
        """
        z = self.encode(x, edge_index)
        adj_pred = self.decode(z)
        return z, adj_pred
    
    def compute_loss(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        num_nodes: int
    ) -> torch.Tensor:
        """
        Compute reconstruction loss.
        
        Loss = MSE between true and reconstructed adjacency.
        
        Args:
            x: Node features
            edge_index: True edges
            num_nodes: Number of nodes
            
        Returns:
            Reconstruction loss (scalar)
        """
        # Encode and decode
        z, adj_pred = self.forward(x, edge_index)
        
        # Create true adjacency matrix
        adj_true = torch.zeros((num_nodes, num_nodes), device=x.device)
        if edge_index.numel() > 0:
            adj_true[edge_index[0], edge_index[1]] = 1.0
        
        # MSE loss
        loss = F.mse_loss(adj_pred, adj_true)
        
        return loss
    
    def compute_anomaly_score(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        num_nodes: int
    ) -> float:
        """
        Compute anomaly score for a graph.
        
        Score = Normalized reconstruction error
        
        Higher score = more anomalous
        """
        self.eval()
        with torch.no_grad():
            z, adj_pred = self.forward(x, edge_index)
            
            # Create true adjacency
            adj_true = torch.zeros((num_nodes, num_nodes), device=x.device)
            if edge_index.numel() > 0:
                adj_true[edge_index[0], edge_index[1]] = 1.0
            
            # Mean squared error (normalized by graph size)
            mse = torch.mean((adj_true - adj_pred) ** 2).item()
            
            # Also compute edge-level reconstruction error
            if edge_index.numel() > 0:
                # Check how well true edges are reconstructed
                edge_probs = adj_pred[edge_index[0], edge_index[1]]
                edge_error = (1.0 - edge_probs).mean().item()
            else:
                edge_error = 0.0
            
            # Combine: MSE + edge reconstruction error
            score = mse * 1000 + edge_error * 100
            
        return score


def graph_to_pyg_data(graph) -> Data:
    """
    Convert BehaviorGraph to PyTorch Geometric Data object.
    
    Args:
        graph: BehaviorGraph instance
        
    Returns:
        PyG Data object
    """
    # Get node features
    node_ids = list(graph.nodes.keys())
    node_id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
    
    # Build feature matrix
    x = []
    for nid in node_ids:
        node = graph.nodes[nid]
        if node.features is not None:
            x.append(node.features)
        else:
            # Default features if not computed
            x.append([0.0] * NODE_FEATURE_DIM)
    
    x = torch.tensor(x, dtype=torch.float)
    
    # Build edge index
    edge_index = []
    for edge in graph.edges:
        if edge.source_id in node_id_to_idx and edge.target_id in node_id_to_idx:
            src_idx = node_id_to_idx[edge.source_id]
            tgt_idx = node_id_to_idx[edge.target_id]
            edge_index.append([src_idx, tgt_idx])
    
    if edge_index:
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
    
    return Data(x=x, edge_index=edge_index, num_nodes=len(node_ids))
