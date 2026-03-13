"""
Model Trainer Module
====================
Trains the Graph Autoencoder using self-supervised learning.

IMPORTANT: Training uses ONLY benign/normal behavior data.
NO attack labels are used anywhere in the training process.
"""

import torch
import torch.optim as optim
from torch_geometric.data import Data
from typing import List, Dict, Optional, Tuple
import numpy as np
import logging

from .autoencoder import GraphAutoencoder, graph_to_pyg_data

logger = logging.getLogger(__name__)


class Trainer:
    """
    Self-supervised trainer for Graph Autoencoder.
    
    Trains the model to reconstruct normal behavior graphs.
    After training, computes statistics (μ, σ) for anomaly detection.
    """
    
    def __init__(
        self,
        model: GraphAutoencoder,
        learning_rate: float = 0.001,
        device: str = "cpu"
    ):
        """
        Args:
            model: GraphAutoencoder instance
            learning_rate: Learning rate for optimizer
            device: Device to train on ('cpu' or 'cuda')
        """
        self.model = model.to(device)
        self.device = device
        self.optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        
        # Training statistics (computed after training)
        self.training_losses: List[float] = []
        self.mean_loss: float = 0.0
        self.std_loss: float = 1.0
        
        # History
        self.history: Dict[str, List[float]] = {
            'train_loss': [],
            'val_loss': []
        }
    
    def _train_epoch(self, train_data: List[Data]) -> float:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        
        for data in train_data:
            data = data.to(self.device)
            
            self.optimizer.zero_grad()
            loss = self.model.compute_loss(data.x, data.edge_index, data.num_nodes)
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
        
        return total_loss / len(train_data) if train_data else 0.0
    
    def _validate(self, val_data: List[Data]) -> float:
        """Validate the model"""
        self.model.eval()
        total_loss = 0.0
        
        with torch.no_grad():
            for data in val_data:
                data = data.to(self.device)
                loss = self.model.compute_loss(data.x, data.edge_index, data.num_nodes)
                total_loss += loss.item()
        
        return total_loss / len(val_data) if val_data else 0.0
    
    def train(
        self,
        train_graphs,
        val_graphs=None,
        epochs: int = 50,
        early_stopping_patience: int = 10,
        verbose: bool = True
    ) -> Dict[str, List[float]]:
        """
        Train the model on benign behavior graphs.
        
        Args:
            train_graphs: List of BehaviorGraph objects (BENIGN only!)
            val_graphs: Optional validation graphs
            epochs: Number of training epochs
            early_stopping_patience: Stop if no improvement for N epochs
            verbose: Print progress
            
        Returns:
            Training history
        """
        # Convert to PyG data
        train_data = [graph_to_pyg_data(g) for g in train_graphs]
        val_data = [graph_to_pyg_data(g) for g in val_graphs] if val_graphs else None
        
        best_val_loss = float('inf')
        patience_counter = 0
        
        logger.info(f"Training on {len(train_data)} graphs for {epochs} epochs")
        
        for epoch in range(epochs):
            # Train
            train_loss = self._train_epoch(train_data)
            self.history['train_loss'].append(train_loss)
            
            # Validate
            if val_data:
                val_loss = self._validate(val_data)
                self.history['val_loss'].append(val_loss)
                
                # Early stopping
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if patience_counter >= early_stopping_patience:
                        if verbose:
                            print(f"Early stopping at epoch {epoch + 1}")
                        break
            
            if verbose and (epoch + 1) % 10 == 0:
                msg = f"Epoch {epoch + 1}/{epochs} - Loss: {train_loss:.6f}"
                if val_data:
                    msg += f" - Val Loss: {val_loss:.6f}"
                print(msg)
        
        # Compute training statistics
        self._compute_training_statistics(train_data)
        
        logger.info(f"Training complete. Mean loss: {self.mean_loss:.6f}, Std: {self.std_loss:.6f}")
        
        return self.history
    
    def _compute_training_statistics(self, train_data: List[Data]):
        """
        Compute μ and σ of reconstruction errors on training data.
        
        These are used for anomaly detection threshold: μ + 3σ
        """
        self.model.eval()
        losses = []
        
        with torch.no_grad():
            for data in train_data:
                data = data.to(self.device)
                score = self.model.compute_anomaly_score(
                    data.x, data.edge_index, data.num_nodes
                )
                losses.append(score)
        
        self.training_losses = losses
        self.mean_loss = np.mean(losses)
        self.std_loss = np.std(losses)
        
        # Ensure std is not zero
        if self.std_loss < 1e-6:
            self.std_loss = 1e-6
    
    def get_statistics(self) -> Dict[str, float]:
        """Get training statistics"""
        return {
            'mean_loss': self.mean_loss,
            'std_loss': self.std_loss,
            'threshold_3sigma': self.mean_loss + 3 * self.std_loss,
            'num_training_samples': len(self.training_losses)
        }
    
    def save_checkpoint(self, filepath: str):
        """Save model checkpoint"""
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'mean_loss': self.mean_loss,
            'std_loss': self.std_loss,
            'history': self.history
        }, filepath)
        logger.info(f"Checkpoint saved to {filepath}")
    
    def load_checkpoint(self, filepath: str):
        """Load model checkpoint"""
        checkpoint = torch.load(filepath, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.mean_loss = checkpoint['mean_loss']
        self.std_loss = checkpoint['std_loss']
        self.history = checkpoint['history']
        logger.info(f"Checkpoint loaded from {filepath}")
