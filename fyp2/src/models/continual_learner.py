"""
Continual Learning Module
=========================
Adapts the autoencoder incrementally using streaming benign graphs while
reducing catastrophic forgetting through replay from memory.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Optional

import torch
import torch.optim as optim

from .autoencoder import GraphAutoencoder, graph_to_pyg_data


@dataclass
class ContinualLearningStats:
    """Container for continual-learning adaptation metrics."""

    chunks_processed: int
    memory_size: int
    mean_chunk_loss: float


class ContinualLearner:
    """
    Incremental trainer for graph autoencoders.

    Strategy:
    - Process incoming graphs in small chunks (simulated stream).
    - For each chunk, fine-tune on current chunk + replay samples.
    - Keep a bounded memory of previous graphs for rehearsal.
    """

    def __init__(
        self,
        model: GraphAutoencoder,
        learning_rate: float = 0.001,
        replay_ratio: float = 0.5,
        memory_size: int = 64,
        replay_batch_cap: int = 16,
        inner_epochs: int = 2,
        device: str = "cpu",
    ):
        self.model = model.to(device)
        self.device = device
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)

        self.replay_ratio = replay_ratio
        self.memory_size = memory_size
        self.replay_batch_cap = replay_batch_cap
        self.inner_epochs = inner_epochs

        self.memory_graphs: List = []

    def _sample_replay_graphs(self, current_chunk_size: int) -> List:
        if not self.memory_graphs or self.replay_ratio <= 0:
            return []

        target_replay = int(current_chunk_size * self.replay_ratio)
        target_replay = max(1, target_replay)
        target_replay = min(target_replay, self.replay_batch_cap, len(self.memory_graphs))
        return random.sample(self.memory_graphs, target_replay)

    def _update_memory(self, graphs: List):
        self.memory_graphs.extend(graphs)
        if len(self.memory_graphs) > self.memory_size:
            self.memory_graphs = self.memory_graphs[-self.memory_size :]

    def _train_once(self, graphs: List) -> float:
        data_batch = [graph_to_pyg_data(g).to(self.device) for g in graphs]
        if not data_batch:
            return 0.0

        self.model.train()
        total_loss = 0.0

        for data in data_batch:
            self.optimizer.zero_grad()
            loss = self.model.compute_loss(data.x, data.edge_index, data.num_nodes)
            loss.backward()
            self.optimizer.step()
            total_loss += loss.item()

        return total_loss / len(data_batch)

    def adapt_on_stream(self, graphs: List, chunk_size: int = 3,
                         on_chunk_start=None, on_epoch_done=None,
                         on_chunk_done=None) -> Dict[str, float]:
        """
        Incrementally adapt model on a stream of mostly-benign behavior graphs.

        Args:
            graphs: Incoming behavior graphs in temporal order.
            chunk_size: Number of graphs per adaptation chunk.
            on_chunk_start: callback(chunk_idx, chunk_graphs, replay_graphs)
            on_epoch_done: callback(chunk_idx, epoch, loss)
            on_chunk_done: callback(chunk_idx, chunk_loss, memory_size)

        Returns:
            Dict with adaptation statistics.
        """
        if not graphs:
            return {
                "chunks_processed": 0,
                "memory_size": len(self.memory_graphs),
                "mean_chunk_loss": 0.0,
            }

        chunk_losses: List[float] = []
        chunks_processed = 0
        total_chunks = (len(graphs) + chunk_size - 1) // chunk_size

        for start in range(0, len(graphs), chunk_size):
            chunk = graphs[start : start + chunk_size]
            replay_graphs = self._sample_replay_graphs(len(chunk))
            training_graphs = chunk + replay_graphs

            if on_chunk_start:
                on_chunk_start(chunks_processed, len(chunk), len(replay_graphs),
                               total_chunks)

            epoch_losses = []
            for ep in range(self.inner_epochs):
                loss = self._train_once(training_graphs)
                epoch_losses.append(loss)
                if on_epoch_done:
                    on_epoch_done(chunks_processed, ep, loss)

            chunk_loss = sum(epoch_losses) / len(epoch_losses)
            chunk_losses.append(chunk_loss)
            chunks_processed += 1
            self._update_memory(chunk)

            if on_chunk_done:
                on_chunk_done(chunks_processed, chunk_loss,
                              len(self.memory_graphs))

        mean_chunk_loss = sum(chunk_losses) / len(chunk_losses) if chunk_losses else 0.0
        stats = ContinualLearningStats(
            chunks_processed=chunks_processed,
            memory_size=len(self.memory_graphs),
            mean_chunk_loss=mean_chunk_loss,
        )
        return {
            "chunks_processed": stats.chunks_processed,
            "memory_size": stats.memory_size,
            "mean_chunk_loss": stats.mean_chunk_loss,
        }

    def adapt_single_graph(self, graph) -> Optional[float]:
        """Online update for one graph plus memory replay; useful for live systems."""
        replay_graphs = self._sample_replay_graphs(1)
        training_graphs = [graph] + replay_graphs

        epoch_losses = []
        for _ in range(self.inner_epochs):
            epoch_losses.append(self._train_once(training_graphs))

        self._update_memory([graph])
        if not epoch_losses:
            return None
        return sum(epoch_losses) / len(epoch_losses)
