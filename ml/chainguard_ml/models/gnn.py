"""Graph Neural Network for Smart Contract Vulnerability Detection.
Implements pure PyTorch GCN with message passing, graph pooling, and multi-label output.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Tuple

VULN_CLASSES: List[str] = [
    "reentrancy",
    "unchecked_call",
    "tx_origin",
    "timestamp_dependence",
    "integer_overflow",
    "access_control",
    "delegatecall",
    "unprotected_selfdestruct",
    "denial_of_service",
    "bad_randomness",
]


class GraphConvLayer(nn.Module):
    """GCN message passing layer with normalized adjacency and residual skip."""

    def __init__(self, in_features: int, out_features: int, dropout: float = 0.2):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.weight_neighbor = nn.Linear(in_features, out_features, bias=False)
        self.weight_self = nn.Linear(in_features, out_features, bias=True)
        self.norm = nn.LayerNorm(out_features)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        num_nodes = x.size(0)
        self_feat = self.weight_self(x)

        if edge_index.size(1) == 0:
            # Graph with no edges: retain self features
            return self.dropout(F.relu(self.norm(self_feat)))

        src, dst = edge_index[0], edge_index[1]
        deg = torch.zeros(num_nodes, dtype=torch.float32, device=x.device)
        deg.scatter_add_(0, dst, torch.ones_like(dst, dtype=torch.float32))
        deg_inv_sqrt = deg.pow(-0.5)
        deg_inv_sqrt[torch.isinf(deg_inv_sqrt)] = 0.0

        # Message passing: gather source features, scale by degree, and aggregate at destination
        msg = x[src] * deg_inv_sqrt[src].unsqueeze(-1)
        agg = torch.zeros((num_nodes, self.in_features), dtype=torch.float32, device=x.device)
        agg.scatter_add_(0, dst.unsqueeze(-1).expand_as(msg), msg)
        agg = agg * deg_inv_sqrt.unsqueeze(-1)

        neighbor_feat = self.weight_neighbor(agg)
        out = self_feat + neighbor_feat
        out = self.norm(out)
        out = F.relu(out)
        return self.dropout(out)


class ContractGNN(nn.Module):
    """
    Two-layer Graph Convolutional Network + Readout Pooling + Multi-label Classification Head.
    Input:
      - x: (N, in_dim) node feature tensor
      - edge_index: (2, E) edge index tensor
      - global_feat: (global_dim,) contract-level summary vector
    Output:
      - logits: (num_classes,) class prediction logits
      - node_importance: (N,) node-level attention/saliency weights for evidence extraction
    """

    def __init__(
        self,
        in_dim: int = 64,
        hidden_dim: int = 128,
        global_dim: int = 32,
        num_classes: int = len(VULN_CLASSES),
        dropout: float = 0.2,
    ):
        super().__init__()
        self.conv1 = GraphConvLayer(in_dim, hidden_dim, dropout)
        self.conv2 = GraphConvLayer(hidden_dim, hidden_dim, dropout)

        # Global feature projection
        self.global_proj = nn.Linear(global_dim, hidden_dim)

        # Node importance scoring head (for evidence line highlighting)
        self.node_scoring = nn.Linear(hidden_dim, 1)

        # Classification MLP: (mean_pool + max_pool + global_proj) -> hidden_dim*3 -> num_classes
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 3, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        global_feat: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        if x.dim() == 1:
            x = x.unsqueeze(0)
        if global_feat.dim() == 1:
            global_feat = global_feat.unsqueeze(0)

        # Graph Convolutions
        h1 = self.conv1(x, edge_index)
        h2 = self.conv2(h1, edge_index)

        # Node importance weights (softmax over all nodes)
        node_scores = self.node_scoring(h2).squeeze(-1)
        node_importance = F.softmax(node_scores, dim=-1)

        # Graph Readout Pooling: concatenate mean and max pooling
        mean_pool = torch.mean(h2, dim=0, keepdim=True)
        max_pool = torch.max(h2, dim=0, keepdim=True)[0]

        # Global features
        g_proj = F.relu(self.global_proj(global_feat))

        graph_repr = torch.cat([mean_pool, max_pool, g_proj], dim=-1)
        logits = self.classifier(graph_repr).squeeze(0)

        return logits, node_importance

    @torch.no_grad()
    def predict(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        global_feat: torch.Tensor,
        threshold: float = 0.5,
    ) -> Dict[str, Any]:
        """Runs inference and returns probabilities, predicted classes, and node saliency."""
        self.eval()
        logits, node_importance = self.forward(x, edge_index, global_feat)
        probs = torch.sigmoid(logits).cpu().numpy()

        results: Dict[str, float] = {}
        detected: List[str] = []

        for i, cls in enumerate(VULN_CLASSES):
            prob = float(probs[i])
            results[cls] = prob
            if prob >= threshold:
                detected.append(cls)

        return {
            "probabilities": results,
            "detected_classes": detected,
            "node_importance": node_importance.cpu().numpy().tolist(),
        }
