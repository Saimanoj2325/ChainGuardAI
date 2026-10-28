"""Baseline Vulnerability Classifier using tabular syntactic & graph summary features."""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier

from .gnn import VULN_CLASSES


class BaselineVulnerabilityClassifier:
    """Random Forest baseline classifier over global graph & syntactic features."""

    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.classes = VULN_CLASSES
        base_rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=8,
            random_state=random_state,
            class_weight="balanced_subsample",
        )
        self.model = MultiOutputClassifier(base_rf)
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> BaselineVulnerabilityClassifier:
        """Trains the baseline classifier on global feature matrix X (N, 32) and labels y (N, 10)."""
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Returns (N, num_classes) array of vulnerability probabilities."""
        if not self.is_fitted:
            raise RuntimeError("Baseline classifier is not fitted.")
        prob_list = self.model.predict_proba(X)
        # Each estimator returns (N, 2) or (N, 1) if single-class in split
        probs = np.zeros((X.shape[0], len(self.classes)), dtype=np.float32)
        for i, p in enumerate(prob_list):
            if p.shape[1] == 2:
                probs[:, i] = p[:, 1]
            elif p.shape[1] == 1:
                probs[:, i] = 0.0
        return probs

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)

    def save(self, path: Path | str) -> None:
        with open(path, "wb") as fh:
            pickle.dump(self, fh)

    @classmethod
    def load(cls, path: Path | str) -> BaselineVulnerabilityClassifier:
        with open(path, "rb") as fh:
            return pickle.load(fh)
