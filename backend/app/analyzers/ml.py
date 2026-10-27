"""Hook for Agent 1's ML analyzer (ml/chainguard_ml/analyzer.py). Loaded only if importable and available().

Expected: module exposes `get_analyzer()` returning an object implementing chainguard_contract.analyzer.Analyzer,
or a class `MLAnalyzer` constructible without args, or a module-level `analyzer` instance."""
from __future__ import annotations

import importlib
import logging

log = logging.getLogger("chainguard.ml")


def load_ml_analyzer(disabled: bool = False):
    """Returns (analyzer_or_None, reason)."""
    if disabled:
        return None, "ML disabled by CG_DISABLE_ML"
    try:
        mod = importlib.import_module("chainguard_ml.analyzer")
    except Exception as e:  # noqa: BLE001
        return None, f"chainguard_ml.analyzer not importable: {type(e).__name__}: {e}"
    try:
        if callable(getattr(mod, "get_analyzer", None)):
            a = mod.get_analyzer()
        elif getattr(mod, "MLAnalyzer", None) is not None:
            a = mod.MLAnalyzer()
        else:
            a = getattr(mod, "analyzer", None)
        if a is None:
            return None, "chainguard_ml.analyzer exposes no get_analyzer()/MLAnalyzer/analyzer"
        if not hasattr(a, "stage") or not getattr(a, "stage", None):
            a.stage = "ml_inference"
        return a, ""
    except Exception as e:  # noqa: BLE001
        log.warning("ML analyzer failed to initialise: %s", e)
        return None, f"ML analyzer failed to initialise: {type(e).__name__}: {e}"
